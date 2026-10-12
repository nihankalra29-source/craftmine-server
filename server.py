#!/usr/bin/env python3
"""CraftMine account + cloud-save server. Standard library only (Python 3.8+).

Run:   ADMIN_PASSWORD='something-long' python3 server.py        (default port 8080, or $PORT)
Data:  PostgreSQL when $DATABASE_URL is set (use this on Render: its disk is wiped on restart),
       otherwise a SQLite file at $CRAFTMINE_DB (default ./craftmine.db).

API (JSON):
  GET  /api/health
  POST /api/register  {username, password}  -> {token, username, role}
  POST /api/login     {username, password}  -> {token, username, role}
  GET  /api/me        (Bearer token)        -> {username, role}
  GET  /api/save      (Bearer token)        -> {save: <string|null>}
  PUT  /api/save      (Bearer token) {save: <string>}

DLC (expansion unlock codes live in $DLC_CODES as "sku=CODE,sku=CODE", never in the game files):
  POST /api/dlc/redeem (Bearer) {code}  -> {ok, sku, dlc:[...]}      Login / register / me also return "dlc".

Multiplayer directory (groundwork for host/join - the game servers themselves run elsewhere):
  GET    /api/servers                      -> {servers: [{name, address, port, players, maxPlayers, version}]}
  POST   /api/servers (Bearer) {name, address, port, players, maxPlayers, version}   register / heartbeat (every <60s)
  DELETE /api/servers (Bearer)             remove your listing
"""
import hashlib, hmac, json, os, re, secrets, sqlite3, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.environ.get("CRAFTMINE_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "craftmine.db"))
PORT = int(os.environ.get("PORT", "8080"))
ADMIN_NAME = "Administrator"
TOKEN_TTL = 60 * 60 * 24 * 30
USER_RE = re.compile(r"^[A-Za-z0-9_]{3,16}$")
MAX_SAVE_BYTES = 64 * 1024
PBKDF_ROUNDS = 200_000

lock = threading.Lock()
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_PG = DATABASE_URL.startswith("postgres")

SCHEMA = [
    "CREATE TABLE IF NOT EXISTS users (key TEXT PRIMARY KEY, name TEXT NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'player', created DOUBLE PRECISION NOT NULL)",
    "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_key TEXT NOT NULL, expires DOUBLE PRECISION NOT NULL)",
    "CREATE TABLE IF NOT EXISTS saves (user_key TEXT PRIMARY KEY, data TEXT NOT NULL, updated DOUBLE PRECISION NOT NULL)",
    "CREATE TABLE IF NOT EXISTS entitlements (user_key TEXT NOT NULL, sku TEXT NOT NULL, granted DOUBLE PRECISION NOT NULL, PRIMARY KEY (user_key, sku))",
]

if USE_PG:
    import psycopg2

    _conn = None

    def _connect():
        global _conn
        _conn = psycopg2.connect(DATABASE_URL)
        _conn.autocommit = True

    _connect()
else:
    _conn = sqlite3.connect(DB_PATH, check_same_thread=False)


def dbx(sql, params=()):
    """Run one statement, return all rows (or []). Portable SQL; only the placeholder style differs."""
    global _conn
    with lock:
        if USE_PG:
            sql = sql.replace("?", "%s")
            for attempt in (0, 1):
                try:
                    cur = _conn.cursor()
                    cur.execute(sql, params)
                    rows = cur.fetchall() if cur.description else []
                    cur.close()
                    return rows
                except psycopg2.OperationalError:
                    if attempt == 1:
                        raise
                    _connect()
        cur = _conn.execute(sql, params)
        rows = cur.fetchall()
        _conn.commit()
        return rows


for _stmt in SCHEMA:
    dbx(_stmt)

def _norm_code(c):
    return "".join(ch for ch in str(c).upper() if ch.isalnum())


DLC_CODES = {}  # sku -> normalised code
for _pair in os.environ.get("DLC_CODES", "").split(","):
    if "=" in _pair:
        _sku, _code = _pair.split("=", 1)
        if _sku.strip() and _norm_code(_code):
            DLC_CODES[_sku.strip().lower()] = _norm_code(_code)
ALL_SKUS = sorted(set(DLC_CODES) | {"blackseed"})


def dlc_for(user_key, role):
    if role == "admin":
        return list(ALL_SKUS)
    return [r[0] for r in dbx("SELECT sku FROM entitlements WHERE user_key=?", (user_key,))]


_attempts = {}  # ip -> [timestamps]; crude brute-force throttle
_servers = {}   # host username (lowercase) -> listing; in memory, expires after SERVER_TTL seconds
SERVER_TTL = 90
MAX_SERVERS = 200


def pw_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF_ROUNDS)


def set_user(name, password, role):
    salt = secrets.token_bytes(16)
    dbx("INSERT INTO users (key, name, salt, hash, role, created) VALUES (?,?,?,?,?,?) "
        "ON CONFLICT (key) DO UPDATE SET name=excluded.name, salt=excluded.salt, hash=excluded.hash, role=excluded.role",
        (name.lower(), name, salt.hex(), pw_hash(password, salt).hex(), role, time.time()))


def seed_admin():
    pw = os.environ.get("ADMIN_PASSWORD")
    exists = dbx("SELECT 1 FROM users WHERE key=?", (ADMIN_NAME.lower(),))
    if pw:
        set_user(ADMIN_NAME, pw, "admin")
        print("[server] Administrator account set from ADMIN_PASSWORD.")
    elif not exists:
        pw = secrets.token_urlsafe(12)
        set_user(ADMIN_NAME, pw, "admin")
        print("[server] No ADMIN_PASSWORD set. Generated Administrator password (shown once):", pw)


def throttled(ip):
    now = time.time()
    hits = [t for t in _attempts.get(ip, []) if now - t < 60]
    _attempts[ip] = hits
    if len(hits) >= 12:
        return True
    hits.append(now)
    return False


def new_session(name):
    token = secrets.token_hex(32)
    dbx("INSERT INTO sessions (token, user_key, expires) VALUES (?,?,?)", (token, name.lower(), time.time() + TOKEN_TTL))
    dbx("DELETE FROM sessions WHERE expires < ?", (time.time(),))
    return token


class Handler(BaseHTTPRequestHandler):
    server_version = "CraftMine/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[server] %s %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_SAVE_BYTES + 1024:
            return None
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return None

    def _user(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        rows = dbx("SELECT u.name, u.role FROM sessions s JOIN users u ON u.key=s.user_key WHERE s.token=? AND s.expires>?",
                   (auth[7:], time.time()))
        return tuple(rows[0]) if rows else None

    def do_OPTIONS(self):
        self._send(204, {})

    def do_DELETE(self):
        u = self._user()
        if self.path != "/api/servers":
            return self._send(404, {"error": "Not found."})
        if not u:
            return self._send(401, {"error": "Not signed in."})
        _servers.pop(u[0].lower(), None)
        self._send(200, {"ok": True})

    def do_GET(self):
        if self.path == "/api/health":
            return self._send(200, {"ok": True, "game": "CraftMine"})
        if self.path == "/api/servers":
            now = time.time()
            for k in [k for k, v in _servers.items() if now - v["seen"] > SERVER_TTL]:
                del _servers[k]
            listing = [{k: v[k] for k in ("name", "address", "port", "players", "maxPlayers", "version")} for v in _servers.values()]
            return self._send(200, {"servers": listing})
        u = self._user()
        if self.path == "/api/me":
            return self._send(200, {"username": u[0], "role": u[1], "dlc": dlc_for(u[0].lower(), u[1])}) if u else self._send(401, {"error": "Not signed in."})
        if self.path == "/api/save":
            if not u:
                return self._send(401, {"error": "Not signed in."})
            rows = dbx("SELECT data FROM saves WHERE user_key=?", (u[0].lower(),))
            return self._send(200, {"save": rows[0][0] if rows else None})
        self._send(404, {"error": "Not found."})

    def do_PUT(self):
        u = self._user()
        if self.path != "/api/save":
            return self._send(404, {"error": "Not found."})
        if not u:
            return self._send(401, {"error": "Not signed in."})
        b = self._body()
        if not b or not isinstance(b.get("save"), str) or len(b["save"]) > MAX_SAVE_BYTES:
            return self._send(400, {"error": "Bad save."})
        dbx("INSERT INTO saves (user_key, data, updated) VALUES (?,?,?) ON CONFLICT (user_key) DO UPDATE SET data=excluded.data, updated=excluded.updated",
            (u[0].lower(), b["save"], time.time()))
        self._send(200, {"ok": True})

    def do_POST(self):
        if self.path == "/api/dlc/redeem":
            u = self._user()
            if not u:
                return self._send(401, {"error": "Sign in to an online account first."})
            if throttled(self.client_address[0]):
                return self._send(429, {"error": "Too many attempts. Wait a minute."})
            code = _norm_code((self._body() or {}).get("code", ""))
            for sku, real in DLC_CODES.items():
                if code and hmac.compare_digest(code, real):
                    dbx("INSERT INTO entitlements (user_key, sku, granted) VALUES (?,?,?) ON CONFLICT (user_key, sku) DO NOTHING",
                        (u[0].lower(), sku, time.time()))
                    return self._send(200, {"ok": True, "sku": sku, "dlc": dlc_for(u[0].lower(), u[1])})
            return self._send(404, {"error": "That code isn't valid."})
        if self.path == "/api/servers":
            u = self._user()
            if not u:
                return self._send(401, {"error": "Not signed in."})
            b = self._body() or {}
            try:
                entry = {
                    "name": str(b.get("name", ""))[:40].strip() or (u[0] + "'s world"),
                    "host": u[0],
                    "address": (str(b.get("address", "")).strip() or self.headers.get("X-Forwarded-For", "").split(",")[0].strip() or self.client_address[0])[:100],
                    "port": max(1, min(65535, int(b.get("port", 7777)))),
                    "players": max(0, min(1000, int(b.get("players", 1)))),
                    "maxPlayers": max(1, min(1000, int(b.get("maxPlayers", 8)))),
                    "version": str(b.get("version", "1.0"))[:16],
                    "seen": time.time(),
                }
            except (TypeError, ValueError):
                return self._send(400, {"error": "Bad server listing."})
            if u[0].lower() not in _servers and len(_servers) >= MAX_SERVERS:
                return self._send(503, {"error": "Directory is full."})
            _servers[u[0].lower()] = entry
            return self._send(200, {"ok": True, "ttl": SERVER_TTL})
        if self.path not in ("/api/register", "/api/login"):
            return self._send(404, {"error": "Not found."})
        if throttled(self.client_address[0]):
            return self._send(429, {"error": "Too many attempts. Wait a minute."})
        b = self._body() or {}
        name, pw = str(b.get("username", "")).strip(), str(b.get("password", ""))
        if self.path == "/api/register":
            if not USER_RE.match(name):
                return self._send(400, {"error": "Username: 3-16 letters, numbers or _."})
            if len(pw) < 6:
                return self._send(400, {"error": "Password must be at least 6 characters."})
            if name.lower() == ADMIN_NAME.lower() or dbx("SELECT 1 FROM users WHERE key=?", (name.lower(),)):
                return self._send(409, {"error": "That username is already taken."})
            set_user(name, pw, "player")
            return self._send(200, {"token": new_session(name), "username": name, "role": "player", "dlc": []})
        rows = dbx("SELECT name, salt, hash, role FROM users WHERE key=?", (name.lower(),))
        row = rows[0] if rows else None
        if not row or not hmac.compare_digest(bytes.fromhex(row[2]), pw_hash(pw, bytes.fromhex(row[1]))):
            return self._send(401, {"error": "Wrong username or password."})
        self._send(200, {"token": new_session(row[0]), "username": row[0], "role": row[3], "dlc": dlc_for(row[0].lower(), row[3])})


if __name__ == "__main__":
    seed_admin()
    print("[server] CraftMine server listening on 0.0.0.0:%d  (db: %s)" % (PORT, DB_PATH))
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
