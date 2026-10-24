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

Admin:  GET /admin (page; enter the Administrator password)   GET /api/admin/users (Bearer admin)
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
    "CREATE TABLE IF NOT EXISTS staff (key TEXT PRIMARY KEY, name TEXT NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL, message TEXT NOT NULL, created DOUBLE PRECISION NOT NULL, decided DOUBLE PRECISION)",
    "CREATE TABLE IF NOT EXISTS staff_sessions (token TEXT PRIMARY KEY, staff_key TEXT NOT NULL, expires DOUBLE PRECISION NOT NULL)",
    "CREATE TABLE IF NOT EXISTS pvp_stats (key TEXT PRIMARY KEY, name TEXT NOT NULL, wins INTEGER NOT NULL, losses INTEGER NOT NULL, rating INTEGER NOT NULL, updated DOUBLE PRECISION NOT NULL)",
    "CREATE TABLE IF NOT EXISTS season_scores (season INTEGER NOT NULL, key TEXT NOT NULL, name TEXT NOT NULL, score INTEGER NOT NULL, updated DOUBLE PRECISION NOT NULL, PRIMARY KEY (season, key))",
    "CREATE TABLE IF NOT EXISTS staff_posts (id TEXT PRIMARY KEY, kind TEXT NOT NULL, author TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, created DOUBLE PRECISION NOT NULL)",
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


STAFF_ROLES = ("manager", "administrator", "helper")


def staff_session(key):
    token = secrets.token_hex(32)
    dbx("INSERT INTO staff_sessions (token, staff_key, expires) VALUES (?,?,?)", (token, key, time.time() + TOKEN_TTL))
    dbx("DELETE FROM staff_sessions WHERE expires < ?", (time.time(),))
    return token


ADMIN_PAGE = b"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Zoolda Admin</title><style>body{font:16px system-ui;background:#0b1230;color:#e9eefc;max-width:760px;margin:30px auto;padding:0 16px}
input,button{font:inherit;padding:8px;margin:4px 0}table{width:100%;border-collapse:collapse;margin-top:14px}
td,th{padding:6px 8px;border-bottom:1px solid #26356b;text-align:left}th{color:#ffd24d}.on{color:#7dff8a}</style>
<h2>Zoolda Admin</h2><div id=f><input id=p type=password placeholder="Administrator password"> <button onclick=go()>View</button></div><div id=o></div>
<script>
async function go(){const o=document.getElementById('o');o.textContent='Loading (the server may be waking up)...';
try{const l=await fetch('/api/login',{method:'POST',body:JSON.stringify({username:'Administrator',password:document.getElementById('p').value})}).then(r=>r.json());
if(!l.token){o.textContent=l.error||'Login failed';return}
const d=await fetch('/api/admin/users',{headers:{Authorization:'Bearer '+l.token}}).then(r=>r.json());
const ago=t=>{if(!t)return'never';const m=(Date.now()/1000-t)/60;return m<5?'<span class=on>online now</span>':m<60?Math.round(m)+' min ago':m<1440?Math.round(m/60)+' h ago':Math.round(m/1440)+' days ago'};
o.innerHTML='<p>'+d.users.length+' accounts</p><table><tr><th>Name<th>Role<th>Created<th>Last active</tr>'+d.users.map(u=>'<tr><td>'+u.name+'<td>'+u.role+'<td>'+new Date(u.created*1000).toLocaleDateString()+'<td>'+ago(u.last_active)).join('')+'</table>'}catch(e){o.textContent='Error: '+e}}
</script>"""


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

    def _staff(self):
        """(name, role) for a signed-in staff member; role is owner / manager / administrator / helper."""
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        u = self._user()
        if u and u[1] == "admin":
            return (u[0], "owner")
        rows = dbx("SELECT f.name, f.role FROM staff_sessions s JOIN staff f ON f.key=s.staff_key "
                   "WHERE s.token=? AND s.expires>? AND f.status='active'", (auth[7:], time.time()))
        return tuple(rows[0]) if rows else None

    def _query(self):
        from urllib.parse import urlparse, parse_qs
        p = urlparse(self.path)
        return p.path, {k: v[0] for k, v in parse_qs(p.query).items()}

    def do_OPTIONS(self):
        self._send(204, {})

    def do_DELETE(self):
        path, q = self._query()
        if path == "/api/staff/posts":
            st = self._staff()
            if not st or st[1] != "owner":
                return self._send(403, {"error": "Only the owner can delete posts."})
            dbx("DELETE FROM staff_posts WHERE id=?", (q.get("id", ""),))
            return self._send(200, {"ok": True})
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
        path, q = self._query()
        if path.startswith("/api/hub/") or path.startswith("/api/season/"):
            return self._hub_route("GET")
        if path.startswith("/api/staff/"):
            st = self._staff()
            if not st:
                return self._send(401, {"error": "Not signed in."})
            if path == "/api/staff/me":
                return self._send(200, {"name": st[0], "role": st[1]})
            if path == "/api/staff/applications":
                if st[1] != "owner":
                    return self._send(403, {"error": "Owner only."})
                rows = dbx("SELECT name, role, status, message, created FROM staff ORDER BY created DESC")
                return self._send(200, {"staff": [dict(zip(("name", "role", "status", "message", "created"), r)) for r in rows]})
            if path == "/api/staff/posts":
                kind = q.get("kind", "idea")
                if kind not in ("beta", "idea") or (kind == "beta" and st[1] not in ("owner", "manager")):
                    return self._send(403, {"error": "You don't have access to that."})
                rows = dbx("SELECT id, author, title, body, created FROM staff_posts WHERE kind=? ORDER BY created DESC", (kind,))
                return self._send(200, {"posts": [dict(zip(("id", "author", "title", "body", "created"), r)) for r in rows]})
            return self._send(404, {"error": "Not found."})
        if self.path == "/admin":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(ADMIN_PAGE)))
            self.end_headers()
            return self.wfile.write(ADMIN_PAGE)
        u = self._user()
        if self.path == "/api/admin/users":
            st = self._staff()
            if not st or st[1] not in ("owner", "manager", "administrator"):
                return self._send(403, {"error": "Administrators only."})
            sess = {r[0]: r[1] for r in dbx("SELECT user_key, MAX(expires) FROM sessions GROUP BY user_key")}
            saved = {r[0]: r[1] for r in dbx("SELECT user_key, updated FROM saves")}
            out = []
            for key, name, role, created in dbx("SELECT key, name, role, created FROM users ORDER BY created"):
                t = max(sess.get(key, 0) - TOKEN_TTL, saved.get(key, 0))
                out.append({"name": name, "role": role, "created": created, "last_active": t or None})
            return self._send(200, {"users": out})
        if self.path == "/api/me":
            return self._send(200, {"username": u[0], "role": u[1], "rank": rank_of(u[0].lower()), "dlc": dlc_for(u[0].lower(), u[1])}) if u else self._send(401, {"error": "Not signed in."})
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
        if self.path.startswith("/api/hub/") or self.path.startswith("/api/season/"):
            return self._hub_route("POST")
        if self.path.startswith("/api/staff/"):
            return self._staff_post()
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
        self._send(200, {"token": new_session(row[0]), "username": row[0], "role": row[3], "rank": rank_of(row[0].lower()), "dlc": dlc_for(row[0].lower(), row[3])})


def _staff_post(self):
    path = self.path
    b = self._body() or {}
    if path in ("/api/staff/apply", "/api/staff/login"):
        if throttled(self.client_address[0]):
            return self._send(429, {"error": "Too many attempts. Wait a minute."})
        name, pw = str(b.get("username", "")).strip(), str(b.get("password", ""))
        if path == "/api/staff/apply":
            role, msg = str(b.get("role", "")).lower(), str(b.get("message", "")).strip()[:600]
            if role not in STAFF_ROLES:
                return self._send(400, {"error": "Pick a role."})
            if not USER_RE.match(name) or name.lower() == ADMIN_NAME.lower():
                return self._send(400, {"error": "Username: 3-16 letters, numbers or _."})
            if len(pw) < 8:
                return self._send(400, {"error": "Password must be at least 8 characters."})
            if len(msg) < 10:
                return self._send(400, {"error": "Tell us a little about why you'd be a good fit."})
            if dbx("SELECT 1 FROM staff WHERE key=?", (name.lower(),)):
                return self._send(409, {"error": "You have already applied with that username."})
            # The rank is applied to the in-game account with this exact username, so the applicant must own it:
            # an existing game account needs its password; otherwise the game account is created now.
            grow = dbx("SELECT salt, hash FROM users WHERE key=?", (name.lower(),))
            if grow:
                if not hmac.compare_digest(bytes.fromhex(grow[0][1]), pw_hash(pw, bytes.fromhex(grow[0][0]))):
                    return self._send(401, {"error": "That in-game username already exists. Enter its in-game password to prove it's yours."})
            else:
                set_user(name, pw, "player")
            salt = secrets.token_bytes(16)
            dbx("INSERT INTO staff (key, name, salt, hash, role, status, message, created) VALUES (?,?,?,?,?,?,?,?)",
                (name.lower(), name, salt.hex(), pw_hash(pw, salt).hex(), role, "pending", msg, time.time()))
            return self._send(200, {"ok": True})
        if name.lower() == ADMIN_NAME.lower():
            rows = dbx("SELECT name, salt, hash, role FROM users WHERE key=?", (name.lower(),))
            row = rows[0] if rows else None
            if not row or row[3] != "admin" or not hmac.compare_digest(bytes.fromhex(row[2]), pw_hash(pw, bytes.fromhex(row[1]))):
                return self._send(401, {"error": "Wrong username or password."})
            return self._send(200, {"token": new_session(row[0]), "name": row[0], "role": "owner", "status": "active"})
        rows = dbx("SELECT name, salt, hash, role, status FROM staff WHERE key=?", (name.lower(),))
        row = rows[0] if rows else None
        if not row or not hmac.compare_digest(bytes.fromhex(row[2]), pw_hash(pw, bytes.fromhex(row[1]))):
            return self._send(401, {"error": "Wrong username or password."})
        if row[4] == "pending":
            return self._send(403, {"error": "Your application is still waiting for the owner to review it."})
        if row[4] != "active":
            return self._send(403, {"error": "Sorry, your application was declined."})
        return self._send(200, {"token": staff_session(row[0].lower()), "name": row[0], "role": row[3], "status": "active"})
    st = self._staff()
    if not st:
        return self._send(401, {"error": "Not signed in."})
    if path == "/api/staff/decide":
        if st[1] != "owner":
            return self._send(403, {"error": "Owner only."})
        key = str(b.get("name", "")).lower()
        status = "active" if b.get("accept") else "declined"
        if not dbx("SELECT 1 FROM staff WHERE key=?", (key,)):
            return self._send(404, {"error": "No such applicant."})
        dbx("UPDATE staff SET status=?, decided=? WHERE key=?", (status, time.time(), key))
        return self._send(200, {"ok": True, "status": status})
    if path == "/api/staff/remove":
        if st[1] != "owner":
            return self._send(403, {"error": "Owner only."})
        key = str(b.get("name", "")).lower()
        dbx("DELETE FROM staff WHERE key=?", (key,))
        dbx("DELETE FROM staff_sessions WHERE staff_key=?", (key,))
        return self._send(200, {"ok": True})
    if path == "/api/staff/posts":
        kind = str(b.get("kind", "idea"))
        title, body = str(b.get("title", "")).strip()[:100], str(b.get("body", "")).strip()[:2000]
        if kind == "beta" and st[1] != "owner":
            return self._send(403, {"error": "Only the owner can post beta updates."})
        if kind not in ("beta", "idea") or not title or not body:
            return self._send(400, {"error": "A title and some text are needed."})
        dbx("INSERT INTO staff_posts (id, kind, author, title, body, created) VALUES (?,?,?,?,?,?)",
            (secrets.token_hex(8), kind, st[0], title, body, time.time()))
        return self._send(200, {"ok": True})
    self._send(404, {"error": "Not found."})


Handler._staff_post = _staff_post


# ----------------------------------------------------------------------------------------------
# Hall of Fame: an always-on public hub that lives on this server (clients poll /api/hub/sync).
# Ranks, chat, duels and leaderboards are all decided here, so a modified game client can't fake them.
# ----------------------------------------------------------------------------------------------
import math, random
from collections import deque

SEASON_EPOCH = 1792800000          # 2026-10-24 00:00 UTC = start of season 1
SEASON_LEN = 14 * 24 * 3600
DUEL_HP, SWORD_DMG, HEAL_AMT, HEAL_COUNT = 20, 2, 6, 2
HIT_REACH, HIT_COOLDOWN, COUNTDOWN, DUEL_MAX, OVER_LINGER = 4.0, 0.35, 4.0, 240.0, 7.0
HUB_TTL = 10.0
STAFF_VIEW = ("owner", "manager", "administrator")

hub_lock = threading.RLock()
hub_players = {}        # key -> dict
hub_chat = deque(maxlen=120)
hub_chat_id = [0]
hub_queue = []          # keys waiting for a duel
hub_duels = {}          # id -> dict
hub_duel_of = {}        # key -> duel id
hub_recent = {}         # (winner, loser) -> [timestamps] (anti win-farming)
_rank_cache = {}        # key -> (rank, expires)
_board_cache = {}       # name -> (data, expires)


def season_info(now=None):
    now = now or time.time()
    n = int((now - SEASON_EPOCH) // SEASON_LEN)
    n = max(n, 0)
    return n + 1, SEASON_EPOCH + (n + 1) * SEASON_LEN - now


def rank_of(key):
    """'owner' | 'manager' | 'administrator' | 'helper' | ''  for an in-game account (by lowercase name)."""
    hit = _rank_cache.get(key)
    now = time.time()
    if hit and hit[1] > now:
        return hit[0]
    rank = ""
    row = dbx("SELECT role FROM users WHERE key=?", (key,))
    if row and row[0][0] == "admin":
        rank = "owner"
    else:
        srow = dbx("SELECT role FROM staff WHERE key=? AND status='active'", (key,))
        if srow and row:            # a staff row only counts while its in-game account exists
            rank = srow[0][0]
    _rank_cache[key] = (rank, now + 20)
    return rank


def _num(v, lo, hi, default=0.0):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return default
    if v != v or v in (float("inf"), float("-inf")):
        return default
    return max(lo, min(hi, v))


def hub_say(name, rank, text, to=None):
    hub_chat_id[0] += 1
    hub_chat.append({"id": hub_chat_id[0], "n": name, "r": rank, "t": text, "to": to})


def _elo(a_rating, b_rating, a_won):
    exp_a = 1.0 / (1.0 + 10 ** ((b_rating - a_rating) / 400.0))
    return int(round(32 * ((1.0 if a_won else 0.0) - exp_a)))


def _pvp_row(key, name):
    r = dbx("SELECT wins, losses, rating FROM pvp_stats WHERE key=?", (key,))
    if r:
        return list(r[0])
    dbx("INSERT INTO pvp_stats (key, name, wins, losses, rating, updated) VALUES (?,?,0,0,1000,?)", (key, name, time.time()))
    return [0, 0, 1000]


def duel_finish(d, winner_key, reason=""):
    """End a duel. winner_key None = draw. Only a real opponent counts; nothing else ever touches the ladder."""
    if d["state"] == "over":
        return
    d["state"], d["over_at"], d["winner"] = "over", time.time(), winner_key or ""
    if not winner_key:
        return
    loser_key = d["b"] if winner_key == d["a"] else d["a"]
    now = time.time()
    hist = [t for t in hub_recent.get((winner_key, loser_key), []) if now - t < 3600]
    hub_recent[(winner_key, loser_key)] = hist + [now]
    d["counted"] = len(hist) < 5
    if not d["counted"]:
        return
    wn, ln = d["names"][winner_key], d["names"][loser_key]
    w, l = _pvp_row(winner_key, wn), _pvp_row(loser_key, ln)
    delta = _elo(w[2], l[2], True)
    dbx("UPDATE pvp_stats SET name=?, wins=?, rating=?, updated=? WHERE key=?", (wn, w[0] + 1, max(100, w[2] + delta), now, winner_key))
    dbx("UPDATE pvp_stats SET name=?, losses=?, rating=?, updated=? WHERE key=?", (ln, l[1] + 1, max(100, l[2] - delta), now, loser_key))
    _board_cache.pop("pvp", None)
    hub_say("", "", "%s defeated %s in the arena!" % (wn, ln))


def hub_tick(now):
    for k in [k for k, p in hub_players.items() if now - p["seen"] > HUB_TTL]:
        _hub_drop(k)
    for did, d in list(hub_duels.items()):
        if d["state"] == "count" and now >= d["start"]:
            d["state"] = "fight"
        if d["state"] in ("count", "fight"):
            for k in (d["a"], d["b"]):
                if k not in hub_players:                      # left or timed out: forfeit
                    duel_finish(d, d["b"] if k == d["a"] else d["a"])
                    break
            else:
                if d["state"] == "fight" and now - d["start"] > DUEL_MAX:
                    duel_finish(d, None)
        if d["state"] == "over" and now - d["over_at"] > OVER_LINGER:
            for k in (d["a"], d["b"]):
                hub_duel_of.pop(k, None)
            del hub_duels[did]
    # pair up the queue
    while len(hub_queue) >= 2:
        a, b = hub_queue.pop(0), hub_queue.pop(0)
        if a not in hub_players or b not in hub_players:
            for k in (a, b):
                if k in hub_players:
                    hub_queue.insert(0, k)
            break
        did = secrets.token_hex(6)
        d = {"id": did, "a": a, "b": b, "state": "count", "start": now + COUNTDOWN, "hp": {a: DUEL_HP, b: DUEL_HP},
             "heals": {a: HEAL_COUNT, b: HEAL_COUNT}, "last_hit": {a: 0.0, b: 0.0}, "last_heal": {a: 0.0, b: 0.0},
             "names": {a: hub_players[a]["name"], b: hub_players[b]["name"]}, "winner": "", "over_at": 0.0, "counted": True}
        hub_duels[did] = d
        hub_duel_of[a] = hub_duel_of[b] = did


def _hub_drop(key):
    hub_players.pop(key, None)
    if key in hub_queue:
        hub_queue.remove(key)


def duel_view(key, now):
    did = hub_duel_of.get(key)
    d = hub_duels.get(did) if did else None
    if not d:
        return None
    opp = d["b"] if key == d["a"] else d["a"]
    return {"id": d["id"], "state": d["state"], "side": 0 if key == d["a"] else 1,
            "opp": d["names"][opp], "oppRank": rank_of(opp), "hp": d["hp"][key], "oppHp": d["hp"][opp],
            "maxHp": DUEL_HP, "heals": d["heals"][key], "startIn": round(max(0.0, d["start"] - now), 2),
            "winner": d["names"].get(d["winner"], "") if d["winner"] else "", "iWon": d["winner"] == key,
            "counted": d.get("counted", True)}


def hub_sync(user, b):
    key = user[0].lower()
    now = time.time()
    with hub_lock:
        p = hub_players.get(key)
        if p is None:
            p = {"name": user[0], "rank": rank_of(key), "spec": False, "x": 0.0, "y": 1.0, "z": 0.0, "yaw": 0.0,
                 "w": 0, "a": 0, "last_msg": 0.0}
            hub_players[key] = p
            hub_say("", "", "%s joined the Hall of Fame." % user[0]) if not p["spec"] else None
        p["rank"] = rank_of(key)
        p["seen"] = now
        p["x"] = _num(b.get("x"), -2000, 2000, p["x"])
        p["y"] = _num(b.get("y"), -500, 2000, p["y"])
        p["z"] = _num(b.get("z"), -2000, 2000, p["z"])
        p["yaw"] = _num(b.get("yaw"), -720, 720, p["yaw"])
        p["w"] = int(_num(b.get("w"), 0, 255, p["w"]))
        p["a"] = int(_num(b.get("a"), 0, 255, p["a"]))
        hub_tick(now)
        staff_view = p["rank"] in STAFF_VIEW
        others = []
        for k, o in hub_players.items():
            if k == key or (o["spec"] and not staff_view):
                continue
            others.append({"n": o["name"], "r": o["rank"], "x": round(o["x"], 2), "y": round(o["y"], 2), "z": round(o["z"], 2),
                           "yaw": round(o["yaw"], 1), "w": o["w"], "a": o["a"], "s": 1 if o["spec"] else 0,
                           "d": 1 if k in hub_duel_of else 0})
        since = int(_num(b.get("since"), 0, 10 ** 12, 0))
        msgs = [m for m in hub_chat if m["id"] > since and (m["to"] is None or m["to"] == key)]
        season, left = season_info(now)
        return {"me": {"rank": p["rank"], "spec": p["spec"], "queued": key in hub_queue},
                "players": others, "chat": [{"id": m["id"], "n": m["n"], "r": m["r"], "t": m["t"]} for m in msgs[-30:]],
                "last": hub_chat_id[0], "duel": duel_view(key, now), "queue": len(hub_queue),
                "online": len([1 for o in hub_players.values() if not o["spec"]]),
                "season": season, "seasonLeft": int(left)}


def hub_chat_post(user, b):
    key = user[0].lower()
    now = time.time()
    text = "".join(ch for ch in str(b.get("text", "")) if ch.isprintable() and ch not in "<>").strip()[:200]
    if not text:
        return {"ok": False}
    with hub_lock:
        p = hub_players.get(key)
        if not p:
            return {"ok": False, "error": "Not in the hub."}
        if text.startswith("/"):
            cmd = " ".join(text.lower().split())
            if cmd == "/gamemode s" and p["rank"] in ("owner", "manager", "administrator"):
                p["spec"] = not p["spec"]
                if p["spec"]:
                    _hub_leave_duel_and_queue(key)
                hub_say("", "", "Spectator mode %s." % ("ON: you are invisible and can't interact" if p["spec"] else "OFF"), to=key)
            elif cmd == "/forfeit":
                did = hub_duel_of.get(key)
                d = hub_duels.get(did) if did else None
                if d and d["state"] in ("count", "fight"):
                    duel_finish(d, d["b"] if key == d["a"] else d["a"])
                else:
                    hub_say("", "", "Unknown command.", to=key)
            else:
                hub_say("", "", "Unknown command.", to=key)
            return {"ok": True}
        if p["spec"]:
            hub_say("", "", "You can't chat while in spectator mode.", to=key)
            return {"ok": True}
        if now - p["last_msg"] < 0.8:
            return {"ok": False, "error": "Slow down."}
        p["last_msg"] = now
        hub_say(p["name"], p["rank"], text)
        return {"ok": True}


def _hub_leave_duel_and_queue(key):
    if key in hub_queue:
        hub_queue.remove(key)
    did = hub_duel_of.get(key)
    d = hub_duels.get(did) if did else None
    if d and d["state"] in ("count", "fight"):
        duel_finish(d, d["b"] if key == d["a"] else d["a"])


def hub_duel_action(user, action, b):
    key = user[0].lower()
    now = time.time()
    with hub_lock:
        p = hub_players.get(key)
        if not p:
            return {"ok": False, "error": "Not in the hub."}
        if action == "queue":
            if p["spec"]:
                return {"ok": False, "error": "Spectators can't take part."}
            if key in hub_duel_of:
                return {"ok": False, "error": "You're already in a duel."}
            if b.get("join", True):
                if key not in hub_queue:
                    hub_queue.append(key)
            elif key in hub_queue:
                hub_queue.remove(key)
            hub_tick(now)
            return {"ok": True, "queued": key in hub_queue}
        did = hub_duel_of.get(key)
        d = hub_duels.get(did) if did else None
        if not d or d["state"] != "fight":
            return {"ok": False}
        opp = d["b"] if key == d["a"] else d["a"]
        if action == "hit":
            if now - d["last_hit"][key] < HIT_COOLDOWN:
                return {"ok": False}
            o = hub_players.get(opp)
            if not o or math.hypot(p["x"] - o["x"], p["z"] - o["z"]) > HIT_REACH or abs(p["y"] - o["y"]) > 3.5:
                return {"ok": False}
            d["last_hit"][key] = now
            d["hp"][opp] = max(0, d["hp"][opp] - SWORD_DMG)
            if d["hp"][opp] <= 0:
                duel_finish(d, key)
            return {"ok": True}
        if action == "heal":
            if d["heals"][key] > 0 and now - d["last_heal"][key] > 1.5 and d["hp"][key] < DUEL_HP:
                d["heals"][key] -= 1
                d["last_heal"][key] = now
                d["hp"][key] = min(DUEL_HP, d["hp"][key] + HEAL_AMT)
                return {"ok": True}
        return {"ok": False}


def pvp_board():
    hit = _board_cache.get("pvp")
    if hit and hit[1] > time.time():
        return hit[0]
    rows = dbx("SELECT name, wins, losses, rating FROM pvp_stats WHERE wins + losses > 0 ORDER BY rating DESC, wins DESC LIMIT 10")
    data = []
    for n, w, l, r in rows:
        data.append({"name": n, "wins": w, "losses": l, "rating": r, "rank": rank_of(n.lower())})
    _board_cache["pvp"] = (data, time.time() + 10)
    return data


def season_board(me_key):
    season, left = season_info()
    rows = dbx("SELECT name, score, key FROM season_scores WHERE season=? ORDER BY score DESC, updated ASC LIMIT 50", (season,))
    top = [{"name": r[0], "score": r[1], "rank": rank_of(r[2])} for r in rows[:10]]
    mine = None
    for i, r in enumerate(rows):
        if r[2] == me_key:
            mine = {"place": i + 1, "score": r[1]}
    return {"season": season, "endsIn": int(left), "top": top, "me": mine}


def season_submit(user, b):
    season, _ = season_info()
    if int(_num(b.get("season"), 0, 10 ** 6, -1)) != season:
        return {"ok": False, "error": "That world isn't part of the current season."}
    score = int(_num(b.get("score"), 0, 200000, 0))
    key, now = user[0].lower(), time.time()
    row = dbx("SELECT score, updated FROM season_scores WHERE season=? AND key=?", (season, key))
    if row:
        old, t = row[0]
        allowed = old + 40 + int((now - t) / 60.0 * 500)      # progress can only climb at a believable pace
        score = min(max(score, old), allowed)
        dbx("UPDATE season_scores SET score=?, name=?, updated=? WHERE season=? AND key=?", (score, user[0], now, season, key))
    else:
        score = min(score, 1500)
        dbx("INSERT INTO season_scores (season, key, name, score, updated) VALUES (?,?,?,?,?)", (season, key, user[0], score, now))
    return {"ok": True, "score": score}


def _hub_route(self, method):
    path, q = self._query()
    if path == "/api/hub/leaderboard/pvp" and method == "GET":
        return self._send(200, {"top": pvp_board()})
    if path == "/api/season/leaderboard" and method == "GET":
        u = self._user()
        return self._send(200, season_board(u[0].lower() if u else ""))
    u = self._user()
    if not u:
        return self._send(401, {"error": "Sign in to an online account first."})
    if method == "POST":
        b = self._body() or {}
        if path == "/api/hub/sync":
            return self._send(200, hub_sync(u, b))
        if path == "/api/hub/chat":
            return self._send(200, hub_chat_post(u, b))
        if path == "/api/hub/duel/queue":
            return self._send(200, hub_duel_action(u, "queue", b))
        if path == "/api/hub/duel/hit":
            return self._send(200, hub_duel_action(u, "hit", b))
        if path == "/api/hub/duel/heal":
            return self._send(200, hub_duel_action(u, "heal", b))
        if path == "/api/hub/leave":
            with hub_lock:
                _hub_leave_duel_and_queue(u[0].lower())
                _hub_drop(u[0].lower())
            return self._send(200, {"ok": True})
        if path == "/api/season/score":
            return self._send(200, season_submit(u, b))
    self._send(404, {"error": "Not found."})


Handler._hub_route = _hub_route


if __name__ == "__main__":
    seed_admin()
    print("[server] CraftMine server listening on 0.0.0.0:%d  (db: %s)" % (PORT, DB_PATH))
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
