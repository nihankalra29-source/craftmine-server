# CraftMine server
Accounts + cloud saves so players can sign in from any machine. Python 3 stdlib only.

    ADMIN_PASSWORD='pick-a-long-password' python3 server.py

Then put its URL in the launcher (Settings -> Server). To use it from anywhere, host it on a public
HTTPS URL (Render, Fly, a VPS...) and set `CRAFTMINE_DB` to a persistent disk path.
The `Administrator` account is created/updated from `ADMIN_PASSWORD` on every start.

## Multiplayer directory (groundwork)
`GET /api/servers` lists active worlds, `POST /api/servers` (signed in) registers or heartbeats one
(listings expire after 90 s), `DELETE /api/servers` removes yours. See `../Docs/Multiplayer.md`.

## Hosting notes
Runs on any host that keeps a process and a disk (Render, Fly, Railway, a VPS). It will not run on Vercel (serverless: no persistent SQLite, no long-lived process).
