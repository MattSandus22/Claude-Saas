# Deploying MCPGuard

This guide walks through a production deployment of MCPGuard using three managed
services. Each does one job:

| Service | Role | What it hosts |
| --- | --- | --- |
| **Supabase** | Managed Postgres database | `backend/` data only — **not** the app |
| **Railway** or **Render** | Application server | The FastAPI backend (`backend/`) |
| **Vercel** | Static/edge host | The Next.js frontend (`frontend/`) |

The frontend (browser) talks to the backend over HTTPS; the backend talks to
Postgres. Supabase cannot run the FastAPI process — it is a database, so it
holds data and nothing else. You need a real app host (Railway or Render) for
the API.

```
Browser ──HTTPS──▶ Vercel (Next.js)  ──HTTPS──▶ Railway/Render (FastAPI) ──▶ Supabase (Postgres)
```

Deploy in this order: **database → backend → frontend**, because each step needs
a URL from the one before it.

---

## 1. Database — Supabase

1. Create a project at [supabase.com](https://supabase.com). Pick a strong
   database password and save it.
2. In the dashboard, open **Project Settings → Database → Connection string**
   and copy the **URI**. It looks like:
   ```
   postgresql://postgres:YOUR-PASSWORD@db.abcdefgh.supabase.co:5432/postgres
   ```
3. MCPGuard uses the async `asyncpg` driver, so change the scheme from
   `postgresql://` to `postgresql+asyncpg://`. The value you give the backend as
   `DATABASE_URL` becomes:
   ```
   postgresql+asyncpg://postgres:YOUR-PASSWORD@db.abcdefgh.supabase.co:5432/postgres
   ```

### Important: use the direct connection (port 5432), not the pooler (6543)

Supabase also offers a connection **pooler** on port `6543` (Supavisor in
"transaction" mode). Do **not** use it with this backend. `asyncpg` relies on
server-side prepared statements, which a transaction-mode pooler breaks — you
get intermittent `prepared statement "__asyncpg_..." does not exist` errors
under load. Use the **direct** connection on port **5432** shown above.

If your backend host cannot reach port 5432 over IPv6 (some free tiers are
IPv4-only), enable Supabase's IPv4 add-on or the **Session** pooler (port 5432,
session mode — which *does* keep prepared statements working), but never the
transaction pooler on 6543.

> **Schema note:** the backend currently creates its tables with SQLAlchemy
> `create_all` on startup (see `backend/app/db/session.py`) rather than Alembic
> migrations. That is fine for launch and demos — the tables are created
> automatically on first boot. Before you store real customer data, wire up
> Alembic (already a dependency) so schema changes are versioned and reversible.

---

## 2. Backend — Railway or Render

Both work. Railway is the fastest path; Render's free tier sleeps on inactivity.

**Root directory:** `backend`
**Start command:**
```
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```
**Build / install:** `pip install -r requirements.txt` (auto-detected from
`backend/requirements.txt`; a `Dockerfile` is also present if you prefer a
container build).

### Environment variables

| Variable | Value | Notes |
| --- | --- | --- |
| `ENV` | `production` | Enables fail-fast checks (e.g. refuses to start without a real `JWT_SECRET`). |
| `JWT_SECRET` | *(generate one)* | `openssl rand -base64 48`. Never commit it. Rotating it logs everyone out. |
| `DATABASE_URL` | *(from step 1)* | The `postgresql+asyncpg://…:5432/postgres` string. |
| `CORS_ORIGINS` | `https://your-app.vercel.app` | Your frontend's public URL (comma-separated if more than one). No trailing slash. Set this **after** step 3, then redeploy. |
| `FIRST_ADMIN_EMAIL` | your admin email | Seeded on first boot only, when no users exist. |
| `FIRST_ADMIN_PASSWORD` | a strong password | Change it immediately after first login. |

Optional, if you use them: `REDIS_URL` (distributed rate limiting across
replicas), `ALERT_WEBHOOK_URL` (Slack/PagerDuty/SIEM routing),
`PROMETHEUS_BEARER_TOKEN` (enables the gated `/metrics` scrape endpoint). See
`backend/.env.example` for the full list and defaults.

### Verify

Once deployed, hit the health check:
```
curl https://your-backend.up.railway.app/health
# {"status":"ok","service":"MCPGuard","version":"0.1.0"}
```
The API is served under `/api/v1` (e.g. `POST /api/v1/auth/login`).

---

## 3. Frontend — Vercel

1. Import the repository at [vercel.com/new](https://vercel.com/new).
2. **Framework preset:** `Next.js` (auto-detected).
3. **Root directory:** `frontend` — set this, or the build won't find the app.
4. **Environment variable:**

   | Variable | Value |
   | --- | --- |
   | `NEXT_PUBLIC_API_BASE_URL` | `https://your-backend.up.railway.app/api/v1` |

   This is baked in at build time (it's a `NEXT_PUBLIC_*` var), so if you change
   it later you must **redeploy** the frontend for it to take effect.
5. Deploy. Vercel gives you a URL like `https://your-app.vercel.app`.

### Close the loop

Go back to the backend (step 2) and set `CORS_ORIGINS` to that exact Vercel URL,
then redeploy the backend. Without this the browser will block API calls with a
CORS error.

---

## 4. First login

1. Open the Vercel URL.
2. Log in with `FIRST_ADMIN_EMAIL` / `FIRST_ADMIN_PASSWORD` from step 2.
3. Change the admin password immediately.
4. (Optional) Seed demo data to populate the dashboard. From the backend host's
   shell, or locally against the production `DATABASE_URL`:
   ```
   cd backend && python -m seeds.demo_data
   ```
   This adds sample MCP servers, a poisoned tool, inspected messages, alerts and
   incidents so the dashboards aren't empty during a demo.

---

## Deployment checklist

- [ ] Supabase project created; `DATABASE_URL` uses `postgresql+asyncpg://` on port **5432** (not 6543).
- [ ] Backend deployed with root dir `backend` and the `uvicorn` start command.
- [ ] `ENV=production` and a freshly generated `JWT_SECRET` set on the backend.
- [ ] `/health` returns `{"status":"ok",...}`.
- [ ] Frontend deployed on Vercel with root dir `frontend` and `NEXT_PUBLIC_API_BASE_URL` set.
- [ ] Backend `CORS_ORIGINS` set to the Vercel URL and backend redeployed.
- [ ] Logged in and rotated the admin password.

## Before real customer data (production hardening)

- Replace `create_all` with **Alembic** migrations for versioned schema changes.
- Set a **`REDIS_URL`** so rate limiting is shared across backend replicas.
- Set a strong, unique `JWT_SECRET` and store it in your host's secret manager.
- Configure `ALERT_WEBHOOK_URL` for real alert routing (Slack / PagerDuty / SIEM).
- Review `CORS_ORIGINS` — list only the origins you actually serve, never `*`.

## Local development

For running the whole stack on your machine (SQLite, zero infra), see the
"Quickstart" section of [`README.md`](./README.md). `docker-compose.yml` brings
up the backend, frontend, and Postgres together if you prefer containers.
