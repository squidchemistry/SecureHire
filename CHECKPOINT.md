# SecureHire checkpoint

**State (2026-11-08):** code complete against the definition of done in `../RESTART.md`. Tagged `checkpoint-2` and `checkpoint-3`. Not pushed or deployed.

## Verified locally

| Check | Result |
|---|---|
| `pytest` on SQLite | 80 passed |
| `pytest` on Postgres 16 (`TEST_DATABASE_URL`) | 80 passed |
| `ruff check app tests` | clean |
| Frontend `npm run build` (tsc + vite) | builds |
| `docker compose up --build` | db, api, 2 workers, web all start; `/api/health` and `/api/ready` return 200 through nginx on :8080; SPA served |
| Clean demo run | succeeds, 45% match, 6 steps |
| Attack demo run | succeeds, **45% match (unchanged)**, `fetch_past_analyses` blocked, injection flagged |
| SSE timeline | streams the full step history |
| Cross-user read | 404 |
| Audit log | chain verifies; `UPDATE`/`DELETE` on Postgres fail with "audit_log is append-only" |
| Crash recovery | worker killed at step 4; after the 120 s lease the run resumed ("resumed" event) and succeeded on attempt 2 |

## Not verified

- **GitHub Actions CI** has never run: there is no remote yet. This includes the new gitleaks job (`.gitleaks.toml` allowlists the `dev-only-*` placeholders; it was not run locally).
- **Real Groq model:** only the mock LLM was exercised.
- **Browser walkthrough** of the UI: the API flow was driven by script, not clicked through.

## Left for you

1. Create the GitHub repo, `git remote add origin …`, push `main` and the tags, and confirm CI is green.
2. Render: New > Blueprint with `render.yaml`. The free tier has no background workers: either delete the `securehire-worker` block and set `EMBEDDED_WORKER=true`, or use a paid worker. Optionally set `GROQ_API_KEY`.
3. Vercel: root directory `frontend`, `VITE_API_URL` = the Render API URL.
4. Set `ALLOWED_ORIGINS` / `ALLOWED_ORIGIN_REGEX` on Render to the real Vercel domain (render.yaml assumes `securehire.vercel.app`).
5. Walk through DEMO.md on the live site.
