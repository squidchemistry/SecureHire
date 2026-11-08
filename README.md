# SecureHire

An AI agent that turns a resume and a job description into a match score, a day-by-day prep plan and practice interview questions. It is built so that a **fully compromised model still can't do damage**: a malicious resume can hijack the LLM, but the hijacked tool calls are refused, personal data never reaches the model, and every decision is written to a tamper-evident audit log.

```
React SPA ──HTTP/SSE──► FastAPI ──► Postgres (job queue, results, audit log) ◄── worker(s) ──► agent loop ──► LLM (Groq or mock)
```

## Quick start

**Docker (full stack, Postgres, 2 workers):**

```bash
docker compose up --build          # http://localhost:8080
# ports busy?  WEB_PORT=8095 API_PORT=8011 docker compose up --build
```

**Local dev:**

```bash
cd backend
python -m venv .venv && .venv/Scripts/activate      # or: source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env                                # EMBEDDED_WORKER=true runs the worker in-process
uvicorn app.main:app --reload                       # http://localhost:8000/docs

cd ../frontend
npm install && npm run dev                          # http://localhost:5173 (proxies /api to :8000)
```

No API key is needed: without `GROQ_API_KEY`, a deterministic mock LLM drives the agent. The mock is **deliberately gullible**. It obeys instructions it finds in documents, which lets the tests and the demo show the defences holding against a model that has already been taken over. See [DEMO.md](DEMO.md) for a 3-minute walkthrough.

## How the agent works

One **step** is one LLM call plus the tool calls it proposes ([backend/app/agent/loop.py](backend/app/agent/loop.py)).

| Tool | Needs | Sees |
|---|---|---|
| `parse_resume` | – | resume text, PII-stripped, wrapped in a random `<untrusted-…>` boundary |
| `extract_skills` | resume | closed taxonomy → canonical skill names only |
| `compare_to_jd` | skills | JD is parsed server-side; the model never sees JD text |
| `fetch_past_analyses` | comparison | the caller's own history, scoped by the server |
| `generate_prep_plan` / `generate_questions` | comparison | canonical skill names; output schema-validated, falls back to templates |

**Limits and reliability**, all configurable in [config.py](backend/app/config.py):
- At most 10 steps, 3 calls per step, a per-tool call cap, and 3 consecutive errors before the run fails closed.
- LLM calls and transient tool failures are retried with exponential backoff, and every tool runs under a timeout.
- After every step, the conversation and artifacts are checkpointed to `agent_runs.state`. A crashed worker's run is re-claimed when its lease expires and resumes where it stopped. Writes are fenced by the lease, so a stale worker can't overwrite.
- The queue is the `agent_runs` table: one conditional `UPDATE` claims a run, so two workers never get the same one. Runs that crash repeatedly are reaped after `WORKER_MAX_ATTEMPTS`.

**Live updates.** Each step emits a timeline row, streamed over Server-Sent Events from `GET /api/runs/{id}/events`. The stream can be resumed with `Last-Event-ID`, and the frontend reads it with `fetch`, so the token stays in a header and never appears in a URL. Timeline rows hold counts and names, never document text.

## Security model

Injection detection ([security/injection.py](backend/app/security/injection.py)) is a **signal, not the control**: regexes are easy to evade. The controls are the layers after it.

1. **Per-step allowlist.** The model is offered only the tools whose inputs exist and whose output doesn't yet. Anything else is rejected before it runs and recorded as a security event.
2. **Strict schemas.** Every tool input is a Pydantic model with `extra="forbid"` and bounded fields. Arguments must be a small JSON object.
3. **Server-side identity.** Arguments containing `user_id`, `owner`, `tenant` and similar keys are rejected outright. Tools get the user from `ToolContext`, and every query goes through [repositories.py](backend/app/repositories.py), which requires `user_id`. Another user's row looks exactly like a missing one (404).
4. **Untrusted data stays data.** Only `parse_resume` returns document text to the model, inside an unpredictable boundary, after forged boundaries and `system:`-style role markers are stripped. Downstream tools see canonical skill names only. The report summary is built from structured data, never from model prose.
5. **Generated output is validated.** LLM-written plans and questions must match the schema, reference only known skills, and contain no PII or instruction-like text. Otherwise the run falls back to templates.
6. **PII never reaches the LLM.** Tools redact names, emails, phones, addresses, postcodes and profile URLs. A [PrivacyGuardLLM](backend/app/llm/guard.py) wrapper re-scrubs every outbound message as a single chokepoint. Detection is regex-based, so a name in the middle of free text would need NER.
7. **Data minimisation.** Emails are stored only as an HMAC digest. Uploads are deleted when the run ends, whether it succeeds or fails. Analyses keep derived fields only.
8. **Audit log.** The log is append-only (DB triggers on Postgres and SQLite) and hash-chained, so `python -m app.audit` detects edits even if the triggers are dropped. It stores HMAC references and argument digests, never raw ids or content.
9. **Platform.**
   - Passwords use scrypt, and logins for unknown emails take the same time as real ones.
   - JWTs are HS256 only, with issuer and expiry checks.
   - Auth and run creation are rate-limited, and each user can have a limited number of active runs.
   - Upload types are checked from magic bytes, and upload size and PDF page count are capped.
   - Security headers and CORS are configured, with CORS limited to an allowlist.
   - Production refuses to start with dev secrets.

## Tests

```bash
cd backend && pytest                       # 79 tests, SQLite
TEST_DATABASE_URL=postgresql://… pytest    # same suite on Postgres
ruff check app tests
```

- [test_injection.py](backend/tests/test_injection.py) covers the hijacked cross-user call, identity arguments, unknown and malformed tools, forged boundaries, JD-borne injection, redact mode, poisoned LLM output, and score tampering.
- [test_agent_loop.py](backend/tests/test_agent_loop.py) covers step limits, retries, timeouts, crash and resume, lease fencing, and reaping.
- [test_api.py](backend/tests/test_api.py) covers auth, cross-user isolation, upload validation, SSE, and the audit chain.

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs lint and tests on SQLite and on Postgres, the frontend type-check and build, and a Docker Compose smoke test.

## Deploy

- **Backend: Render.** [render.yaml](render.yaml) creates the API, the worker and Postgres, and generates the secrets. For a single free service, drop the worker and set `EMBEDDED_WORKER=true`.
- **Frontend: Vercel.** Set the root directory to `frontend` and `VITE_API_URL` to the API URL. Then set the API's `ALLOWED_ORIGINS` / `ALLOWED_ORIGIN_REGEX` to the Vercel domain(s).
- **Real model.** Set `GROQ_API_KEY`. Models in `GROQ_MODELS` are tried in order on rate limits and errors.

| Variable | Default | Notes |
|---|---|---|
| `ENV` | development | `production` enforces strong secrets and hides `/docs` |
| `DATABASE_URL` | sqlite | `postgres://` URLs are normalised for psycopg 3 |
| `JWT_SECRET`, `AUDIT_HMAC_KEY`, `IDENTITY_HMAC_KEY` | dev values | 32+ random chars in production |
| `LLM_PROVIDER` | auto | `auto` / `groq` / `mock` |
| `INJECTION_ACTION` | flag | `redact` also removes suspected instructions before the model sees them |
| `EMBEDDED_WORKER` | false | run the worker inside the API process |
| `AGENT_MAX_STEPS`, `AGENT_TOOL_TIMEOUT_S`, `AGENT_MAX_RETRIES` | 10, 20, 2 | agent limits |

## Known limits

- PII detection is regex-based, so a name in the middle of free text isn't caught; that would need an NER model.
- Rate limits are counted per process, so behind several API replicas they belong in Redis or the database.
- A tool that times out keeps running in its thread until it finishes (Python threads can't be killed). The run moves on, and the result is discarded.
