# Development Guide

Running Nyx locally without Docker, writing tests, and getting a PR merged.

---

## Local setup (without Docker)

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Run migrations
alembic upgrade head

# Start the dev server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The backend hot-reloads on file changes. Point a `.env` file at the repo root or export variables directly.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Vite runs on `http://localhost:5173` by default (not `3000` — that is the Docker-served production build). The dev server proxies `/api/*` to `http://localhost:8000`.

<!-- IMAGE: Two terminals side by side with backend and frontend dev servers running.
     File: wiki/images/dev-servers.png -->
![Dev servers](images/dev-servers.png)
<!-- /IMAGE -->

---

## Running tests

### Backend

```bash
cd backend
pytest                              # all tests
pytest tests/services/              # scoped
pytest -k test_deduplication -xvs   # one by name, verbose, stop on first fail
pytest --cov=app --cov-report=term-missing
```

The test suite uses an in-memory SQLite database per test function — tests are fully isolated and do not touch your real data.

### Frontend

```bash
cd frontend
npm test               # vitest, watch mode
npm run test:ci        # one-shot, coverage
npm run lint
npm run typecheck
```

---

## Code quality

### Python

```bash
cd backend
ruff check app/
ruff format app/
mypy app/
```

All three are enforced in CI. PRs that fail any of them are blocked.

### TypeScript

```bash
cd frontend
npm run lint
npm run typecheck
```

### Pre-commit hooks

```bash
pip install pre-commit
pre-commit install
```

Runs ruff, mypy, and frontend lint on every commit.

---

## Project layout reminder

```
backend/
├── app/
│   ├── main.py              FastAPI entrypoint
│   ├── config.py            Pydantic settings
│   ├── database.py          Async SQLAlchemy engine
│   ├── core/                Auth, logging, exceptions
│   ├── models/              ORM models, one file per aggregate
│   ├── schemas/             Pydantic request/response
│   ├── routers/             One file per resource
│   ├── services/            Business logic
│   │   └── normalization/   One normalizer per scanner
│   └── workers/             Background tasks
├── alembic/                 Migrations
└── tests/                   Pytest suite

frontend/
└── src/
    ├── pages/               Top-level routes
    ├── components/          Reusable UI
    ├── api/                 Typed API client
    ├── store/               Zustand stores
    ├── hooks/               Custom hooks
    └── types/               Shared TS types
```

---

## Adding a new endpoint

1. **Model** — add / extend a SQLAlchemy model in `app/models/`.
2. **Schema** — Pydantic request/response in `app/schemas/`.
3. **Service** — business logic in `app/services/`. Keep routers thin.
4. **Router** — wire the service into an HTTP endpoint in `app/routers/`.
5. **Migration** — `alembic revision --autogenerate -m "add x"` then review the generated file.
6. **Test** — at minimum one happy path and one error case in `tests/`.
7. **Audit** — call `audit_service.log(...)` for any state change.

---

## Adding a frontend page

1. Create `frontend/src/pages/MyPage.tsx`.
2. Register the route in `App.tsx`.
3. Add a sidebar entry in `components/Sidebar.tsx`.
4. Use `api/client.ts` — do **not** fetch from `window.fetch` directly.
5. Write a vitest for any non-trivial rendering logic.

---

## Commit conventions

- Present tense, imperative: `add risk acceptance workflow`, not `added`.
- Prefix with a short category when it helps: `feat:`, `fix:`, `refactor:`, `docs:`, `chore:`.
- Body explains **why**, not **what** — the diff already shows what.
- One logical change per commit. It is fine to have many small commits in one PR.

---

## Opening a pull request

1. Fork and branch from `main`.
2. Run the full quality stack locally: `ruff check`, `mypy`, `pytest`, `npm run lint && npm test`.
3. Open the PR with a clear title and a body that explains the motivation.
4. Link the issue it addresses.
5. Expect review comments — address them in new commits rather than force-pushing over history.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full policy.

---

## Debugging tips

| Symptom | Try |
|---|---|
| Migrations out of sync | `alembic current`, `alembic history`, reset with `alembic stamp head` |
| CORS errors in the browser | Make sure `CORS_ALLOWED_ORIGINS` includes your dev origin |
| Frontend can't reach backend | Check the Vite proxy in `vite.config.ts` |
| SQLAlchemy warnings about sessions | You are mixing sync and async sessions — use `async with SessionLocal()` |
| Claude returns nothing | Check `ANTHROPIC_API_KEY`, check `/health/integrations`, check `AI_MAX_TOKENS` |
| Webhooks return 401 | Signature mismatch — re-install the webhook from the repo page |

---

## What next

- **Add a scanner normalizer →** [Adding a Scanner](Adding-a-Scanner.md)
- **Architecture overview →** [Architecture](Architecture.md)
