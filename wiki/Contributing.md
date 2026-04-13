# Contributing

Thank you for considering a contribution to Nyx. Short version: fork, branch, write a test, open a PR. Long version below.

> For the authoritative policy, see [CONTRIBUTING.md](../CONTRIBUTING.md) in the repo root.

---

## Before you start

- **Open an issue first** for anything larger than a typo fix. It saves duplicated effort and lets us flag direction problems before you've written 500 lines.
- **Check the roadmap.** If your idea is already planned, jump on the existing thread instead of opening a new one.
- **Read [CONTRIBUTING.md](../CONTRIBUTING.md).** It specifies the CLA, licensing, and merge policy.

---

## Setting up a dev environment

Full instructions in the [Development Guide](Development.md). Short version:

```bash
git clone https://github.com/<your-fork>/nyx.git
cd nyx
./setup.sh --skip-start     # just configure .env

# Backend
cd backend && python3 -m venv .venv && source .venv/bin/activate
pip install -e .
alembic upgrade head
uvicorn app.main:app --reload

# Frontend (separate terminal)
cd frontend && npm install && npm run dev
```

---

## Branching model

- `main` is always releasable.
- Feature work goes on branches named `feat/short-slug` or `fix/short-slug`.
- Open PRs against `main`. Rebase before merge if your branch is behind.

---

## Writing good PRs

### Title and description

- Title: imperative, ≤ 70 chars. `Add risk acceptance expiry warnings`, not `Added risk acceptance expiry warnings please review`.
- Description: **why**, then **what**. Link the issue. Screenshots or GIFs for UI changes.

### Size

- Keep PRs focused. One logical change per PR. If you find yourself writing "and also", split it.
- 500 lines is a comfortable ceiling. Over that, reviewers start skimming.

### Commits

- Present tense, imperative mood.
- Each commit should be individually valid — CI passes, tests green, lint clean.
- Squash noise ("fix lint", "wip") before requesting review.

---

## Tests

PRs without tests are rejected unless the change is genuinely untestable (docs, config defaults).

- **Backend:** `pytest` in `backend/tests/`. Aim for one happy path and one error path for every new service method.
- **Frontend:** `vitest` in `frontend/src/**/*.test.tsx`. Focus on components with non-trivial rendering logic.

Run the full suite locally before pushing:

```bash
cd backend && pytest
cd ../frontend && npm test -- --run && npm run typecheck && npm run lint
```

---

## Code style

- **Python:** ruff (lint + format) + mypy. Both enforced in CI.
- **TypeScript:** ESLint + Prettier + TS strict. Enforced in CI.
- No comments unless the *why* is non-obvious. The diff already shows the *what*.
- No premature abstractions. Three similar lines is fine.

---

## Security-sensitive changes

If your PR touches authentication, webhook verification, the audit chain, or the diff scanner, call it out explicitly in the PR description. Security-sensitive reviews are slower — plan for that.

---

## Commit authorship

Commits in this repository are authored solely by the contributor making the change. Do not add co-author trailers for AI tools or anyone who did not actually collaborate.

---

## What happens after you open the PR

1. CI runs (lint, typecheck, tests, SAST via Semgrep, supply chain via Trivy).
2. A maintainer reviews within a few days.
3. Review comments come as new commits, not force-pushes over history.
4. Once approved and CI green, a maintainer squash-merges to `main`.

---

## Where to start if you want to help

- Browse open issues labeled `good-first-issue`.
- Look at the **Troubleshooting** page — every entry there is a potential UX improvement.
- Add a new scanner normalizer (see [Adding a Scanner](Adding-a-Scanner.md)).
- Write docs. Docs contributions are always welcome, especially screenshots for this wiki.

---

## Reporting security issues

**Do not open a public issue for security vulnerabilities.** See [SECURITY.md](../SECURITY.md) for the disclosure process.
