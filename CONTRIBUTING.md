# Contributing to Nyx

Thank you for your interest in contributing to Nyx! This guide will help you get started.

## Development Setup

### Prerequisites

- Docker and Docker Compose
- Python 3.11+
- Node.js 20+
- Git

### Quick Start

```bash
# Clone the repository
git clone https://github.com/shadowm82/nyx.git
cd nyx

# Run the setup wizard
./setup.sh

# Or set up manually:
cp .env.example .env
# Edit .env with your configuration
docker compose up -d
```

### Backend Development

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # if available
```

### Frontend Development

```bash
cd frontend
npm install
npm run dev
```

## Code Style

### Python (Backend)

- Formatter/linter: [Ruff](https://docs.astral.sh/ruff/)
- Run before committing: `ruff check . --fix && ruff format .`
- Type hints are encouraged for all public functions

### TypeScript (Frontend)

- Linter: ESLint (config in the frontend directory)
- Run before committing: `npm run lint`
- Use TypeScript strict mode

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. **Make your changes** in focused, atomic commits.
3. **Write or update tests** for any new functionality.
4. **Run linters and tests** locally before pushing.
5. **Open a pull request** against `main` with a clear description of:
   - What the change does
   - Why it is needed
   - How it was tested
6. Address any review feedback promptly.

### PR Checklist

- [ ] Code follows the project style guidelines
- [ ] Tests pass locally
- [ ] Linters pass with no warnings
- [ ] Documentation updated (if applicable)
- [ ] No secrets or credentials committed

## Testing

- **Backend:** Run tests with `pytest` from the `backend/` directory.
- **Frontend:** Run tests with `npm test` from the `frontend/` directory.
- All PRs should include tests for new functionality.
- Bug fix PRs should include a regression test when feasible.

## Commit Message Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

<optional body>
```

### Types

- `feat` -- new feature
- `fix` -- bug fix
- `docs` -- documentation only
- `style` -- formatting, no logic change
- `refactor` -- code restructuring, no feature change
- `test` -- adding or updating tests
- `chore` -- build, CI, dependency updates

### Examples

```
feat(scanner): add Trivy container image scanning
fix(api): return 404 instead of 500 for missing repo
docs: update production deployment guide
chore(deps): bump FastAPI to 0.111
```

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
