# NOTES

Iteration journal. Each iteration appends one entry of at most ten lines (see PROMPT.md section 6). Newest at the bottom.

## 2026-10-13T20:26:10Z T01 attempt 1
- Changed: PLAN.md (new), OPEN_QUESTIONS.md (8 T01 entries), NOTES.md
- Verify: pass (T01 verify command, exit 0)
- Decisions: IC client and shared HTTP client live in core/ (core/ic_client.py is the coverage target for T18); rules are pure and get per-subject event groups from rules/engine.py; no census_runs table (census_run_id + census.run_completed event); span-level redaction.
- Follow-ups: none

## 2026-10-13T22:17:31Z T01 attempt 2
- Changed: NOTES.md, .loop/tasks.json (status); PLAN.md and OPEN_QUESTIONS.md unchanged from attempt 1, which passed verify but was never marked done or committed
- Verify: pass (T01 verify command, exit 0; section 5 pre-commit checks clean)
- Decisions: re-checked acceptance (six sections, all 12 tables typed, T02-T18 mapped, no src/); no edits needed
- Follow-ups: none

## 2026-10-13T22:49:39Z T02 attempt 1
- Changed: pyproject.toml, uv.lock, .python-version, Makefile, Dockerfile, docker-compose.yml, .env.example, LICENSE, README.md (stub for T17), .github/workflows/ci.yml, src/icp_threat_intel/{core/{enums,models,interfaces}.py, cli/app.py, scheduler/__main__.py, 13 stage packages}, tests/unit/test_smoke.py
- Verify: pass (T02 verify command, exit 0; make check: ruff, mypy --strict, 14 tests)
- Decisions: hatchling build backend; dev tools in [dependency-groups] dev (uv sync installs them). ruff `include` is Python-only because ruff 0.17 also formats code blocks in Markdown and rewrote PLAN.md (reverted). `make run` = `python -m icp_threat_intel.scheduler` (SPEC lists no `run` CLI command). LICENSE copied from the canonical Apache-2.0 text (sha256 cfc7749b...).
- Follow-ups: tests/conftest.py socket block and core/config.py land with T03; docker-compose requires POSTGRES_PASSWORD from .env
