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
