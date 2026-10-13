# Loop engineering kit: icp-threat-intel

This kit builds **icp-threat-intel** with Claude Code, one task per iteration, against a fixed spec. There is no runner script: each iteration is a Claude Code session that follows the contract in `PROMPT.md`. A task is done only when its `verify` command from `.loop/tasks.json` exits 0 and the agent has committed it through the procedure in `PROMPT.md` section 5.

## What is in the kit

| File | Owner | Purpose |
|---|---|---|
| `SPEC.md` | You | Stable spec: product, pre-answered decisions, ground truth, hypotheses, sources, architecture, guardrails, definition of done |
| `PROMPT.md` | You | The loop contract: orient, do one task, hard rules, how to verify and commit, how to record questions or blockers |
| `CLAUDE.md` | Agent (T17), contract import by you | Loaded into every session; imports `PROMPT.md` so every session sees the contract |
| `.loop/tasks.json` | You; agent changes `status` only | 18 ordered tasks, each with acceptance criteria and a shell `verify` command |
| `.claude/settings.json` | You | Deny rules: no edits to contract files, no reset/push/history rewrites, no `dfx`, no publishing |
| `NOTES.md` | Agent | Iteration journal, appended every iteration |
| `OPEN_QUESTIONS.md` | Agent | Questions the agent could not ask, with the default it chose |
| `BLOCKED.md` | Agent | Written when the agent cannot continue. Not gitignored, so `git status` shows it; the pre-commit checks refuse to commit while it exists. Delete it once resolved |

## How one iteration works

1. The agent picks the task you name, or the first task not marked `done`.
2. It reads the spec, notes and any earlier failed attempt, and checks that every task marked `done` has its own `(Txx)` commit. Then it does that one task.
3. Before committing, it runs the checks the old runner did, as plain git commands (`PROMPT.md` section 5):
   - contract files (`SPEC.md`, `PROMPT.md`, `LOOP.md`, `.claude/`, `.loop/`) are unchanged since the last commit;
   - committed guardrail tests in `tests/guardrails/` are unchanged (new files are allowed);
   - the diff adds no `skip`/`xfail` and no secret-shaped strings;
   - `BLOCKED.md` does not exist.
4. It runs the task's `verify` command exactly as stored in `tasks.json` and shows the exit code.
5. Pass: it appends to `NOTES.md`, sets the task's `status` to `done`, commits everything as `<type>(Txx): <title>` and shows `git log --oneline -3`. Fail: it records the failure in `NOTES.md` and keeps working. After the third failed attempt, or for a blocker it cannot work around, it writes `BLOCKED.md` and stops without committing.

## Commands

### 1. Prerequisites (once)

```bash
curl -fsSL https://claude.ai/install.sh | bash      # or: npm install -g @anthropic-ai/claude-code
claude update && claude -v
claude auth login                                    # or export ANTHROPIC_API_KEY for API billing
curl -LsSf https://astral.sh/uv/install.sh | sh      # uv (Python 3.12 is fetched by uv)
sudo apt-get install -y jq git make                  # macOS: brew install jq
```

### 2. Run one iteration

Interactive, with a goal that matches the contract:

```
claude
/goal Task T02 in .loop/tasks.json is "done" and committed per the loop contract in PROMPT.md section 5, with its verify output shown exiting 0 before the commit, followed by `git log --oneline -3`. Stop if BLOCKED.md exists, or after 15 turns.
```

The goal's stop hook judges from the conversation, not from the repo, and has been seen to keep blocking after a stop clause applied. If an iteration ends blocked and the hook keeps firing, run `/goal clear`; `BLOCKED.md` is the record of why.

Headless:

```bash
claude -p "Run one iteration of the loop contract in PROMPT.md for the next task." --permission-mode auto
```

Read what it did before starting the next one:

```bash
git log --stat -1
tail -20 NOTES.md
cat OPEN_QUESTIONS.md
```

### 3. Status

```bash
jq -r '.tasks[] | "\(.id)  \(.status)  \(.title)"' .loop/tasks.json
test -f BLOCKED.md && cat BLOCKED.md
```

### 4. Redo a task

Fix `SPEC.md` (not the agent's output), reset the task and commit the reset yourself:

```bash
jq '(.tasks[] | select(.id=="T01") | .status) = "pending"' .loop/tasks.json > /tmp/t && mv /tmp/t .loop/tasks.json
git rm -q PLAN.md && git commit -qam "chore(loop): redo T01"
```

### 5. When it stops

Read `BLOCKED.md`, fix the cause (usually by editing `SPEC.md` or answering an entry in `OPEN_QUESTIONS.md` there), delete `BLOCKED.md` and run the next iteration.

### 6. After every task is done

```bash
make check && make coverage        # rerun the gate yourself
make bootstrap                     # needs Docker: seeds IOCs, inspects both seed canisters
git log --oneline                  # one commit per verified task
```

Review `OPEN_QUESTIONS.md` and the last `NOTES.md` entry first, then the guardrail tests, then the rules.

## Limits worth knowing

- Without a runner, nothing independent checks the agent's work: the agent runs the verify command and commits it itself. Check each commit's message, diff and the verify output it showed before starting the next task.
- The deny rules in `.claude/settings.json` cover Claude's file tools, recognised shell file commands and redirects, but not a script that opens files itself. The pre-commit checks in `PROMPT.md` catch changes to contract files and locked guardrail tests, but only if the agent runs them.
- The verify commands prove structure and passing tests, not correctness of detection logic. Read the rules and guardrail tests yourself before publishing anything from this tool.
- Cassette recording (T07–T09) touches live IC hosts once. If the network is unavailable, the agent falls back to labelled synthetic fixtures and logs it; rerun `make record` yourself later.
