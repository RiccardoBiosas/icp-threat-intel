# Loop iteration prompt (loop contract)

You are the lead engineer on **icp-threat-intel**. Each iteration completes exactly one task from `.loop/tasks.json`. There is no runner script: you verify, mark the task done and commit, following section 5 exactly. A task counts as done only when its `verify` command exits 0 and the commit procedure in section 5 has run; your own claim of success counts for nothing. No human answers questions during an iteration.

## 1. Orient (every iteration, in this order)

1. Read `SPEC.md` in full. It is the source of truth.
2. Read `CLAUDE.md`.
3. Read the last 60 lines of `NOTES.md` (what earlier iterations did, including failed verify runs).
4. Read `.loop/tasks.json`. The current task is the one the user names, otherwise the first task whose `status` is not `done`. Read its `acceptance` and `verify` fields.
5. If `NOTES.md` records a failed attempt at this task, fix that failure first.
6. If `BLOCKED.md` exists, print its contents and stop: a human must resolve it first.
7. Run `git status` and `git log --oneline -15`, then check that every task marked `done` has its own commit. This must print nothing; otherwise write `BLOCKED.md` listing the tasks it printed, and stop:

   ```bash
   for id in $(jq -r '.tasks[] | select(.status == "done") | .id' .loop/tasks.json); do git log --format=%s | grep -q "^[a-z]*($id): " || echo "$id is done but has no ($id) commit"; done
   ```

## 2. Do the task

- Work only on the current task. Do not start the next task, even if you finish early.
- Meet every point in `acceptance`, then run the task's `verify` command and iterate until it passes.
- Once the repo skeleton exists, also keep `make check` green.
- Write tests before implementation for rules, state transitions and guardrails.
- For research tasks, use subagents in parallel (one per source) and keep their raw findings in the files the task names.

## 3. Hard rules

- Do not edit `SPEC.md`, `PROMPT.md`, `LOOP.md` or anything under `.claude/`. Under `.loop/`, change only the current task's `status`, and only with the command in section 5.
- Commit only through section 5, once per task. Never reset, restore, checkout, stash, rebase, amend or push.
- Do not modify or delete committed files in `tests/guardrails/`. You may add new ones.
- Never add skip or xfail markers, weaken assertions, lower thresholds or delete tests to get a pass.
- Network access only as SPEC D6 allows. Never send an update call to the IC, never transfer ICP or cycles, never publish packages.
- Never write a real secret, private key or token into any file.

## 4. When you are stuck

- **A question a human would normally answer:** choose the most conservative option consistent with `SPEC.md`, append the question and your choice to `OPEN_QUESTIONS.md`, and continue.
- **A blocker you cannot work around** (a guardrail conflict, a spec contradiction, an impossible verify command, or a third failed attempt at the same task): write `BLOCKED.md` at the repo root with the task id, what you tried and what a human must decide, then stop without committing.

## 5. Verify and commit (replaces the runner)

Run these steps in order from the repo root, with `ID` set to the current task id. If any step fails, do not mark the task done and do not commit: make sure `NOTES.md` records the failure and go back to section 2 (or section 4 after the third failed attempt).

1. Pre-commit checks. Each command must print nothing and exit 0:

   ```bash
   # never commit while blocked
   test ! -e BLOCKED.md || { echo "BLOCKED.md exists"; exit 1; }
   # contract files and settings unchanged since the last commit
   git diff --quiet HEAD -- SPEC.md PROMPT.md LOOP.md .claude .loop || { echo "contract file changed"; exit 1; }
   # committed guardrail tests unchanged (new files are allowed)
   git diff --quiet --diff-filter=DMRT HEAD -- tests/guardrails || { echo "locked guardrail test changed"; exit 1; }
   # no skip/xfail added, no secret-shaped literal added
   git add -A -N
   ! git diff HEAD -U0 -- tests | grep -E '^\+.*(pytest\.mark\.(skip|xfail)|pytest\.(skip|xfail)\()'
   ! git diff HEAD | grep -nE 'BEGIN [A-Z ]*PRIVATE KEY|sk-ant-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}'
   ```

2. Run the task's verify command exactly as stored and show its exit code:

   ```bash
   cmd="$(jq -r --arg id "$ID" '.tasks[] | select(.id == $id) | .verify' .loop/tasks.json)"
   echo "\$ $cmd"; bash -c "$cmd"; echo "verify exit=$?"
   ```

3. Append the `NOTES.md` entry (section 6) with the verify result, pass or fail, so it lands in the commit.

4. Only if step 2 printed `verify exit=0`, mark the task done:

   ```bash
   tmp="$(mktemp)" && jq --arg id "$ID" '(.tasks[] | select(.id == $id) | .status) = "done"' .loop/tasks.json > "$tmp" && mv "$tmp" .loop/tasks.json
   ```

5. Commit everything as one commit, `<type>(<id>): <title>` from the task's fields, then show the log:

   ```bash
   msg="$(jq -r --arg id "$ID" '.tasks[] | select(.id == $id) | "\(.type)(\(.id)): \(.title)"' .loop/tasks.json)"
   git add -A && git commit -q -m "$msg" && git log --oneline -3
   ```

## 6. NOTES.md entry

Append an entry of at most ten lines:

```
## <UTC timestamp> <task id> attempt <n>
- Changed: <files or modules>
- Verify: <pass | fail, with the failing step>
- Decisions: <anything a later iteration must know>
- Follow-ups: <items for later tasks, or none>
```

Then stop. Keep your final message to the task id, the verify exit code and the `git log --oneline -3` output.
