---
description: Finish a task — lint, full test suite at 100% coverage, then a Conventional Commit
allowed-tools: Bash(npm run lint:*), Bash(npm run coverage), Bash(git add:*), Bash(git commit:*), Bash(git status:*), Bash(git diff:*)
---

Wrap up the current change. Stop and report at the first failure — do not commit if any step fails.

1. `npm run lint` — must pass clean.
2. `npm run coverage` — suite must pass and stay at 100% lines/branches/functions/statements.
3. Show `git status` and `git diff` so the changes are clear.
4. Stage the relevant files and create a single commit using **Conventional Commits**
   (`<type>: <msg>`, type ∈ `feat|fix|chore|docs|refactor|test|build`). No co-authoring.
   **Do not `git push`.**

Never weaken or skip a test or lower coverage thresholds to make a step pass.

$ARGUMENTS
