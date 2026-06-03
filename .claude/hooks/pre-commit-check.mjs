#!/usr/bin/env node
// PreToolUse(Bash) hook: when the command is a `git commit`, enforce CLAUDE.md's
// "lint + test must pass" rule by running them first. Exit 2 blocks the commit
// and feeds stderr back to Claude; any other command passes through untouched.
import { execSync } from 'node:child_process';

let raw = '';
process.stdin.on('data', (chunk) => (raw += chunk));
process.stdin.on('end', () => {
  let command = '';
  try {
    command = JSON.parse(raw || '{}').tool_input?.command ?? '';
  } catch {
    process.exit(0); // unparsable input — don't block
  }

  // Only gate real commits (ignore `git commit --help`, `git log`, etc.).
  if (!/\bgit\s+commit\b/.test(command) || /\bgit\s+commit\b.*--help/.test(command)) {
    process.exit(0);
  }

  for (const [label, cmd] of [
    ['lint', 'npm run lint'],
    ['tests', 'npm test'],
  ]) {
    try {
      execSync(cmd, { stdio: 'pipe' });
    } catch (err) {
      const out = `${err.stdout ?? ''}${err.stderr ?? ''}`.trim();
      console.error(
        `Pre-commit ${label} check failed (\`${cmd}\`). Fix this before committing:\n\n${out}`,
      );
      process.exit(2);
    }
  }

  process.exit(0);
});
