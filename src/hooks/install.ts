import * as fs from 'node:fs';
import * as path from 'node:path';

export function installHook(targetDir?: string): string {
  const hookDir = targetDir || path.join(findGitRoot(), '.git', 'hooks');
  const hookPath = path.join(hookDir, 'pre-commit');
  const script = generateHookScript();

  if (!fs.existsSync(hookDir)) {
    fs.mkdirSync(hookDir, { recursive: true });
  }

  fs.writeFileSync(hookPath, script, { mode: 0o755 });
  return hookPath;
}

function findGitRoot(): string {
  let dir = process.cwd();
  while (dir !== path.dirname(dir)) {
    if (fs.existsSync(path.join(dir, '.git'))) {
      return dir;
    }
    dir = path.dirname(dir);
  }
  return process.cwd();
}

function generateHookScript(): string {
  return `#!/bin/sh
# agent-leak-guard pre-commit hook
# Blocks commits containing leaked secrets

STAGED=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED" ]; then
  exit 0
fi

echo "$STAGED" | while read -r file; do
  if [ -f "$file" ]; then
    npx agent-leak-guard scan "$file" || exit 1
  fi
done

exit 0
`;
}
