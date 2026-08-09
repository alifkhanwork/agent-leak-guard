import { Command } from 'commander';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { scan, loadConfig } from '../index.js';

const program = new Command();

program
  .name('agent-leak-guard')
  .description('Inline secret leak scanner for AI coding agents')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan a file or stdin for leaked secrets')
  .option('-c, --config <path>', 'Path to .leakguard.json config file')
  .option('-m, --mode <mode>', 'Override response mode (warn, block, redact)')
  .option('--stdin', 'Read content from stdin instead of a file')
  .argument('[file]', 'File to scan')
  .action(async (file?: string, opts?: { config?: string; mode?: string; stdin?: boolean }) => {
    const configPath = opts?.config;
    let content = '';

    if (opts?.stdin || !file) {
      content = await readStdin();
    } else {
      content = fs.readFileSync(file, 'utf8');
    }

    const result = scan(content, {
      configPath,
      mode: opts?.mode as any,
      filePath: file,
    });

    printResult(result);
  });

program
  .command('install-hook')
  .description('Install a pre-commit git hook')
  .option('--global', 'Install hook globally for all repos', false)
  .action((opts?: { global?: boolean }) => {
    const hookPath = getHookPath();
    const content = generateHookScript();

    if (!fs.existsSync(hookPath)) {
      fs.mkdirSync(hookPath, { recursive: true });
    }

    const target = path.join(hookPath, 'pre-commit');
    fs.writeFileSync(target, content, { mode: 0o755 });
    console.log(`Pre-commit hook installed at ${target}`);
  });

program.parse();

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk: string) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
  });
}

function printResult(result: ReturnType<typeof scan>) {
  if (result.isBlocked) {
    console.error(`\n❌ LeakGuard: Blocked ${result.summary.blocked} secret(s)\n`);
    for (const f of result.findings) {
      console.error(`  [${f.action.toUpperCase()}] ${f.ruleId}: ${f.description}`);
      console.error(`    Match: ${f.rawMatch}\n`);
    }
    process.exit(1);
  }

  if (result.summary.warned > 0) {
    console.log(`⚠️  LeakGuard: Warned ${result.summary.warned} secret(s)`);
    for (const f of result.findings) {
      console.log(`  [${f.action.toUpperCase()}] ${f.ruleId}: ${f.description}`);
      console.log(`    Match: ${f.rawMatch}`);
    }
  }

  if (result.summary.redacted > 0) {
    console.log(`🧹 LeakGuard: Redacted ${result.summary.redacted} secret(s)`);
  }

  if (result.hasFindings) {
    console.log('\nScan complete with findings.');
  } else {
    console.log('✅ LeakGuard: No secrets detected.');
  }
}

function getHookPath(): string {
  const repoRoot = findGitRoot();
  return path.join(repoRoot, '.git', 'hooks');
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
