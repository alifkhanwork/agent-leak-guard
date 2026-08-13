import * as fs from 'node:fs';
import * as path from 'node:path';
import { LeakGuardConfig } from './types.js';

export const DEFAULT_CONFIG: LeakGuardConfig = {
  defaultMode: 'block',
  entropyThreshold: 4.5,
  entropyMinLength: 20,
  allowlist: {
    strings: [
      'AKIAIOSFODNN7EXAMPLE', // Standard AWS documentation example key
      'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', // Standard AWS example secret key
      'sk-test-dummy-key-for-testing-purposes-12345678',
      '00000000-0000-0000-0000-000000000000',
    ],
    regexes: [
      '^EXAMPLE_',
      '^TEST_',
      '^DUMMY_',
    ],
    files: [
      '**/node_modules/**',
      '**/*.min.js',
      '**/*.map',
      '**/package-lock.json',
      '**/yarn.lock',
      '**/pnpm-lock.yaml',
    ],
  },
  rules: {
    aws_access_key: { enabled: true, mode: 'block' },
    openai_api_key: { enabled: true, mode: 'block' },
    anthropic_api_key: { enabled: true, mode: 'block' },
    github_token: { enabled: true, mode: 'block' },
    stripe_key: { enabled: true, mode: 'block' },
    private_key: { enabled: true, mode: 'block' },
    jwt_token: { enabled: true, mode: 'warn' },
    db_connection_string: { enabled: true, mode: 'block' },
    slack_token: { enabled: true, mode: 'block' },
    gcp_api_key: { enabled: true, mode: 'block' },
    entropy: { enabled: true, mode: 'warn' },
  },
};

/**
 * Loads configuration from file path or resolves `.leakguard.json` in working dir hierarchy.
 */
export function loadConfig(configPath?: string): LeakGuardConfig {
  let targetPath = configPath;

  if (!targetPath) {
    let currentDir = process.cwd();
    while (currentDir) {
      const candidate = path.join(currentDir, '.leakguard.json');
      if (fs.existsSync(candidate)) {
        targetPath = candidate;
        break;
      }
      const parent = path.dirname(currentDir);
      if (parent === currentDir) break;
      currentDir = parent;
    }
  }

  if (targetPath && fs.existsSync(targetPath)) {
    try {
      const fileContent = fs.readFileSync(targetPath, 'utf8');
      const parsed = JSON.parse(fileContent);
      return mergeConfig(DEFAULT_CONFIG, parsed);
    } catch {
      return DEFAULT_CONFIG;
    }
  }

  return DEFAULT_CONFIG;
}

/**
 * Merges user config with defaults.
 */
export function mergeConfig(
  base: LeakGuardConfig,
  overrides?: Partial<LeakGuardConfig>
): LeakGuardConfig {
  if (!overrides) return base;

  return {
    defaultMode: overrides.defaultMode || base.defaultMode,
    entropyThreshold: overrides.entropyThreshold ?? base.entropyThreshold,
    entropyMinLength: overrides.entropyMinLength ?? base.entropyMinLength,
    allowlist: {
      strings: Array.from(
        new Set([...base.allowlist.strings, ...(overrides.allowlist?.strings || [])])
      ),
      regexes: Array.from(
        new Set([...base.allowlist.regexes, ...(overrides.allowlist?.regexes || [])])
      ),
      files: Array.from(
        new Set([...base.allowlist.files, ...(overrides.allowlist?.files || [])])
      ),
    },
    rules: {
      ...base.rules,
      ...(overrides.rules || {}),
    },
  };
}

/**
 * Checks if a string or secret match is allowlisted.
 */
export function isAllowlisted(secretValue: string, config: LeakGuardConfig): boolean {
  if (!secretValue) return false;

  // Direct string match
  if (config.allowlist.strings.includes(secretValue)) {
    return true;
  }

  // Regex pattern match
  for (const pattern of config.allowlist.regexes) {
    try {
      const reg = new RegExp(pattern, 'i');
      if (reg.test(secretValue)) {
        return true;
      }
    } catch {
      // Ignore invalid user regex
    }
  }

  return false;
}
