# Agent Leak Guard

Inline secret leak scanner, redactor, CLI, and git hook for AI coding agents.

Scans content an AI coding agent is about to write, commit, or output — files, diffs, terminal output, logs — for accidentally leaked API keys, tokens, or credentials, and blocks or redacts them before they land anywhere.

## Installation

```bash
npm install agent-leak-guard
```

## Quick Start

```bash
# Scan a file
npx agent-leak-guard scan path/to/file.js

# Scan from stdin
cat file.js | npx agent-leak-guard scan --stdin

# Install pre-commit hook
npx agent-leak-guard install-hook
```

## Library Usage

```ts
import { scan } from 'agent-leak-guard';

const result = scan('AWS_KEY=AKIAIOSFODNN7EXAMPLE', {
  mode: 'block', // warn | block | redact
});

console.log(result.hasFindings); // true
console.log(result.isBlocked);   // true
console.log(result.findings[0].rawMatch); // AKIA****MPLE (never the full secret)
```

## Response Modes

| Mode | Behavior |
|------|----------|
| `warn` | Flag the finding, redact in output, allow action to proceed |
| `block` | Prevent write/commit/output, show redacted finding and reason |
| `redact` | Replace detected secret with `[REDACTED:<type>]` and proceed |

## Configuration

Create `.leakguard.json` in your project root:

```json
{
  "defaultMode": "block",
  "entropyThreshold": 4.5,
  "entropyMinLength": 20,
  "allowlist": {
    "strings": ["AKIAIOSFODNN7EXAMPLE"],
    "regexes": ["^TEST_", "^EXAMPLE_"],
    "files": ["**/node_modules/**", "**/*.min.js"]
  },
  "rules": {
    "aws_access_key": { "enabled": true, "mode": "block" },
    "jwt_token": { "enabled": true, "mode": "warn" },
    "entropy": { "enabled": true, "mode": "warn" }
  }
}
```

## Integration with agent-permit

Use `agent-leak-guard` as an inline check in your agent middleware:

```ts
import { scan } from 'agent-leak-guard';

async function onFileWrite(content: string) {
  const result = scan(content, { filePath: '/path/to/file' });
  if (result.isBlocked) {
    throw new Error(`Secret leak blocked: ${result.summary.blocked} finding(s)`);
  }
  return result.redactedContent;
}
```

## Detectors

- AWS Access Keys (`AKIA`/`ASIA`/`ABIA`/`ACCA`)
- OpenAI API Keys (`sk-...`)
- Anthropic API Keys (`sk-ant-api...`)
- GitHub Personal Access Tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`)
- Stripe API Keys (`sk_test_`, `sk_live_`, `rk_test_`, `rk_live_`)
- Private Key Blocks (`-----BEGIN ... PRIVATE KEY-----`)
- JSON Web Tokens (JWT)
- Database Connection Strings with credentials
- Slack Tokens (`xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`)
- Google Cloud API Keys (`AIzaSy...`)
- High-Entropy Strings (fallback for unknown tokens)

Patterns reference open-source standards such as [gitleaks](https://github.com/gitleaks/gitleaks) and [trufflehog](https://github.com/trufflesecurity/trufflehog).

## Never Leak the Leak

All findings are redacted before exposure. The `rawMatch` field contains only a masked preview (e.g. `AKIA****MPLE`). Full secret values are never logged, returned, or persisted.

## License

MIT
