import { describe, it, expect } from 'vitest';
import { scan } from '../src/index.js';
import { maskSecretPreview, redactToken } from '../src/redaction/index.js';
import { PatternDetector } from '../src/detectors/pattern.js';

const patternDetector = new PatternDetector();

function buildAwsKey() {
  const chars = [65,75,73,65,90,55,69,88,65,77,80,76,69,49,50,51,52,53,54,55];
  return String.fromCharCode(...chars);
}

function buildOpenAIKey() {
  return 'sk-proj-' + 'a'.repeat(26);
}

function buildAnthropicKey() {
  return 'sk-ant-api03-' + 'a'.repeat(35);
}

function buildGitHubToken() {
  return 'ghp_' + 'A'.repeat(36);
}

function buildStripeKey() {
  return 'sk_test_' + 'A'.repeat(24);
}

function buildJWT() {
  return String.fromCharCode(...'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'.split('').map(c => c.charCodeAt(0)));
}

function buildSlackToken() {
  return 'xoxb-' + '1'.repeat(10) + 'a'.repeat(10);
}

function buildGcpKey() {
  return String.fromCharCode(...'AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWYab'.split('').map(c => c.charCodeAt(0)));
}

function buildAwsExampleKey() {
  const chars = [65,75,73,65,73,79,83,70,79,68,78,78,55,69,88,65,77,80,76,69];
  return String.fromCharCode(...chars);
}

describe('scan', () => {
  describe('true positives', () => {
    it('detects AWS access keys', () => {
      const content = buildAwsKey();
      const result = scan(content);
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.ruleId === 'aws_access_key')).toBe(true);
    });

    it('detects OpenAI API keys', () => {
      const content = buildOpenAIKey();
      const result = scan(content);
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.ruleId === 'openai_api_key')).toBe(true);
    });

    it('detects Anthropic API keys', () => {
      const content = buildAnthropicKey();
      const result = scan(content);
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.ruleId === 'anthropic_api_key')).toBe(true);
    });

    it('detects GitHub tokens', () => {
      const content = buildGitHubToken();
      const result = scan(content);
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.ruleId === 'github_token')).toBe(true);
    });

    it('detects Stripe keys', () => {
      const content = buildStripeKey();
      const result = scan(content);
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.ruleId === 'stripe_key')).toBe(true);
    });

    it('detects private key blocks', () => {
      const content = `-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJLA
-----END RSA PRIVATE KEY-----`;
      const result = scan(content);
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.ruleId === 'private_key')).toBe(true);
    });

    it('detects JWTs', () => {
      const content = buildJWT();
      const result = scan(content);
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.ruleId === 'jwt_token')).toBe(true);
    });

    it('detects DB connection strings with credentials', () => {
      const content = 'postgres://admin:supersecret@localhost:5432/mydb';
      const result = scan(content);
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.ruleId === 'db_connection_string')).toBe(true);
    });

    it('detects Slack tokens', () => {
      const content = buildSlackToken();
      const result = scan(content);
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.ruleId === 'slack_token')).toBe(true);
    });

    it('detects GCP API keys', () => {
      const content = buildGcpKey();
      const result = scan(content);
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.ruleId === 'gcp_api_key')).toBe(true);
    });

    it('detects high entropy strings', () => {
      const content = 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0';
      const result = scan(content);
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.ruleId === 'entropy')).toBe(true);
    });
  });

  describe('true negatives / allowlist', () => {
    it('does not flag known allowlisted example keys', () => {
      const content = buildAwsExampleKey();
      const result = scan(content);
      expect(result.hasFindings).toBe(false);
    });

    it('does not flag dummy test keys', () => {
      const content = 'sk-test-dummy-key-for-testing-purposes-12345678';
      const result = scan(content);
      expect(result.hasFindings).toBe(false);
    });

    it('does not flag common code patterns as entropy', () => {
      const content = 'THIS_IS_A_CONSTANT_NAME_IN_UPPERCASE';
      const result = scan(content);
      expect(result.findings.some(f => f.ruleId === 'entropy')).toBe(false);
    });

    it('does not flag UUIDs as entropy', () => {
      const content = '123e4567-e89b-12d3-a456-426614174000';
      const result = scan(content);
      expect(result.findings.some(f => f.ruleId === 'entropy')).toBe(false);
    });
  });

  describe('redaction', () => {
    it('never exposes raw secret in findings', () => {
      const content = buildAwsKey();
      const result = scan(content);
      for (const f of result.findings) {
        expect(f.rawMatch).not.toBe(content);
        expect(f.rawMatch).toContain('****');
      }
    });

    it('redacts content when mode is redact', () => {
      const content = 'api_key = ' + buildAwsKey();
      const result = scan(content, { mode: 'redact' });
      expect(result.redactedContent).toContain('[REDACTED:aws_access_key]');
      expect(result.redactedContent).not.toContain(buildAwsKey());
    });

    it('does not redact when mode is warn', () => {
      const content = buildAwsKey();
      const result = scan(content, { mode: 'warn' });
      expect(result.redactedContent).toBe(content);
    });
  });

  describe('response modes', () => {
    it('blocks by default', () => {
      const result = scan(buildAwsKey());
      expect(result.isBlocked).toBe(true);
    });

    it('warns without blocking', () => {
      const result = scan(buildAwsKey(), { mode: 'warn' });
      expect(result.isBlocked).toBe(false);
      expect(result.summary.warned).toBeGreaterThan(0);
    });

    it('redacts and proceeds', () => {
      const result = scan(buildAwsKey(), { mode: 'redact' });
      expect(result.isBlocked).toBe(false);
      expect(result.summary.redacted).toBeGreaterThan(0);
    });
  });

  describe('per-type mode override', () => {
    it('blocks AWS keys when rule config says block', () => {
      const result = scan(buildAwsKey(), {
        rules: { aws_access_key: { enabled: true, mode: 'block' } },
      });
      expect(result.isBlocked).toBe(true);
    });
  });
});

describe('maskSecretPreview', () => {
  it('masks long secrets', () => {
    expect(maskSecretPreview(buildAwsExampleKey())).toBe('AKIA****MPLE');
  });

  it('masks short secrets completely', () => {
    expect(maskSecretPreview('abc')).toBe('****');
  });

  it('returns [REDACTED] for empty input', () => {
    expect(maskSecretPreview('')).toBe('[REDACTED]');
  });
});

describe('redactToken', () => {
  it('replaces secret with placeholder', () => {
    const secret = buildAwsExampleKey();
    const result = redactToken('key=' + secret, secret, 'aws_access_key');
    expect(result).toBe('key=[REDACTED:aws_access_key]');
  });

  it('replaces all occurrences', () => {
    const secret = buildAwsExampleKey();
    const result = redactToken(secret + ' ' + secret, secret, 'aws_access_key');
    expect(result).toBe('[REDACTED:aws_access_key] [REDACTED:aws_access_key]');
  });
});
