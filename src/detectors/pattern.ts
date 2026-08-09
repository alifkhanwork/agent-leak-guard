import { Detector } from './interface.js';
import { InternalMatch, LeakGuardConfig } from '../types.js';

export interface PatternRule {
  id: string;
  name: string;
  type: string;
  description: string;
  regex: RegExp;
  confidence: 'high' | 'medium' | 'low';
}

/**
 * Built-in pattern rules referencing open-source detection standards (Gitleaks / TruffleHog).
 */
export const BUILTIN_PATTERNS: PatternRule[] = [
  {
    id: 'aws_access_key',
    name: 'AWS Access Key ID',
    type: 'aws_access_key',
    description: 'AWS Access Key Identifier (AKIA/ASIA/ABIA/ACCA)',
    regex: /\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    confidence: 'high',
  },
  {
    id: 'openai_api_key',
    name: 'OpenAI API Key',
    type: 'openai_api_key',
    description: 'OpenAI Secret API key or Project key',
    regex: /\bsk-(proj-)?[a-zA-Z0-9T3BlbkFJ]{20,}\b/g,
    confidence: 'high',
  },
  {
    id: 'anthropic_api_key',
    name: 'Anthropic API Key',
    type: 'anthropic_api_key',
    description: 'Anthropic Claude API key',
    regex: /\bsk-ant-api[0-9a-zA-Z\-_]{32,}\b/g,
    confidence: 'high',
  },
  {
    id: 'github_token',
    name: 'GitHub Personal Access Token',
    type: 'github_token',
    description: 'GitHub Personal Access Token (ghp/gho/ghu/ghs/ghr) or Fine-Grained PAT',
    regex: /\b((ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b/g,
    confidence: 'high',
  },
  {
    id: 'stripe_key',
    name: 'Stripe API Key',
    type: 'stripe_key',
    description: 'Stripe Secret or Restricted API Key',
    regex: /\b(sk|rk)_(test|live)_[0-9a-zA-Z]{24,34}\b/g,
    confidence: 'high',
  },
  {
    id: 'private_key',
    name: 'Private Key Block',
    type: 'private_key',
    description: 'RSA, EC, DSA, OPENSSH, or PGP Private Key',
    regex: /-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)?\s?PRIVATE KEY[^\r\n]*-----[\s\S]+?-----END (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)?\s?PRIVATE KEY[^\r\n]*-----/g,
    confidence: 'high',
  },
  {
    id: 'jwt_token',
    name: 'JSON Web Token (JWT)',
    type: 'jwt_token',
    description: 'JSON Web Token (JWT) string',
    regex: /\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b/g,
    confidence: 'medium',
  },
  {
    id: 'db_connection_string',
    name: 'Database Connection String Credentials',
    type: 'db_connection_string',
    description: 'Database URL containing plaintext username & password credentials',
    regex: /\b(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis):\/\/[^:\s]+:[^@\s]+@[^:\s/]+\b/gi,
    confidence: 'high',
  },
  {
    id: 'slack_token',
    name: 'Slack Token',
    type: 'slack_token',
    description: 'Slack Bot, User, or App token',
    regex: /\bxox[baprs]-[0-9a-zA-Z]{10,48}\b/g,
    confidence: 'high',
  },
  {
    id: 'gcp_api_key',
    name: 'Google Cloud API Key',
    type: 'gcp_api_key',
    description: 'Google Cloud Platform API key',
    regex: /\bAIzaSy[A-Za-z0-9-_]{35}\b/g,
    confidence: 'high',
  },
];

export class PatternDetector implements Detector {
  id = 'pattern_detector';
  name = 'Pattern Detector';
  type = 'pattern';
  description = 'Detects known secret signatures (AWS, OpenAI, Anthropic, GitHub, Stripe, JWT, DB, etc.)';

  detect(content: string, config: LeakGuardConfig): InternalMatch[] {
    const matches: InternalMatch[] = [];

    for (const rule of BUILTIN_PATTERNS) {
      const ruleConfig = config.rules[rule.id];
      if (ruleConfig && ruleConfig.enabled === false) {
        continue;
      }

      // Reset regex index for global regexes
      rule.regex.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = rule.regex.exec(content)) !== null) {
        const secretValue = match[0];
        const start = match.index;
        const end = start + secretValue.length;

        matches.push({
          ruleId: rule.id,
          type: rule.type,
          description: rule.description,
          secretValue,
          start,
          end,
          confidence: rule.confidence,
        });
      }
    }

    return matches;
  }
}
