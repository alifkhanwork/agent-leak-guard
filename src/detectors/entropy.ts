import { Detector } from './interface.js';
import { InternalMatch, LeakGuardConfig } from '../types.js';

/**
 * Computes Shannon Entropy (bits per character) of a string.
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX_HASH_REGEX = /^[0-9a-fA-F]{32,64}$/;
const COMMON_CODE_PATTERNS = [
  /^[A-Z_]{10,60}$/, // CONSTANT_NAMES_IN_UPPERCASE
  /^https?:\/\//i,
  /^[a-zA-Z0-9_-]+\.(png|jpg|jpeg|svg|css|html|js|ts|json|md|py|go|rs|java)$/i,
];

export class EntropyDetector implements Detector {
  id = 'entropy';
  name = 'High Entropy Detector';
  type = 'high_entropy_string';
  description = 'Detects high-entropy random strings (potential unpatterned API keys, secrets, or passwords)';

  detect(content: string, config: LeakGuardConfig): InternalMatch[] {
    const ruleConfig = config.rules['entropy'];
    if (ruleConfig && ruleConfig.enabled === false) {
      return [];
    }

    const threshold = config.entropyThreshold ?? 4.5;
    const minLength = config.entropyMinLength ?? 20;
    const matches: InternalMatch[] = [];

    // Extract continuous alphanumeric/base64 token candidates
    const tokenRegex = /[A-Za-z0-9+/=_~-]{20,}/g;
    let match: RegExpExecArray | null;

    while ((match = tokenRegex.exec(content)) !== null) {
      const token = match[0];
      if (token.length < minLength) continue;

      // Skip UUIDs, hex hashes, and standard code noise
      if (UUID_REGEX.test(token)) continue;
      if (HEX_HASH_REGEX.test(token)) continue;
      if (COMMON_CODE_PATTERNS.some((p) => p.test(token))) continue;

      const entropy = calculateShannonEntropy(token);

      if (entropy >= threshold) {
        matches.push({
          ruleId: 'entropy',
          type: this.type,
          description: `High entropy string detected (${entropy.toFixed(2)} bits/char)`,
          secretValue: token,
          start: match.index,
          end: match.index + token.length,
          confidence: entropy >= 5.2 ? 'high' : 'medium',
        });
      }
    }

    return matches;
  }
}
