import { PatternDetector } from './detectors/pattern.js';
import { EntropyDetector } from './detectors/entropy.js';
import { ScanOptions, ScanResult, InternalMatch } from './types.js';
import { loadConfig, mergeConfig, isAllowlisted } from './config.js';
import { redactToken, redactAllMatches, maskSecretPreview } from './redaction/index.js';

const detectors = [new PatternDetector(), new EntropyDetector()];

export function scan(content: string, options: ScanOptions = {}): ScanResult {
  const config = mergeConfig(loadConfig(options.configPath), {
    defaultMode: options.mode,
    rules: options.rules,
    entropyThreshold: options.entropyThreshold,
  });

  const findings: ScanResult['findings'] = [];
  const internalMatches: InternalMatch[] = [];

  for (const detector of detectors) {
    const matches = detector.detect(content, config);
    internalMatches.push(...matches);
  }

  let redactedContent = content;

  for (const match of internalMatches) {
    if (isAllowlisted(match.secretValue, config)) continue;

    const ruleConfig = config.rules[match.ruleId] || {};
    const action: ScanOptions['mode'] = options.mode || ruleConfig.mode || config.defaultMode;

    if (action === 'block' || action === 'warn') {
      findings.push({
        type: match.type,
        ruleId: match.ruleId,
        description: match.description,
        rawMatch: maskSecretPreview(match.secretValue),
        location: { start: match.start, end: match.end },
        confidence: match.confidence,
        action,
      });
    }

    if (action === 'redact') {
      findings.push({
        type: match.type,
        ruleId: match.ruleId,
        description: match.description,
        rawMatch: maskSecretPreview(match.secretValue),
        location: { start: match.start, end: match.end },
        confidence: match.confidence,
        action: 'redact',
      });
      redactedContent = redactToken(redactedContent, match.secretValue, match.type);
    }
  }

  const blocked = findings.filter((f) => f.action === 'block').length;
  const warned = findings.filter((f) => f.action === 'warn').length;
  const redactedCount = findings.filter((f) => f.action === 'redact').length;

  return {
    hasFindings: findings.length > 0,
    isBlocked: blocked > 0,
    findings,
    redactedContent,
    summary: {
      total: findings.length,
      blocked,
      warned,
      redacted: redactedCount,
    },
  };
}

export { loadConfig, mergeConfig, isAllowlisted, maskSecretPreview, redactToken, redactAllMatches };
export { PatternDetector, BUILTIN_PATTERNS } from './detectors/pattern.js';
export { EntropyDetector, calculateShannonEntropy } from './detectors/entropy.js';
export { LeakGuardConfig, ScanOptions, ScanResult, Finding, ResponseMode, Confidence } from './types.js';
