export type ResponseMode = 'warn' | 'block' | 'redact';

export type Confidence = 'low' | 'medium' | 'high';

export interface Location {
  start: number;
  end: number;
  line?: number;
  column?: number;
}

export interface Finding {
  type: string;
  ruleId: string;
  description: string;
  rawMatch: string; // ALWAYS masked / redacted preview string (never full raw secret!)
  location: Location;
  confidence: Confidence;
  action: ResponseMode;
}

export interface RuleConfig {
  enabled?: boolean;
  mode?: ResponseMode;
  confidenceThreshold?: Confidence;
  options?: Record<string, unknown>;
}

export interface LeakGuardConfig {
  defaultMode: ResponseMode;
  entropyThreshold: number;
  entropyMinLength: number;
  allowlist: {
    strings: string[];
    regexes: string[];
    files: string[];
  };
  rules: Record<string, RuleConfig>;
}

export interface ScanOptions {
  mode?: ResponseMode;
  filePath?: string;
  configPath?: string;
  allowlist?: string[];
  rules?: Record<string, RuleConfig>;
  entropyThreshold?: number;
}

export interface ScanResult {
  hasFindings: boolean;
  isBlocked: boolean;
  findings: Finding[];
  redactedContent: string;
  summary: {
    total: number;
    blocked: number;
    warned: number;
    redacted: number;
  };
}

export interface InternalMatch {
  ruleId: string;
  type: string;
  description: string;
  secretValue: string;
  start: number;
  end: number;
  confidence: Confidence;
}
