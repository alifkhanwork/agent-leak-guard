/**
 * Redaction & Masking Utilities — "Never leak the leak"
 * Ensures secrets are safely masked before exposure in logs, previews, or CLI outputs.
 */

/**
 * Creates a safe preview of a secret without exposing the core value.
 * e.g., "AKIAIOSFODNN7EXAMPLE" -> "AKIA****MPLE"
 * Short secrets (< 8 chars) -> "****"
 */
export function maskSecretPreview(secret: string): string {
  if (!secret) return '[REDACTED]';
  const len = secret.length;
  if (len <= 8) {
    return '****';
  }
  const prefixLen = Math.min(4, Math.floor(len / 4));
  const suffixLen = Math.min(4, Math.floor(len / 4));
  const prefix = secret.slice(0, prefixLen);
  const suffix = secret.slice(len - suffixLen);
  return `${prefix}****${suffix}`;
}

/**
 * Redacts a secret token inside a content string with a descriptive placeholder.
 * e.g., "api_key = AKIAIOSFODNN7EXAMPLE" -> "api_key = [REDACTED:aws_access_key]"
 */
export function redactToken(content: string, secretValue: string, secretType: string): string {
  if (!content || !secretValue) return content;
  const placeholder = `[REDACTED:${secretType}]`;
  // Escape special regex characters in secretValue
  const escaped = secretValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return content.replace(new RegExp(escaped, 'g'), placeholder);
}

/**
 * Redacts all matched internal secrets from a text string.
 */
export function redactAllMatches(
  content: string,
  matches: Array<{ secretValue: string; type: string }>
): string {
  let result = content;
  // Sort by longest secret length first to prevent partial redactions
  const sorted = [...matches].sort((a, b) => b.secretValue.length - a.secretValue.length);

  for (const m of sorted) {
    result = redactToken(result, m.secretValue, m.type);
  }
  return result;
}
