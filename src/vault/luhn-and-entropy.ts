import { compileSafeRegex } from '../dsl/analyzer.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import type { ConfidentialityLevel } from '../types/lattice.js';
import type { VaultConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';

export type SensitiveEntityKind =
  | 'API_KEY'
  | 'CREDIT_CARD'
  | 'SSN'
  | 'EMAIL'
  | 'PHONE'
  | 'HIGH_ENTROPY_SECRET'
  | 'CUSTOM';

export interface SensitiveSpanMatch {
  readonly kind: SensitiveEntityKind;
  readonly ruleName: string;
  readonly value: string;
  readonly start: number;
  readonly end: number;
  readonly confidentiality: ConfidentialityLevel;
}

export interface CompiledCustomVaultPattern {
  readonly name: string;
  readonly regex: RegExp;
}

export const SYNTHETIC_EMAIL_DOMAIN = '@sentinel.vault';
export const SYNTHETIC_SECRET_PREFIX = 'syn_sec_';
export const SYNTHETIC_CARD_PREFIX = '4000009';
export const SYNTHETIC_SSN_PREFIX = '900-';

const SYNTHETIC_PHONE_EXACT_REGEX = /^\+1[2-9]\d{2}55501\d{2}$/;
const UUID_V4_EXACT_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const API_KEY_PATTERNS: readonly { readonly name: string; readonly regex: RegExp }[] = [
  { name: 'openai_api_key', regex: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,180}\b/g },
  { name: 'anthropic_api_key', regex: /\bsk-ant-api03-[A-Za-z0-9_-]{24,140}\b/g },
  { name: 'aws_access_key_id', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'github_pat', regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,120}\b/g },
  { name: 'github_fine_grained_pat', regex: /\bgithub_pat_[A-Za-z0-9_]{40,140}\b/g },
  { name: 'stripe_secret_key', regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,120}\b/g },
  { name: 'slack_token', regex: /\bxox[baprs]-[0-9A-Za-z-]{20,140}\b/g },
  {
    name: 'jwt_bearer_token',
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b/g,
  },
  {
    name: 'pem_private_key',
    regex:
      /-----BEGIN (?:RSA |EC |OPENSSH |PRIVATE )?PRIVATE KEY-----[\s\S]{32,4096}?-----END (?:RSA |EC |OPENSSH |PRIVATE )?PRIVATE KEY-----/g,
  },
];

const EMAIL_SCAN_REGEX = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}\b/g;
const SSN_SCAN_REGEX = /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
const CREDIT_CARD_CANDIDATE_REGEX = /\b(?:\d[ -]*?){13,19}\b/g;
const PHONE_SCAN_REGEX = /(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b|\+[1-9]\d{9,14}\b/g;
const TOKEN_CANDIDATE_REGEX = /[^\s"'`,;:=<>()[\]{}]+/g;

const KIND_PRIORITY: Readonly<Record<SensitiveEntityKind, number>> = {
  API_KEY: 70,
  CREDIT_CARD: 65,
  SSN: 60,
  CUSTOM: 55,
  EMAIL: 50,
  PHONE: 40,
  HIGH_ENTROPY_SECRET: 20,
};

const KIND_CONFIDENTIALITY: Readonly<Record<SensitiveEntityKind, ConfidentialityLevel>> = {
  API_KEY: 'SECRET',
  CREDIT_CARD: 'SECRET',
  SSN: 'SECRET',
  CUSTOM: 'CONFIDENTIAL',
  HIGH_ENTROPY_SECRET: 'SECRET',
  EMAIL: 'CONFIDENTIAL',
  PHONE: 'CONFIDENTIAL',
};

/**
 * Computes the single ISO/IEC 7812-1 Luhn check digit (0..9) to append to
 * a numeric payload string so that `${payloadDigits}${checkDigit}` is Luhn-valid.
 */
export function computeLuhnCheckDigit(payloadDigits: string): number {
  let sum = 0;
  let shouldDouble = true;

  for (let i = payloadDigits.length - 1; i >= 0; i -= 1) {
    const code = payloadDigits.charCodeAt(i) - 48;
    if (code < 0 || code > 9) {
      throw new RangeError('payloadDigits must contain only ASCII digits 0-9');
    }
    let addend = code;
    if (shouldDouble) {
      addend *= 2;
      if (addend > 9) {
        addend -= 9;
      }
    }
    sum += addend;
    shouldDouble = !shouldDouble;
  }

  return (10 - (sum % 10)) % 10;
}

/**
 * Validates payment card candidates using the Luhn mod-10 algorithm while
 * rejecting trivial all-identical digit sequences.
 */
export function passesLuhnCheck(rawCandidate: string): boolean {
  const digits = rawCandidate.replace(/[ -]/g, '');
  if (digits.length < 13 || digits.length > 19 || !/^\d+$/.test(digits)) {
    return false;
  }

  const firstChar = digits[0];
  if (firstChar !== undefined && digits.split('').every((ch) => ch === firstChar)) {
    return false;
  }

  const payload = digits.slice(0, -1);
  const actualCheckDigit = digits.charCodeAt(digits.length - 1) - 48;
  return computeLuhnCheckDigit(payload) === actualCheckDigit;
}

/**
 * Calculates Shannon information entropy H(X) = -sum(p_i * log2(p_i)) in bits/symbol.
 */
export function shannonEntropyBits(input: string): number {
  if (input.length === 0) {
    return 0;
  }
  const frequencies = new Map<string, number>();
  for (const ch of input) {
    frequencies.set(ch, (frequencies.get(ch) ?? 0) + 1);
  }
  const total = input.length;
  let entropy = 0;
  for (const count of frequencies.values()) {
    const p = count / total;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Filters out benign high-entropy strings (standard UUIDs, URLs, file system paths)
 * and requires multi-class character diversity typical of cryptographic secrets.
 */
export function isLikelyUnstructuredSecret(
  token: string,
  minLength: number,
  entropyThresholdBits: number,
): boolean {
  if (token.length < minLength || token.length > 512) {
    return false;
  }
  if (isSyntheticVaultToken(token)) {
    return false;
  }
  if (UUID_V4_EXACT_REGEX.test(token)) {
    return false;
  }
  if (
    token.startsWith('http://') ||
    token.startsWith('https://') ||
    token.startsWith('/') ||
    token.startsWith('./') ||
    token.startsWith('../') ||
    (token.includes('/') && !token.endsWith('='))
  ) {
    return false;
  }

  let hasLower = false;
  let hasUpper = false;
  let hasDigit = false;
  let hasSymbol = false;

  for (let i = 0; i < token.length; i += 1) {
    const c = token.charCodeAt(i);
    if (c >= 97 && c <= 122) hasLower = true;
    else if (c >= 65 && c <= 90) hasUpper = true;
    else if (c >= 48 && c <= 57) hasDigit = true;
    else hasSymbol = true;
  }

  const classCount =
    (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);

  // Require either >=3 character classes (base64/mixed secret) or hex-like with digits+letters
  const isHexSecret = token.length >= 32 && /^[0-9a-fA-F]+$/.test(token) && hasDigit && (hasLower || hasUpper);
  if (classCount < 3 && !isHexSecret) {
    return false;
  }

  return shannonEntropyBits(token) >= entropyThresholdBits;
}

export function isSyntheticVaultToken(value: string): boolean {
  const lower = value.toLowerCase();
  if (lower.endsWith(SYNTHETIC_EMAIL_DOMAIN) && lower.startsWith('syn_')) {
    return true;
  }
  if (value.startsWith(SYNTHETIC_SECRET_PREFIX)) {
    return true;
  }
  const compactDigits = value.replace(/[ -]/g, '');
  if (compactDigits.length === 16 && compactDigits.startsWith(SYNTHETIC_CARD_PREFIX)) {
    return true;
  }
  if (value.startsWith(SYNTHETIC_SSN_PREFIX) && /^900-\d{2}-\d{4}$/.test(value)) {
    return true;
  }
  if (SYNTHETIC_PHONE_EXACT_REGEX.test(value)) {
    return true;
  }
  return false;
}

export function compileCustomVaultPatterns(
  customPatterns?: Readonly<Record<string, string>>,
): Result<readonly CompiledCustomVaultPattern[], SentinelError> {
  if (customPatterns === undefined) {
    return ok([]);
  }
  const compiled: CompiledCustomVaultPattern[] = [];
  for (const [name, rawPattern] of Object.entries(customPatterns)) {
    const safeRes = compileSafeRegex(rawPattern);
    if (!safeRes.ok) {
      return err(
        createSentinelError(
          'POLICY_VIOLATION',
          `Invalid custom vault pattern "${name}": ${safeRes.error.message}`,
          'vault-scanner',
        ),
      );
    }
    const flags = safeRes.value.flags.includes('g')
      ? safeRes.value.flags
      : `${safeRes.value.flags}g`;
    compiled.push({
      name,
      regex: new RegExp(safeRes.value.source, flags),
    });
  }
  return ok(compiled);
}

/**
 * Scans a string for API keys, Luhn-verified payment cards, SSNs, emails,
 * phone numbers, custom enterprise patterns, and high-entropy secrets,
 * returning non-overlapping spans sorted by `start` index.
 */
export function scanSensitiveSpans(
  text: string,
  config: VaultConfig,
  customPatterns: readonly CompiledCustomVaultPattern[] = [],
): readonly SensitiveSpanMatch[] {
  if (!config.enabled || text.length === 0) {
    return [];
  }

  const candidates: SensitiveSpanMatch[] = [];

  const pushCandidate = (
    kind: SensitiveEntityKind,
    ruleName: string,
    value: string,
    start: number,
  ): void => {
    if (candidates.length >= 256 || value.length === 0 || isSyntheticVaultToken(value)) {
      return;
    }
    candidates.push({
      kind,
      ruleName,
      value,
      start,
      end: start + value.length,
      confidentiality: KIND_CONFIDENTIALITY[kind],
    });
  };

  if (config.detectApiKeys) {
    for (const entry of API_KEY_PATTERNS) {
      const re = new RegExp(entry.regex.source, entry.regex.flags);
      let m = re.exec(text);
      while (m !== null) {
        pushCandidate('API_KEY', entry.name, m[0], m.index);
        m = re.exec(text);
      }
    }
  }

  if (config.detectCreditCard) {
    const re = new RegExp(CREDIT_CARD_CANDIDATE_REGEX.source, 'g');
    let m = re.exec(text);
    while (m !== null) {
      const rawCard = m[0].trim();
      const leadOffset = m[0].indexOf(rawCard);
      if (passesLuhnCheck(rawCard)) {
        pushCandidate('CREDIT_CARD', 'luhn_payment_card', rawCard, m.index + leadOffset);
      }
      m = re.exec(text);
    }
  }

  if (config.detectSsn) {
    const re = new RegExp(SSN_SCAN_REGEX.source, 'g');
    let m = re.exec(text);
    while (m !== null) {
      pushCandidate('SSN', 'us_ssn', m[0], m.index);
      m = re.exec(text);
    }
  }

  for (const custom of customPatterns) {
    const re = new RegExp(custom.regex.source, custom.regex.flags);
    let m = re.exec(text);
    while (m !== null) {
      if (m[0].length === 0) {
        re.lastIndex += 1;
      } else {
        pushCandidate('CUSTOM', custom.name, m[0], m.index);
      }
      m = re.exec(text);
    }
  }

  if (config.detectEmail) {
    const re = new RegExp(EMAIL_SCAN_REGEX.source, 'g');
    let m = re.exec(text);
    while (m !== null) {
      pushCandidate('EMAIL', 'email_address', m[0], m.index);
      m = re.exec(text);
    }
  }

  if (config.detectPhone) {
    const re = new RegExp(PHONE_SCAN_REGEX.source, 'g');
    let m = re.exec(text);
    while (m !== null) {
      pushCandidate('PHONE', 'phone_number', m[0], m.index);
      m = re.exec(text);
    }
  }

  // High-entropy token scan for proprietary secrets unknown to static regexes
  const tokRegex = new RegExp(TOKEN_CANDIDATE_REGEX.source, 'g');
  let tokMatch = tokRegex.exec(text);
  while (tokMatch !== null) {
    const token = tokMatch[0];
    if (isLikelyUnstructuredSecret(token, config.minSecretLength, config.entropyThresholdBits)) {
      pushCandidate('HIGH_ENTROPY_SECRET', 'shannon_entropy', token, tokMatch.index);
    }
    tokMatch = tokRegex.exec(text);
  }

  if (candidates.length <= 1) {
    return candidates;
  }

  // Resolve overlaps deterministically: highest semantic priority, then longest span, then earliest start
  candidates.sort((a, b) => {
    const prioDiff = KIND_PRIORITY[b.kind] - KIND_PRIORITY[a.kind];
    if (prioDiff !== 0) return prioDiff;
    const lenDiff = b.end - b.start - (a.end - a.start);
    if (lenDiff !== 0) return lenDiff;
    return a.start - b.start;
  });

  const accepted: SensitiveSpanMatch[] = [];
  for (const candidate of candidates) {
    const overlapsExisting = accepted.some(
      (sel) => candidate.start < sel.end && sel.start < candidate.end,
    );
    if (!overlapsExisting) {
      accepted.push(candidate);
    }
  }

  accepted.sort((a, b) => a.start - b.start);
  return accepted;
}
