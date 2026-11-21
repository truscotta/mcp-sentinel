import { hmacSha256Bytes, hmacSha256Hex } from '../core/canonical.js';
import {
  computeLuhnCheckDigit,
  SYNTHETIC_CARD_PREFIX,
  SYNTHETIC_EMAIL_DOMAIN,
  SYNTHETIC_SECRET_PREFIX,
  SYNTHETIC_SSN_PREFIX,
  type SensitiveEntityKind,
} from './luhn-and-entropy.js';

const DANGLING_ALIAS_REGEX =
  /\bsyn_[0-9a-f]{10}@sentinel\.vault\b|\bsyn_sec_[0-9a-f]{20}\b|\b4000009\d{9}\b|\b900-\d{2}-\d{4}\b|\+1[2-9]\d{2}55501\d{2}\b/gi;

function deriveNumericDigits(seedBytes: Uint8Array, length: number): string {
  let digits = '';
  let idx = 0;
  while (digits.length < length) {
    const byteVal = seedBytes[idx % seedBytes.length] ?? 0;
    digits += String((byteVal + idx * 7) % 10);
    idx += 1;
  }
  return digits.slice(0, length);
}

/**
 * Generates deterministic, collision-safe, format-preserving synthetic aliases
 * within a session so LLMs can reason over structured emails, Luhn-valid cards,
 * SSNs, E.164 phones, and opaque tokens without ever seeing raw plaintext PII.
 */
export function generateFormatPreservingAlias(params: {
  readonly hmacSecret: Uint8Array | string;
  readonly tenantId: string;
  readonly sessionId: string;
  readonly kind: SensitiveEntityKind;
  readonly rawPlaintext: string;
  readonly collisionAttempt?: number;
}): string {
  const attempt = params.collisionAttempt ?? 0;
  const domainInput = `alias:v1:${params.tenantId}:${params.sessionId}:${params.kind}:${attempt}:${params.rawPlaintext}`;

  switch (params.kind) {
    case 'EMAIL': {
      const digest = hmacSha256Hex(params.hmacSecret, domainInput).slice(0, 10);
      return `syn_${digest}${SYNTHETIC_EMAIL_DOMAIN}`;
    }

    case 'CREDIT_CARD': {
      // 7-digit non-routable test prefix '4000009' + 8 HMAC-derived digits + 1 Luhn check digit = 16-digit Luhn-valid card
      const bytes = hmacSha256Bytes(params.hmacSecret, domainInput);
      const body8 = deriveNumericDigits(bytes, 8);
      const payload15 = `${SYNTHETIC_CARD_PREFIX}${body8}`;
      const checkDigit = computeLuhnCheckDigit(payload15);
      return `${payload15}${checkDigit}`;
    }

    case 'SSN': {
      // '900-' prefix is permanently unassigned by SSA, guaranteeing zero real-world collision
      const bytes = hmacSha256Bytes(params.hmacSecret, domainInput);
      const sixDigits = deriveNumericDigits(bytes, 6);
      const group2 = sixDigits.slice(0, 2);
      let serial4 = sixDigits.slice(2, 6);
      if (serial4 === '0000') {
        serial4 = '0001';
      }
      return `${SYNTHETIC_SSN_PREFIX}${group2}-${serial4}`;
    }

    case 'PHONE': {
      // NANPA fictional range: +1 + [200..999] + 55501 + [00..99] (80,000 valid E.164 fictional numbers)
      const bytes = hmacSha256Bytes(params.hmacSecret, domainInput);
      const b0 = bytes[0] ?? 0;
      const b1 = bytes[1] ?? 0;
      const b2 = bytes[2] ?? 0;
      const areaCode = 200 + (((b0 << 8) | b1) % 800);
      const lineSuffix = String(b2 % 100).padStart(2, '0');
      return `+1${areaCode}55501${lineSuffix}`;
    }

    case 'API_KEY':
    case 'HIGH_ENTROPY_SECRET':
    case 'CUSTOM': {
      const hex20 = hmacSha256Hex(params.hmacSecret, domainInput).slice(0, 20);
      return `${SYNTHETIC_SECRET_PREFIX}${hex20}`;
    }
  }
}

/**
 * Extracts all synthetic alias tokens matching Sentinel's reserved namespaces
 * from an arbitrary outbound string.
 */
export function extractSyntheticAliasesFromText(text: string): readonly string[] {
  if (text.length === 0) {
    return [];
  }
  const found = new Set<string>();
  const re = new RegExp(DANGLING_ALIAS_REGEX.source, 'gi');
  let m = re.exec(text);
  while (m !== null) {
    found.add(m[0]);
    m = re.exec(text);
  }
  return Array.from(found);
}
