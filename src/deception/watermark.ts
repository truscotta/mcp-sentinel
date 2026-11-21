import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { constantTimeEqualHex, hmacSha256Hex } from '../core/canonical.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import { isJsonObject, type JsonValue } from '../types/jsonrpc.js';
import type { DeceptionConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';

const DYNAMIC_CANARY_REGEX = /CANARY-MS1-([0-9a-f]{8})-([0-9a-f]{16})/gi;
const BASE64_CHUNK_REGEX = /[A-Za-z0-9+/_-]{20,512}={0,2}/g;

export interface CanaryDetectionMatch {
  readonly kind: 'STATIC_CANARY' | 'DYNAMIC_WATERMARK';
  readonly encoding: 'RAW' | 'URL_DECODED' | 'BASE64_DECODED';
  readonly matchedTokenPreview: string;
}

/**
 * Cryptographic Canary Honeytoken & Epistemic Watermark detector.
 * Inspects outbound tool call arguments across raw text, URL-encoded payloads,
 * and Base64-encoded chunks so prompt-injected agents cannot obfuscate stolen
 * canary secrets before exfiltrating them.
 */
export class EpistemicWatermarkEngine {
  private readonly config: DeceptionConfig;
  private readonly hmacSecret: string;
  private readonly staticCanaries: readonly string[];

  public constructor(config: DeceptionConfig, hmacSecret?: string) {
    this.config = config;
    this.hmacSecret = hmacSecret ?? randomBytes(32).toString('hex');
    this.staticCanaries = config.canaryTokens
      .map((token) => token.trim())
      .filter((token) => token.length >= 8);
  }

  /**
   * Mints a cryptographically verifiable session-bound canary watermark.
   */
  public mintSessionCanary(tenantId: string, sessionId: string): string {
    const sessionTag = hmacSha256Hex(this.hmacSecret, `${tenantId}:${sessionId}`).slice(0, 8);
    const mac16 = hmacSha256Hex(this.hmacSecret, `ms1:${sessionTag}`).slice(0, 16);
    return `CANARY-MS1-${sessionTag}-${mac16}`;
  }

  public verifyDynamicCanary(sessionTag: string, providedMac16: string): boolean {
    const normalizedTag = sessionTag.toLowerCase();
    const normalizedMac = providedMac16.toLowerCase();
    const expectedMac16 = hmacSha256Hex(this.hmacSecret, `ms1:${normalizedTag}`).slice(0, 16);
    return constantTimeEqualHex(expectedMac16, normalizedMac);
  }

  private inspectSingleString(
    candidate: string,
    encoding: CanaryDetectionMatch['encoding'],
  ): CanaryDetectionMatch | null {
    for (const canary of this.staticCanaries) {
      if (candidate.includes(canary)) {
        return {
          kind: 'STATIC_CANARY',
          encoding,
          matchedTokenPreview: `${canary.slice(0, 10)}...`,
        };
      }
    }

    DYNAMIC_CANARY_REGEX.lastIndex = 0;
    let match = DYNAMIC_CANARY_REGEX.exec(candidate);
    while (match !== null) {
      const tag = match[1];
      const mac = match[2];
      if (tag !== undefined && mac !== undefined && this.verifyDynamicCanary(tag, mac)) {
        return {
          kind: 'DYNAMIC_WATERMARK',
          encoding,
          matchedTokenPreview: `CANARY-MS1-${tag}-...`,
        };
      }
      match = DYNAMIC_CANARY_REGEX.exec(candidate);
    }

    return null;
  }

  private scanStringMultiLayer(rawText: string): CanaryDetectionMatch | null {
    const directHit = this.inspectSingleString(rawText, 'RAW');
    if (directHit !== null) {
      return directHit;
    }

    // Layer 2: URL-decoded evasion check
    if (rawText.includes('%')) {
      try {
        const urlDecoded = decodeURIComponent(rawText);
        if (urlDecoded !== rawText) {
          const urlHit = this.inspectSingleString(urlDecoded, 'URL_DECODED');
          if (urlHit !== null) {
            return urlHit;
          }
        }
      } catch {
        // Ignore malformed percent-sequences in benign text
      }
    }

    // Layer 3: Base64 / Base64url evasion check
    BASE64_CHUNK_REGEX.lastIndex = 0;
    let b64Match = BASE64_CHUNK_REGEX.exec(rawText);
    while (b64Match !== null) {
      const chunk = b64Match[0];
      if (chunk !== undefined) {
        try {
          const normalized = chunk.replace(/-/g, '+').replace(/_/g, '/');
          const decodedUtf8 = Buffer.from(normalized, 'base64').toString('utf8');
          if (decodedUtf8.length >= 8) {
            const b64Hit = this.inspectSingleString(decodedUtf8, 'BASE64_DECODED');
            if (b64Hit !== null) {
              return b64Hit;
            }
          }
        } catch {
          // Ignore non-Base64 substrings
        }
      }
      b64Match = BASE64_CHUNK_REGEX.exec(rawText);
    }

    return null;
  }

  /**
   * Recursively inspects an outbound `JsonValue` payload for leaked static
   * canary tokens or HMAC-verified session watermarks.
   */
  public assertNoCanaryExfiltration(payload: JsonValue): Result<void, SentinelError> {
    if (!this.config.enabled) {
      return ok(undefined);
    }

    const walk = (node: JsonValue, depth: number): CanaryDetectionMatch | null => {
      if (depth > 32 || node === null || typeof node === 'number' || typeof node === 'boolean') {
        return null;
      }

      if (typeof node === 'string') {
        return this.scanStringMultiLayer(node);
      }

      if (Array.isArray(node)) {
        for (const item of node) {
          const hit = walk(item, depth + 1);
          if (hit !== null) {
            return hit;
          }
        }
        return null;
      }

      if (isJsonObject(node)) {
        for (const [key, val] of Object.entries(node)) {
          const keyHit = this.scanStringMultiLayer(key);
          if (keyHit !== null) {
            return keyHit;
          }
          if (val !== undefined) {
            const valHit = walk(val, depth + 1);
            if (valHit !== null) {
              return valHit;
            }
          }
        }
      }

      return null;
    };

    const detected = walk(payload, 0);
    if (detected !== null) {
      return err(
        createSentinelError(
          'DECEPTION_TRIPPED',
          `Canary tripwire triggered (${detected.kind} via ${detected.encoding}): outbound exfiltration blocked`,
          'epistemic-watermark',
          {
            detectionKind: detected.kind,
            encoding: detected.encoding,
            tokenPreview: detected.matchedTokenPreview,
          },
        ),
      );
    }

    return ok(undefined);
  }
}
