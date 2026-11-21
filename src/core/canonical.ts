import { Buffer } from 'node:buffer';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import { err, ok, type Result } from '../types/result.js';

const FNV_OFFSET_BASIS_64 = 0xcbf29ce484222325n;
const FNV_PRIME_64 = 0x100000001b3n;

/**
 * Deterministic RFC-8785 (JCS) canonical JSON serializer.
 * Guarantees identical byte representations regardless of object key insertion order,
 * rejects non-finite numbers and cyclic references, and normalizes -0 to 0.
 */
export function canonicalizeJson(value: unknown, maxDepth = 48): Result<string, SentinelError> {
  const seen = new WeakSet<object>();

  function serialize(current: unknown, depth: number): Result<string, SentinelError> {
    if (depth > maxDepth) {
      return err(
        createSentinelError(
          'INVALID_PARAMS',
          `Canonicalization exceeded maximum nesting depth of ${maxDepth}`,
          'canonicalizeJson',
        ),
      );
    }

    if (current === null) {
      return ok('null');
    }

    const kind = typeof current;
    if (kind === 'boolean') {
      return ok(current ? 'true' : 'false');
    }

    if (kind === 'number') {
      const num = current as number;
      if (!Number.isFinite(num)) {
        return err(
          createSentinelError(
            'INVALID_PARAMS',
            'Non-finite numbers (NaN/Infinity) are forbidden in canonical JSON',
            'canonicalizeJson',
          ),
        );
      }
      return ok(Object.is(num, -0) ? '0' : JSON.stringify(num));
    }

    if (kind === 'string') {
      return ok(JSON.stringify(current));
    }

    if (kind !== 'object') {
      return err(
        createSentinelError(
          'INVALID_PARAMS',
          `Unsupported value type "${kind}" in canonical JSON`,
          'canonicalizeJson',
        ),
      );
    }

    const obj = current as object;
    if (seen.has(obj)) {
      return err(
        createSentinelError(
          'INVALID_PARAMS',
          'Circular reference detected during canonical JSON serialization',
          'canonicalizeJson',
        ),
      );
    }

    seen.add(obj);

    if (Array.isArray(obj)) {
      const parts: string[] = [];
      for (const element of obj) {
        const serializedElement = serialize(element === undefined ? null : element, depth + 1);
        if (!serializedElement.ok) {
          seen.delete(obj);
          return serializedElement;
        }
        parts.push(serializedElement.value);
      }
      seen.delete(obj);
      return ok(`[${parts.join(',')}]`);
    }

    const record = obj as Record<string, unknown>;
    const sortedKeys = Object.keys(record).sort();
    const pairs: string[] = [];

    for (const key of sortedKeys) {
      const propValue = record[key];
      if (propValue === undefined) {
        continue;
      }
      const serializedVal = serialize(propValue, depth + 1);
      if (!serializedVal.ok) {
        seen.delete(obj);
        return serializedVal;
      }
      pairs.push(`${JSON.stringify(key)}:${serializedVal.value}`);
    }

    seen.delete(obj);
    return ok(`{${pairs.join(',')}}`);
  }

  return serialize(value, 0);
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export function sha256Bytes(data: string | Uint8Array): Buffer {
  return createHash('sha256').update(data).digest();
}

export function hmacSha256Hex(key: string | Uint8Array, data: string | Uint8Array): string {
  return createHmac('sha256', key).update(data).digest('hex');
}

export function hmacSha256Bytes(key: string | Uint8Array, data: string | Uint8Array): Buffer {
  return createHmac('sha256', key).update(data).digest();
}

export function canonicalHashHex(value: unknown): Result<string, SentinelError> {
  const canonical = canonicalizeJson(value);
  if (!canonical.ok) {
    return canonical;
  }
  return ok(sha256Hex(canonical.value));
}

export function constantTimeEqualHex(hexA: string, hexB: string): boolean {
  if (hexA.length === 0 || hexA.length !== hexB.length || hexA.length % 2 !== 0) {
    return false;
  }
  if (!/^[0-9a-fA-F]+$/.test(hexA) || !/^[0-9a-fA-F]+$/.test(hexB)) {
    return false;
  }
  const bufA = Buffer.from(hexA, 'hex');
  const bufB = Buffer.from(hexB, 'hex');
  if (bufA.byteLength !== bufB.byteLength) {
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

export function fnv1a64(input: string): bigint {
  let hash = FNV_OFFSET_BASIS_64;
  const bytes = Buffer.from(input, 'utf8');
  for (const byte of bytes) {
    hash ^= BigInt(byte);
    hash = BigInt.asUintN(64, hash * FNV_PRIME_64);
  }
  return hash;
}
