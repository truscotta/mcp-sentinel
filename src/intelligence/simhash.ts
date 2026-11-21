import { canonicalHashHex, fnv1a64 } from '../core/canonical.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import { isJsonObject, type JsonObject, type JsonValue } from '../types/jsonrpc.js';
import type { IntelligenceConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';

export type LoopDetectionTier =
  | 'EXACT_CANONICAL_STREAK'
  | 'PERIODIC_CYCLE'
  | 'SIMHASH_NEAR_DUPLICATE'
  | 'ERROR_RETRY_SPIRAL';

export interface SimHashCallVerdict {
  readonly canonicalDigestHex: string;
  readonly simhash64Hex: string;
  readonly nearestHammingDistance: number | null;
  readonly windowCallCount: number;
}

interface WeightedFeature {
  readonly token: string;
  readonly weight: number;
}

interface CallHistoryEntry {
  readonly toolName: string;
  readonly canonicalDigestHex: string;
  readonly simhash: bigint;
  failed: boolean;
}

function extractStringShingles(path: string, text: string, out: WeightedFeature[]): void {
  const normalized = text.trim().toLowerCase().replace(/\s+/g, ' ');
  if (normalized.length === 0) {
    out.push({ token: `${path}=<empty>`, weight: 2 });
    return;
  }

  const words = normalized.split(' ');
  if (words.length <= 2) {
    out.push({ token: `${path}=${normalized.slice(0, 128)}`, weight: 3 });
  } else {
    for (let i = 0; i < words.length - 1 && i < 64; i += 1) {
      const w1 = words[i] ?? '';
      const w2 = words[i + 1] ?? '';
      out.push({ token: `${path}:w2:${w1}_${w2}`, weight: 2 });
    }
  }

  // Character 4-grams capture subtle token mutations (e.g. changing limit=10 to limit=11)
  const compact = normalized.slice(0, 160);
  if (compact.length >= 4) {
    for (let i = 0; i <= compact.length - 4; i += 2) {
      out.push({ token: `${path}:c4:${compact.slice(i, i + 4)}`, weight: 1 });
    }
  }
}

function collectStructuralFeatures(
  node: JsonValue,
  path: string,
  depth: number,
  out: WeightedFeature[],
): void {
  if (depth > 16 || out.length > 512) {
    return;
  }

  if (node === null) {
    out.push({ token: `${path}=null`, weight: 2 });
    return;
  }

  if (typeof node === 'boolean') {
    out.push({ token: `${path}=bool:${String(node)}`, weight: 3 });
    return;
  }

  if (typeof node === 'number') {
    // Bucket magnitude alongside exact value so small numeric jitter stays close in Hamming space
    const magnitudeBucket = node === 0 ? 0 : Math.floor(Math.log10(Math.abs(node)));
    out.push({ token: `${path}=num_mag:${magnitudeBucket}`, weight: 2 });
    out.push({ token: `${path}=num_val:${node}`, weight: 1 });
    return;
  }

  if (typeof node === 'string') {
    extractStringShingles(path, node, out);
    return;
  }

  if (Array.isArray(node)) {
    out.push({ token: `${path}#len:${Math.min(node.length, 32)}`, weight: 2 });
    const limit = Math.min(node.length, 16);
    for (let i = 0; i < limit; i += 1) {
      const item = node[i];
      if (item !== undefined) {
        collectStructuralFeatures(item, `${path}[${i}]`, depth + 1, out);
      }
    }
    return;
  }

  if (isJsonObject(node)) {
    const sortedKeys = Object.keys(node).sort();
    for (const key of sortedKeys) {
      out.push({ token: `key:${path}.${key}`, weight: 4 });
      const val = node[key];
      if (val !== undefined) {
        collectStructuralFeatures(val, `${path}.${key}`, depth + 1, out);
      }
    }
  }
}

/**
 * Computes Charikar's 64-bit locality-sensitive SimHash over a tool invocation's
 * name and structured JSON arguments.
 */
export function computeInvocationSimHash64(toolName: string, args: JsonObject): bigint {
  const features: WeightedFeature[] = [{ token: `tool:${toolName}`, weight: 8 }];
  collectStructuralFeatures(args, 'args', 0, features);

  const bitAccumulator = new Int32Array(64);

  for (const feature of features) {
    const hash64 = fnv1a64(feature.token);
    for (let bit = 0; bit < 64; bit += 1) {
      const isSet = ((hash64 >> BigInt(bit)) & 1n) === 1n;
      const current = bitAccumulator[bit] ?? 0;
      bitAccumulator[bit] = isSet ? current + feature.weight : current - feature.weight;
    }
  }

  let fingerprint = 0n;
  for (let bit = 0; bit < 64; bit += 1) {
    if ((bitAccumulator[bit] ?? 0) > 0) {
      fingerprint |= 1n << BigInt(bit);
    }
  }

  return BigInt.asUintN(64, fingerprint);
}

/**
 * Computes bitwise Hamming distance between two unsigned 64-bit integers in O(popcount) <= 64 ops
 * using Brian Kernighan's bit-clearing identity.
 */
export function hammingDistance64(a: bigint, b: bigint): number {
  let xor = BigInt.asUintN(64, a ^ b);
  let distance = 0;
  while (xor !== 0n) {
    xor &= xor - 1n;
    distance += 1;
  }
  return distance;
}

export function formatSimHashHex(hash: bigint): string {
  return BigInt.asUintN(64, hash).toString(16).padStart(16, '0');
}

function detectPeriodicSuffixCycle(
  history: readonly CallHistoryEntry[],
  candidateDigest: string,
): number | null {
  const seq = [...history.map((h) => h.canonicalDigestHex), candidateDigest];
  // Check period p = 2 (A-B-A-B-A-B, 3 full repetitions = 6 items) and p = 3 (A-B-C x 3 = 9 items)
  for (const period of [2, 3]) {
    const requiredLen = period * 3;
    if (seq.length < requiredLen) {
      continue;
    }
    const tail = seq.slice(seq.length - requiredLen);
    // Ensure elements within a single period aren't all identical (handled by streak check)
    const uniqueInPeriod = new Set(tail.slice(0, period));
    if (uniqueInPeriod.size < 2) {
      continue;
    }

    let isPeriodic = true;
    for (let i = period; i < requiredLen; i += 1) {
      if (tail[i] !== tail[i % period]) {
        isPeriodic = false;
        break;
      }
    }
    if (isPeriodic) {
      return period;
    }
  }
  return null;
}

/**
 * 3-Tier Cognitive Loop & Error-Retry Spiral Detector powered by canonical SHA-256,
 * periodic N-gram cycle matching, and 64-bit SimHash Hamming proximity.
 */
export class SimHashLoopDetector {
  private readonly config: IntelligenceConfig;
  private readonly sessions = new Map<string, CallHistoryEntry[]>();
  private readonly maxSessions: number;

  public constructor(config: IntelligenceConfig, maxSessions = 2_048) {
    this.config = config;
    this.maxSessions = maxSessions;
  }

  private getOrCreateWindow(sessionId: string): CallHistoryEntry[] {
    const existing = this.sessions.get(sessionId);
    if (existing !== undefined) {
      this.sessions.delete(sessionId);
      this.sessions.set(sessionId, existing);
      return existing;
    }

    if (this.sessions.size >= this.maxSessions) {
      const oldest = this.sessions.keys().next().value;
      if (oldest !== undefined) {
        this.sessions.delete(oldest);
      }
    }

    const fresh: CallHistoryEntry[] = [];
    this.sessions.set(sessionId, fresh);
    return fresh;
  }

  public evaluateAndRecord(
    sessionId: string,
    toolName: string,
    args: JsonObject,
  ): Result<SimHashCallVerdict, SentinelError> {
    const canonicalRes = canonicalHashHex({ tool: toolName, args });
    if (!canonicalRes.ok) {
      return canonicalRes;
    }
    const canonicalDigestHex = canonicalRes.value;
    const simhash = computeInvocationSimHash64(toolName, args);
    const simhash64Hex = formatSimHashHex(simhash);

    if (!this.config.simhashEnabled) {
      return ok({
        canonicalDigestHex,
        simhash64Hex,
        nearestHammingDistance: null,
        windowCallCount: 1,
      });
    }

    const window = this.getOrCreateWindow(sessionId);

    // Tier 1: Consecutive identical canonical streak
    let identicalStreak = 1;
    for (let i = window.length - 1; i >= 0; i -= 1) {
      const entry = window[i];
      if (entry !== undefined && entry.canonicalDigestHex === canonicalDigestHex) {
        identicalStreak += 1;
      } else {
        break;
      }
    }

    if (identicalStreak >= this.config.maxIdenticalStreak) {
      return err(
        createSentinelError(
          'LOOP_DETECTED',
          `Cognitive loop blocked on "${toolName}": identical tool invocation repeated ${identicalStreak} consecutive times`,
          'simhash-loop-detector',
          {
            tier: 'EXACT_CANONICAL_STREAK' satisfies LoopDetectionTier,
            toolName,
            identicalStreak,
            canonicalDigestHex,
          },
        ),
      );
    }

    // Tier 2: Periodic multi-step oscillation (A -> B -> A -> B -> A -> B)
    const cyclePeriod = detectPeriodicSuffixCycle(window, canonicalDigestHex);
    if (cyclePeriod !== null) {
      return err(
        createSentinelError(
          'LOOP_DETECTED',
          `Periodic ${cyclePeriod}-step agent oscillation loop blocked involving "${toolName}"`,
          'simhash-loop-detector',
          {
            tier: 'PERIODIC_CYCLE' satisfies LoopDetectionTier,
            toolName,
            cyclePeriod,
            canonicalDigestHex,
          },
        ),
      );
    }

    // Tier 3: 64-bit SimHash near-duplicate & error-retry spiral check within sliding window
    let nearDuplicateCount = 0;
    let failedNearDuplicateCount = 0;
    let nearestHammingDistance: number | null = null;

    for (const prev of window) {
      if (prev.toolName !== toolName) {
        continue;
      }
      const dist = hammingDistance64(prev.simhash, simhash);
      if (nearestHammingDistance === null || dist < nearestHammingDistance) {
        nearestHammingDistance = dist;
      }
      if (dist <= this.config.simhashMaxHammingDistance) {
        nearDuplicateCount += 1;
        if (prev.failed) {
          failedNearDuplicateCount += 1;
        }
      }
    }

    if (failedNearDuplicateCount >= Math.max(2, this.config.maxIdenticalStreak - 1)) {
      return err(
        createSentinelError(
          'LOOP_DETECTED',
          `Error-retry spiral blocked on "${toolName}": ${failedNearDuplicateCount} prior near-identical calls failed (Hamming <= ${this.config.simhashMaxHammingDistance})`,
          'simhash-loop-detector',
          {
            tier: 'ERROR_RETRY_SPIRAL' satisfies LoopDetectionTier,
            toolName,
            failedNearDuplicateCount,
            nearestHammingDistance,
            simhash64Hex,
          },
        ),
      );
    }

    if (nearDuplicateCount + 1 > this.config.maxIdenticalStreak + 1) {
      return err(
        createSentinelError(
          'LOOP_DETECTED',
          `Fuzzy semantic loop blocked on "${toolName}": ${nearDuplicateCount + 1} near-duplicate calls within Hamming distance <= ${this.config.simhashMaxHammingDistance}`,
          'simhash-loop-detector',
          {
            tier: 'SIMHASH_NEAR_DUPLICATE' satisfies LoopDetectionTier,
            toolName,
            nearDuplicateCount: nearDuplicateCount + 1,
            maxHammingDistance: this.config.simhashMaxHammingDistance,
            nearestHammingDistance,
            simhash64Hex,
          },
        ),
      );
    }

    window.push({
      toolName,
      canonicalDigestHex,
      simhash,
      failed: false,
    });

    while (window.length > this.config.simhashWindowSize) {
      window.shift();
    }

    return ok({
      canonicalDigestHex,
      simhash64Hex,
      nearestHammingDistance,
      windowCallCount: window.length,
    });
  }

  /**
   * Marks the most recent matching invocation in the session window as failed
   * so repeated futile retries with slightly tweaked parameters trip `ERROR_RETRY_SPIRAL`.
   */
  public markLastCallFailed(sessionId: string, canonicalDigestHex: string): void {
    const window = this.sessions.get(sessionId);
    if (window === undefined) {
      return;
    }
    for (let i = window.length - 1; i >= 0; i -= 1) {
      const item = window[i];
      if (item !== undefined && item.canonicalDigestHex === canonicalDigestHex) {
        item.failed = true;
        return;
      }
    }
  }

  public resetSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }
}
