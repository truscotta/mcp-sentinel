import { canonicalHashHex } from '../core/canonical.js';
import type { Clock } from '../core/clock.js';
import { matchToolGlob } from '../ifc/security-lattice.js';
import type { SentinelError } from '../types/errors.js';
import type { JsonObject } from '../types/jsonrpc.js';
import type { IdempotencyConfig } from '../types/policy.js';
import { ok, type Result } from '../types/result.js';

export type CoalescedExecutionSource = 'EXECUTED' | 'CACHE_HIT' | 'COALESCED_IN_FLIGHT';

export interface CoalescedExecutionOutcome<T> {
  readonly value: T;
  readonly source: CoalescedExecutionSource;
  readonly keyHex: string;
}

export interface IdempotencyKeyInput {
  readonly tenantId: string;
  readonly sessionId: string;
  readonly method: string;
  readonly toolName: string;
  readonly args: JsonObject;
}

interface CachedEntry<T> {
  readonly value: T;
  readonly expiresAtMs: number;
}

/**
 * Deterministic TTL Idempotency Cache & In-Flight Request Coalescer.
 * Collapses concurrent identical tool invocations arriving within the same
 * millisecond into a single upstream execution and serves subsequent repeats
 * within `ttlMs` at zero upstream cost.
 */
export class IdempotencyCoalescer<T> {
  private readonly config: IdempotencyConfig;
  private readonly clock: Clock;
  private readonly cache = new Map<string, CachedEntry<T>>();
  private readonly inFlight = new Map<string, Promise<Result<T, SentinelError>>>();

  public constructor(config: IdempotencyConfig, clock: Clock) {
    this.config = config;
    this.clock = clock;
  }

  private isToolBypassed(toolName: string): boolean {
    if (this.config.bypassTools === undefined) {
      return false;
    }
    return this.config.bypassTools.some((pattern) => matchToolGlob(pattern, toolName));
  }

  public computeKey(input: IdempotencyKeyInput): Result<string, SentinelError> {
    return canonicalHashHex({
      tenantId: input.tenantId,
      sessionId: input.sessionId,
      method: input.method,
      toolName: input.toolName,
      args: input.args,
    });
  }

  private getValidCached(keyHex: string): T | undefined {
    const entry = this.cache.get(keyHex);
    if (entry === undefined) {
      return undefined;
    }
    if (this.clock.nowMs() >= entry.expiresAtMs) {
      this.cache.delete(keyHex);
      return undefined;
    }
    // Refresh LRU order
    this.cache.delete(keyHex);
    this.cache.set(keyHex, entry);
    return entry.value;
  }

  private storeInCache(keyHex: string, value: T): void {
    if (this.config.maxEntries <= 0 || this.config.ttlMs <= 0) {
      return;
    }
    if (this.cache.size >= this.config.maxEntries && !this.cache.has(keyHex)) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }
    this.cache.set(keyHex, {
      value,
      expiresAtMs: this.clock.nowMs() + this.config.ttlMs,
    });
  }

  public async executeOrCoalesce(
    input: IdempotencyKeyInput,
    executor: () => Promise<Result<T, SentinelError>>,
  ): Promise<Result<CoalescedExecutionOutcome<T>, SentinelError>> {
    const keyRes = this.computeKey(input);
    if (!keyRes.ok) {
      return keyRes;
    }
    const keyHex = keyRes.value;

    if (!this.config.enabled || this.isToolBypassed(input.toolName)) {
      const directRes = await executor();
      if (!directRes.ok) {
        return directRes;
      }
      return ok({
        value: directRes.value,
        source: 'EXECUTED',
        keyHex,
      });
    }

    const cachedVal = this.getValidCached(keyHex);
    if (cachedVal !== undefined) {
      return ok({
        value: cachedVal,
        source: 'CACHE_HIT',
        keyHex,
      });
    }

    if (this.config.coalesceInFlight) {
      const activePromise = this.inFlight.get(keyHex);
      if (activePromise !== undefined) {
        const sharedRes = await activePromise;
        if (!sharedRes.ok) {
          return sharedRes;
        }
        return ok({
          value: sharedRes.value,
          source: 'COALESCED_IN_FLIGHT',
          keyHex,
        });
      }
    }

    const executionPromise = executor();
    if (this.config.coalesceInFlight) {
      this.inFlight.set(keyHex, executionPromise);
    }

    try {
      const outcome = await executionPromise;
      if (!outcome.ok) {
        return outcome;
      }
      this.storeInCache(keyHex, outcome.value);
      return ok({
        value: outcome.value,
        source: 'EXECUTED',
        keyHex,
      });
    } finally {
      this.inFlight.delete(keyHex);
    }
  }

  public purgeExpired(): number {
    const nowMs = this.clock.nowMs();
    let purged = 0;
    for (const [key, entry] of this.cache.entries()) {
      if (nowMs >= entry.expiresAtMs) {
        this.cache.delete(key);
        purged += 1;
      }
    }
    return purged;
  }

  public clear(): void {
    this.cache.clear();
  }
}
