import type { Clock } from '../core/clock.js';
import { matchToolGlob } from '../ifc/security-lattice.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import type { RateLimiterConfig, RateLimitRuleConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';

export type RateLimitTier = 'TENANT' | 'SESSION' | 'TOOL';

export interface RateLimitDecision {
  readonly remainingTenantTokens?: number;
  readonly remainingSessionTokens?: number;
  readonly remainingToolTokens?: number;
}

interface TokenBucketState {
  tokens: number;
  lastRefillMs: number;
}

interface ScopedCheckSpec {
  readonly tier: RateLimitTier;
  readonly key: string;
  readonly rule: RateLimitRuleConfig;
}

/**
 * Transactional 3-Tier Continuous-Refill Token Bucket Rate Limiter
 * (Tenant -> Session -> Tool). Evaluates capacity across all active tiers first
 * and deducts tokens atomically so a rejection at a narrower tier never drains
 * parent Tenant or Session buckets.
 */
export class HierarchicalRateLimiter {
  private readonly config: RateLimiterConfig;
  private readonly clock: Clock;
  private readonly buckets = new Map<string, TokenBucketState>();
  private readonly maxBuckets: number;

  public constructor(config: RateLimiterConfig, clock: Clock, maxBuckets = 8_192) {
    this.config = config;
    this.clock = clock;
    this.maxBuckets = maxBuckets;
  }

  private resolveToolRule(toolName: string): RateLimitRuleConfig | undefined {
    if (this.config.perTool !== undefined) {
      const exact = this.config.perTool[toolName];
      if (exact !== undefined) {
        return exact;
      }
      for (const [pattern, rule] of Object.entries(this.config.perTool)) {
        if ((pattern.includes('*') || pattern.includes('?')) && matchToolGlob(pattern, toolName)) {
          return rule;
        }
      }
    }
    return this.config.defaultTool;
  }

  private getRefilledBucket(key: string, rule: RateLimitRuleConfig, nowMs: number): TokenBucketState {
    const existing = this.buckets.get(key);
    if (existing !== undefined) {
      this.buckets.delete(key);
      this.buckets.set(key, existing);

      const elapsedSeconds = Math.max(0, (nowMs - existing.lastRefillMs) / 1_000);
      if (elapsedSeconds > 0) {
        existing.tokens = Math.min(
          rule.capacity,
          existing.tokens + elapsedSeconds * rule.refillPerSecond,
        );
        existing.lastRefillMs = nowMs;
      }
      return existing;
    }

    if (this.buckets.size >= this.maxBuckets) {
      const oldestKey = this.buckets.keys().next().value;
      if (oldestKey !== undefined) {
        this.buckets.delete(oldestKey);
      }
    }

    const fresh: TokenBucketState = {
      tokens: rule.capacity,
      lastRefillMs: nowMs,
    };
    this.buckets.set(key, fresh);
    return fresh;
  }

  public acquire(
    tenantId: string,
    sessionId: string,
    toolName: string,
    cost = 1,
  ): Result<RateLimitDecision, SentinelError> {
    if (!this.config.enabled) {
      return ok({});
    }

    const nowMs = this.clock.nowMs();
    const specs: ScopedCheckSpec[] = [];

    if (this.config.tenant !== undefined) {
      specs.push({
        tier: 'TENANT',
        key: `tenant:${tenantId}`,
        rule: this.config.tenant,
      });
    }

    if (this.config.session !== undefined) {
      specs.push({
        tier: 'SESSION',
        key: `session:${tenantId}:${sessionId}`,
        rule: this.config.session,
      });
    }

    const toolRule = this.resolveToolRule(toolName);
    if (toolRule !== undefined) {
      specs.push({
        tier: 'TOOL',
        key: `tool:${tenantId}:${sessionId}:${toolName}`,
        rule: toolRule,
      });
    }

    // Phase 1: Refill and verify sufficient tokens across all tiers without mutating counts
    const evaluated: { readonly spec: ScopedCheckSpec; readonly bucket: TokenBucketState }[] = [];

    for (const spec of specs) {
      const bucket = this.getRefilledBucket(spec.key, spec.rule, nowMs);
      if (bucket.tokens < cost) {
        const deficit = cost - bucket.tokens;
        const retryAfterMs =
          spec.rule.refillPerSecond > 0
            ? Math.ceil((deficit / spec.rule.refillPerSecond) * 1_000)
            : 60_000;

        return err(
          createSentinelError(
            'RATE_LIMITED',
            `Rate limit exceeded at ${spec.tier} tier for "${toolName}"; retry after ${retryAfterMs}ms`,
            'rate-limiter',
            {
              tier: spec.tier,
              toolName,
              retryAfterMs,
              capacity: spec.rule.capacity,
              refillPerSecond: spec.rule.refillPerSecond,
            },
          ),
        );
      }
      evaluated.push({ spec, bucket });
    }

    // Phase 2: Atomic deduction across all tiers
    let remainingTenantTokens: number | undefined;
    let remainingSessionTokens: number | undefined;
    let remainingToolTokens: number | undefined;

    for (const item of evaluated) {
      item.bucket.tokens -= cost;
      const floored = Math.floor(item.bucket.tokens * 100) / 100;
      if (item.spec.tier === 'TENANT') remainingTenantTokens = floored;
      else if (item.spec.tier === 'SESSION') remainingSessionTokens = floored;
      else remainingToolTokens = floored;
    }

    return ok({
      ...(remainingTenantTokens !== undefined ? { remainingTenantTokens } : {}),
      ...(remainingSessionTokens !== undefined ? { remainingSessionTokens } : {}),
      ...(remainingToolTokens !== undefined ? { remainingToolTokens } : {}),
    });
  }

  public resetAll(): void {
    this.buckets.clear();
  }
}
