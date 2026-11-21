import type { Clock } from '../core/clock.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import type { CircuitBreakerConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitSnapshot {
  readonly toolName: string;
  readonly state: CircuitState;
  readonly consecutiveFailures: number;
  readonly halfOpenSuccesses: number;
  readonly openedAtMs: number | null;
}

interface BreakerEntry {
  state: CircuitState;
  consecutiveFailures: number;
  halfOpenSuccesses: number;
  openedAtMs: number | null;
  probeInFlight: boolean;
}

/**
 * Per-Tool Deterministic Circuit Breaker State Machine (`CLOSED` -> `OPEN` -> `HALF_OPEN`)
 * with single-probe half-open gating to prevent thundering-herd recovery storms.
 */
export class CircuitBreakerRegistry {
  private readonly config: CircuitBreakerConfig;
  private readonly clock: Clock;
  private readonly breakers = new Map<string, BreakerEntry>();

  public constructor(config: CircuitBreakerConfig, clock: Clock) {
    this.config = config;
    this.clock = clock;
  }

  private getOrCreate(toolName: string): BreakerEntry {
    const existing = this.breakers.get(toolName);
    if (existing !== undefined) {
      return existing;
    }
    const created: BreakerEntry = {
      state: 'CLOSED',
      consecutiveFailures: 0,
      halfOpenSuccesses: 0,
      openedAtMs: null,
      probeInFlight: false,
    };
    this.breakers.set(toolName, created);
    return created;
  }

  /**
   * Verifies whether a call to `toolName` may proceed. Transitions `OPEN` -> `HALF_OPEN`
   * automatically once `recoveryTimeoutMs` has elapsed on the injected `Clock`.
   */
  public beforeCall(toolName: string): Result<CircuitState, SentinelError> {
    if (!this.config.enabled) {
      return ok('CLOSED');
    }

    const entry = this.getOrCreate(toolName);
    const nowMs = this.clock.nowMs();

    if (entry.state === 'OPEN') {
      const openedAt = entry.openedAtMs ?? nowMs;
      const elapsedMs = nowMs - openedAt;
      if (elapsedMs < this.config.recoveryTimeoutMs) {
        const retryAfterMs = this.config.recoveryTimeoutMs - elapsedMs;
        return err(
          createSentinelError(
            'CIRCUIT_OPEN',
            `Circuit breaker is OPEN for upstream tool "${toolName}"; retry after ${retryAfterMs}ms`,
            'circuit-breaker',
            {
              toolName,
              state: 'OPEN',
              retryAfterMs,
              consecutiveFailures: entry.consecutiveFailures,
            },
          ),
        );
      }

      // Cooldown elapsed: transition to HALF_OPEN and admit a single recovery probe
      entry.state = 'HALF_OPEN';
      entry.halfOpenSuccesses = 0;
      entry.probeInFlight = true;
      return ok('HALF_OPEN');
    }

    if (entry.state === 'HALF_OPEN') {
      if (entry.probeInFlight) {
        return err(
          createSentinelError(
            'CIRCUIT_OPEN',
            `Circuit breaker for "${toolName}" is HALF_OPEN with an active recovery probe in flight`,
            'circuit-breaker',
            {
              toolName,
              state: 'HALF_OPEN',
            },
          ),
        );
      }
      entry.probeInFlight = true;
      return ok('HALF_OPEN');
    }

    return ok('CLOSED');
  }

  public recordSuccess(toolName: string): CircuitSnapshot {
    const entry = this.getOrCreate(toolName);
    entry.probeInFlight = false;

    if (entry.state === 'HALF_OPEN') {
      entry.halfOpenSuccesses += 1;
      if (entry.halfOpenSuccesses >= this.config.halfOpenSuccessThreshold) {
        entry.state = 'CLOSED';
        entry.consecutiveFailures = 0;
        entry.halfOpenSuccesses = 0;
        entry.openedAtMs = null;
      }
    } else if (entry.state === 'CLOSED') {
      entry.consecutiveFailures = 0;
    }

    return this.snapshot(toolName);
  }

  public recordFailure(toolName: string): CircuitSnapshot {
    const entry = this.getOrCreate(toolName);
    const nowMs = this.clock.nowMs();
    entry.probeInFlight = false;

    if (entry.state === 'HALF_OPEN') {
      // Immediate re-open if recovery probe fails
      entry.state = 'OPEN';
      entry.openedAtMs = nowMs;
      entry.halfOpenSuccesses = 0;
      entry.consecutiveFailures += 1;
      return this.snapshot(toolName);
    }

    entry.consecutiveFailures += 1;
    if (entry.consecutiveFailures >= this.config.failureThreshold) {
      entry.state = 'OPEN';
      entry.openedAtMs = nowMs;
      entry.halfOpenSuccesses = 0;
    }

    return this.snapshot(toolName);
  }

  public snapshot(toolName: string): CircuitSnapshot {
    const entry = this.getOrCreate(toolName);
    return {
      toolName,
      state: entry.state,
      consecutiveFailures: entry.consecutiveFailures,
      halfOpenSuccesses: entry.halfOpenSuccesses,
      openedAtMs: entry.openedAtMs,
    };
  }

  public reset(toolName?: string): void {
    if (toolName !== undefined) {
      this.breakers.delete(toolName);
    } else {
      this.breakers.clear();
    }
  }
}
