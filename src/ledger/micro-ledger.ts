import { randomBytes } from 'node:crypto';
import type { Clock } from '../core/clock.js';
import { matchToolGlob } from '../ifc/security-lattice.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import type { BudgetLedgerConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';
import { formatMicroUsdAsUsd } from './cost-model.js';

export type BudgetTierName = 'GLOBAL' | 'TENANT' | 'SESSION' | 'TOOL';

export interface BudgetReservation {
  readonly reservationId: string;
  readonly tenantId: string;
  readonly sessionId: string;
  readonly toolName: string;
  readonly reservedMicroUsd: number;
  readonly createdAtMs: number;
}

export interface CommitReceipt {
  readonly reservationId: string;
  readonly reservedMicroUsd: number;
  readonly committedMicroUsd: number;
  readonly deltaMicroUsd: number;
  readonly sessionSettledMicroUsd: number;
  readonly sessionReservedMicroUsd: number;
}

export interface RollbackReceipt {
  readonly reservationId: string;
  readonly releasedMicroUsd: number;
  readonly sessionSettledMicroUsd: number;
  readonly sessionReservedMicroUsd: number;
}

export interface LedgerExposureSnapshot {
  readonly globalSettledMicroUsd: number;
  readonly globalReservedMicroUsd: number;
  readonly tenantSettledMicroUsd: number;
  readonly tenantReservedMicroUsd: number;
  readonly sessionSettledMicroUsd: number;
  readonly sessionReservedMicroUsd: number;
  readonly activeReservationsCount: number;
}

interface DualBalanceCounter {
  settledMicroUsd: number;
  reservedMicroUsd: number;
}

function validateMicroUsdAmount(amount: number, stage: string): Result<number, SentinelError> {
  if (!Number.isFinite(amount) || amount < 0 || !Number.isSafeInteger(amount)) {
    return err(
      createSentinelError(
        'INVALID_PARAMS',
        `Ledger amount must be a non-negative safe integer in Micro-USD, got ${String(amount)}`,
        stage,
      ),
    );
  }
  return ok(amount);
}

/**
 * 4-Tier Atomic Two-Phase Micro-USD Budget Ledger (`GLOBAL` -> `TENANT` -> `SESSION` -> `TOOL`).
 *
 * Eliminates parallel async race-condition overspending by locking estimated exposure via
 * `reserve()` prior to tool execution, followed by exact one-time settlement via `commit()`
 * or full release via `rollback()` on upstream transport failure.
 */
export class MicroUsdLedger {
  private readonly config: BudgetLedgerConfig;
  private readonly clock: Clock;
  private readonly globalBalance: DualBalanceCounter = {
    settledMicroUsd: 0,
    reservedMicroUsd: 0,
  };
  private readonly tenantBalances = new Map<string, DualBalanceCounter>();
  private readonly sessionBalances = new Map<string, DualBalanceCounter>();
  private readonly toolBalances = new Map<string, DualBalanceCounter>();
  private readonly activeReservations = new Map<string, BudgetReservation>();

  public constructor(config: BudgetLedgerConfig, clock: Clock) {
    this.config = config;
    this.clock = clock;
  }

  private sessionKey(tenantId: string, sessionId: string): string {
    return `${tenantId}:${sessionId}`;
  }

  private toolKey(tenantId: string, sessionId: string, toolName: string): string {
    return `${tenantId}:${sessionId}:${toolName}`;
  }

  private getOrCreateCounter(
    map: Map<string, DualBalanceCounter>,
    key: string,
  ): DualBalanceCounter {
    const existing = map.get(key);
    if (existing !== undefined) {
      return existing;
    }
    const created: DualBalanceCounter = { settledMicroUsd: 0, reservedMicroUsd: 0 };
    map.set(key, created);
    return created;
  }

  private resolvePerToolCeiling(toolName: string): number | undefined {
    if (this.config.maxPerToolMicroUsd === undefined) {
      return undefined;
    }
    const exact = this.config.maxPerToolMicroUsd[toolName];
    if (exact !== undefined) {
      return exact;
    }
    for (const [pattern, ceiling] of Object.entries(this.config.maxPerToolMicroUsd)) {
      if ((pattern.includes('*') || pattern.includes('?')) && matchToolGlob(pattern, toolName)) {
        return ceiling;
      }
    }
    return undefined;
  }

  private checkTierCeiling(
    tier: BudgetTierName,
    counter: DualBalanceCounter,
    requestedMicroUsd: number,
    ceilingMicroUsd: number | undefined,
    toolName: string,
  ): Result<void, SentinelError> {
    if (ceilingMicroUsd === undefined) {
      return ok(undefined);
    }
    const currentExposure = counter.settledMicroUsd + counter.reservedMicroUsd;
    const projectedExposure = currentExposure + requestedMicroUsd;
    if (projectedExposure > ceilingMicroUsd) {
      return err(
        createSentinelError(
          'BUDGET_EXCEEDED',
          `${tier} budget ceiling exceeded on "${toolName}": projected $${formatMicroUsdAsUsd(projectedExposure)} > limit $${formatMicroUsdAsUsd(ceilingMicroUsd)}`,
          'micro-usd-ledger',
          {
            tier,
            toolName,
            ceilingMicroUsd,
            settledMicroUsd: counter.settledMicroUsd,
            reservedMicroUsd: counter.reservedMicroUsd,
            requestedMicroUsd,
          },
        ),
      );
    }
    return ok(undefined);
  }

  /**
   * Phase 1: Atomically locks `estimatedMicroUsd` across all 4 ledger tiers
   * only if every tier has sufficient remaining headroom.
   */
  public reserve(params: {
    readonly tenantId: string;
    readonly sessionId: string;
    readonly toolName: string;
    readonly estimatedMicroUsd: number;
  }): Result<BudgetReservation, SentinelError> {
    const validAmount = validateMicroUsdAmount(params.estimatedMicroUsd, 'micro-usd-ledger.reserve');
    if (!validAmount.ok) {
      return validAmount;
    }
    const amount = validAmount.value;

    const tenantCounter = this.getOrCreateCounter(this.tenantBalances, params.tenantId);
    const sKey = this.sessionKey(params.tenantId, params.sessionId);
    const sessionCounter = this.getOrCreateCounter(this.sessionBalances, sKey);
    const tKey = this.toolKey(params.tenantId, params.sessionId, params.toolName);
    const toolCounter = this.getOrCreateCounter(this.toolBalances, tKey);

    if (this.config.enabled) {
      const globalCheck = this.checkTierCeiling(
        'GLOBAL',
        this.globalBalance,
        amount,
        this.config.maxGlobalMicroUsd,
        params.toolName,
      );
      if (!globalCheck.ok) return globalCheck;

      const tenantCheck = this.checkTierCeiling(
        'TENANT',
        tenantCounter,
        amount,
        this.config.maxTenantMicroUsd,
        params.toolName,
      );
      if (!tenantCheck.ok) return tenantCheck;

      const sessionCheck = this.checkTierCeiling(
        'SESSION',
        sessionCounter,
        amount,
        this.config.maxSessionMicroUsd,
        params.toolName,
      );
      if (!sessionCheck.ok) return sessionCheck;

      const toolCeiling = this.resolvePerToolCeiling(params.toolName);
      const toolCheck = this.checkTierCeiling(
        'TOOL',
        toolCounter,
        amount,
        toolCeiling,
        params.toolName,
      );
      if (!toolCheck.ok) return toolCheck;
    }

    // All tiers passed: mutate reservation holds atomically
    this.globalBalance.reservedMicroUsd += amount;
    tenantCounter.reservedMicroUsd += amount;
    sessionCounter.reservedMicroUsd += amount;
    toolCounter.reservedMicroUsd += amount;

    const reservation: BudgetReservation = {
      reservationId: `rsv_${randomBytes(10).toString('hex')}`,
      tenantId: params.tenantId,
      sessionId: params.sessionId,
      toolName: params.toolName,
      reservedMicroUsd: amount,
      createdAtMs: this.clock.nowMs(),
    };

    this.activeReservations.set(reservation.reservationId, reservation);
    return ok(reservation);
  }

  /**
   * Phase 2a: Releases the reservation hold and commits `actualMicroUsd` into
   * settled spend across all 4 tiers. Enforces strict single-settlement idempotency.
   */
  public commit(
    reservationId: string,
    actualMicroUsd: number,
  ): Result<CommitReceipt, SentinelError> {
    const validActual = validateMicroUsdAmount(actualMicroUsd, 'micro-usd-ledger.commit');
    if (!validActual.ok) {
      return validActual;
    }

    const reservation = this.activeReservations.get(reservationId);
    if (reservation === undefined) {
      return err(
        createSentinelError(
          'INTERNAL_ERROR',
          `Cannot commit unknown or already-settled budget reservation "${reservationId}"`,
          'micro-usd-ledger',
          { reservationId },
        ),
      );
    }

    this.activeReservations.delete(reservationId);

    const committed = validActual.value;
    const held = reservation.reservedMicroUsd;

    const tenantCounter = this.getOrCreateCounter(this.tenantBalances, reservation.tenantId);
    const sessionCounter = this.getOrCreateCounter(
      this.sessionBalances,
      this.sessionKey(reservation.tenantId, reservation.sessionId),
    );
    const toolCounter = this.getOrCreateCounter(
      this.toolBalances,
      this.toolKey(reservation.tenantId, reservation.sessionId, reservation.toolName),
    );

    this.globalBalance.reservedMicroUsd = Math.max(0, this.globalBalance.reservedMicroUsd - held);
    tenantCounter.reservedMicroUsd = Math.max(0, tenantCounter.reservedMicroUsd - held);
    sessionCounter.reservedMicroUsd = Math.max(0, sessionCounter.reservedMicroUsd - held);
    toolCounter.reservedMicroUsd = Math.max(0, toolCounter.reservedMicroUsd - held);

    this.globalBalance.settledMicroUsd += committed;
    tenantCounter.settledMicroUsd += committed;
    sessionCounter.settledMicroUsd += committed;
    toolCounter.settledMicroUsd += committed;

    return ok({
      reservationId,
      reservedMicroUsd: held,
      committedMicroUsd: committed,
      deltaMicroUsd: committed - held,
      sessionSettledMicroUsd: sessionCounter.settledMicroUsd,
      sessionReservedMicroUsd: sessionCounter.reservedMicroUsd,
    });
  }

  /**
   * Phase 2b: Releases the reservation hold in full when an upstream MCP call
   * fails or is aborted prior to completion.
   */
  public rollback(reservationId: string): Result<RollbackReceipt, SentinelError> {
    const reservation = this.activeReservations.get(reservationId);
    if (reservation === undefined) {
      return err(
        createSentinelError(
          'INTERNAL_ERROR',
          `Cannot roll back unknown or already-settled budget reservation "${reservationId}"`,
          'micro-usd-ledger',
          { reservationId },
        ),
      );
    }

    this.activeReservations.delete(reservationId);
    const held = reservation.reservedMicroUsd;

    const tenantCounter = this.getOrCreateCounter(this.tenantBalances, reservation.tenantId);
    const sessionCounter = this.getOrCreateCounter(
      this.sessionBalances,
      this.sessionKey(reservation.tenantId, reservation.sessionId),
    );
    const toolCounter = this.getOrCreateCounter(
      this.toolBalances,
      this.toolKey(reservation.tenantId, reservation.sessionId, reservation.toolName),
    );

    this.globalBalance.reservedMicroUsd = Math.max(0, this.globalBalance.reservedMicroUsd - held);
    tenantCounter.reservedMicroUsd = Math.max(0, tenantCounter.reservedMicroUsd - held);
    sessionCounter.reservedMicroUsd = Math.max(0, sessionCounter.reservedMicroUsd - held);
    toolCounter.reservedMicroUsd = Math.max(0, toolCounter.reservedMicroUsd - held);

    return ok({
      reservationId,
      releasedMicroUsd: held,
      sessionSettledMicroUsd: sessionCounter.settledMicroUsd,
      sessionReservedMicroUsd: sessionCounter.reservedMicroUsd,
    });
  }

  public getSessionExposureMicroUsd(tenantId: string, sessionId: string): number {
    const counter = this.sessionBalances.get(this.sessionKey(tenantId, sessionId));
    if (counter === undefined) {
      return 0;
    }
    return counter.settledMicroUsd + counter.reservedMicroUsd;
  }

  public getSnapshot(tenantId: string, sessionId: string): LedgerExposureSnapshot {
    const tenantCounter = this.tenantBalances.get(tenantId);
    const sessionCounter = this.sessionBalances.get(this.sessionKey(tenantId, sessionId));

    return {
      globalSettledMicroUsd: this.globalBalance.settledMicroUsd,
      globalReservedMicroUsd: this.globalBalance.reservedMicroUsd,
      tenantSettledMicroUsd: tenantCounter?.settledMicroUsd ?? 0,
      tenantReservedMicroUsd: tenantCounter?.reservedMicroUsd ?? 0,
      sessionSettledMicroUsd: sessionCounter?.settledMicroUsd ?? 0,
      sessionReservedMicroUsd: sessionCounter?.reservedMicroUsd ?? 0,
      activeReservationsCount: this.activeReservations.size,
    };
  }

  /**
   * Reclaims abandoned in-flight holds older than `maxHoldAgeMs` so hung callers
   * never permanently starve tenant or global budgets.
   */
  public reapStaleReservations(maxHoldAgeMs: number): number {
    const nowMs = this.clock.nowMs();
    const staleIds: string[] = [];

    for (const [id, rsv] of this.activeReservations.entries()) {
      if (nowMs - rsv.createdAtMs >= maxHoldAgeMs) {
        staleIds.push(id);
      }
    }

    let reaped = 0;
    for (const id of staleIds) {
      const res = this.rollback(id);
      if (res.ok) {
        reaped += 1;
      }
    }
    return reaped;
  }
}
