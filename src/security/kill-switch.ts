import type { Clock } from '../core/clock.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import type { JsonObject } from '../types/jsonrpc.js';
import { err, ok, type Result } from '../types/result.js';

export type LockdownScope = 'GLOBAL' | 'TENANT' | 'SESSION';

export interface LockdownRecord {
  readonly scope: LockdownScope;
  readonly targetId: string;
  readonly reason: string;
  readonly triggeredByStage: string;
  readonly triggeredAtMs: number;
  readonly expiresAtMs?: number;
  readonly evidence?: JsonObject;
}

export interface TriggerLockdownInput {
  readonly reason: string;
  readonly triggeredByStage: string;
  readonly durationMs?: number;
  readonly evidence?: JsonObject;
}

/**
 * Emergency Isolation Circuit (Kill-Switch) capable of immediately quarantining
 * compromised sessions, tenants, or the entire runtime gateway upon Honey-Tool
 * triggers, Canary tripwires, or severe statistical anomalies.
 */
export class KillSwitch {
  private readonly clock: Clock;
  private globalLock: LockdownRecord | null = null;
  private readonly tenantLocks = new Map<string, LockdownRecord>();
  private readonly sessionLocks = new Map<string, LockdownRecord>();

  public constructor(clock: Clock) {
    this.clock = clock;
  }

  private isRecordActive(record: LockdownRecord): boolean {
    if (record.expiresAtMs === undefined) {
      return true;
    }
    return this.clock.nowMs() < record.expiresAtMs;
  }

  private buildRecord(
    scope: LockdownScope,
    targetId: string,
    input: TriggerLockdownInput,
  ): LockdownRecord {
    const now = this.clock.nowMs();
    const base: LockdownRecord = {
      scope,
      targetId,
      reason: input.reason,
      triggeredByStage: input.triggeredByStage,
      triggeredAtMs: now,
    };

    const expiresAtMs =
      input.durationMs !== undefined && input.durationMs > 0
        ? now + Math.floor(input.durationMs)
        : undefined;

    return {
      ...base,
      ...(expiresAtMs !== undefined ? { expiresAtMs } : {}),
      ...(input.evidence !== undefined ? { evidence: input.evidence } : {}),
    };
  }

  public lockGlobal(input: TriggerLockdownInput): LockdownRecord {
    const record = this.buildRecord('GLOBAL', '*', input);
    this.globalLock = record;
    return record;
  }

  public lockTenant(tenantId: string, input: TriggerLockdownInput): LockdownRecord {
    const record = this.buildRecord('TENANT', tenantId, input);
    this.tenantLocks.set(tenantId, record);
    return record;
  }

  public lockSession(sessionId: string, input: TriggerLockdownInput): LockdownRecord {
    const record = this.buildRecord('SESSION', sessionId, input);
    this.sessionLocks.set(sessionId, record);
    return record;
  }

  public unlockGlobal(): boolean {
    const existed = this.globalLock !== null;
    this.globalLock = null;
    return existed;
  }

  public unlockTenant(tenantId: string): boolean {
    return this.tenantLocks.delete(tenantId);
  }

  public unlockSession(sessionId: string): boolean {
    return this.sessionLocks.delete(sessionId);
  }

  /**
   * Fails closed with `-32008 SESSION_LOCKED` if Global, Tenant, or Session
   * quarantine is active; lazily purges expired temporary locks.
   */
  public assertPermitted(tenantId: string, sessionId: string): Result<void, SentinelError> {
    if (this.globalLock !== null) {
      if (this.isRecordActive(this.globalLock)) {
        return err(this.toLockedError(this.globalLock));
      }
      this.globalLock = null;
    }

    const tenantRecord = this.tenantLocks.get(tenantId);
    if (tenantRecord !== undefined) {
      if (this.isRecordActive(tenantRecord)) {
        return err(this.toLockedError(tenantRecord));
      }
      this.tenantLocks.delete(tenantId);
    }

    const sessionRecord = this.sessionLocks.get(sessionId);
    if (sessionRecord !== undefined) {
      if (this.isRecordActive(sessionRecord)) {
        return err(this.toLockedError(sessionRecord));
      }
      this.sessionLocks.delete(sessionId);
    }

    return ok(undefined);
  }

  public listActiveLockdowns(): readonly LockdownRecord[] {
    const active: LockdownRecord[] = [];

    if (this.globalLock !== null) {
      if (this.isRecordActive(this.globalLock)) {
        active.push(this.globalLock);
      } else {
        this.globalLock = null;
      }
    }

    for (const [id, rec] of this.tenantLocks.entries()) {
      if (this.isRecordActive(rec)) {
        active.push(rec);
      } else {
        this.tenantLocks.delete(id);
      }
    }

    for (const [id, rec] of this.sessionLocks.entries()) {
      if (this.isRecordActive(rec)) {
        active.push(rec);
      } else {
        this.sessionLocks.delete(id);
      }
    }

    return active;
  }

  private toLockedError(record: LockdownRecord): SentinelError {
    return createSentinelError(
      'SESSION_LOCKED',
      `Kill-Switch quarantine active [${record.scope}:${record.targetId}]: ${record.reason}`,
      'kill-switch',
      {
        scope: record.scope,
        targetId: record.targetId,
        triggeredByStage: record.triggeredByStage,
        triggeredAtMs: record.triggeredAtMs,
        ...(record.expiresAtMs !== undefined ? { expiresAtMs: record.expiresAtMs } : {}),
      },
    );
  }
}
