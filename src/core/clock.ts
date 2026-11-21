/**
 * Abstract monotonic and wall-clock time source enabling deterministic,
 * zero-sleep sub-millisecond unit testing across all time-based state machines.
 */
export interface Clock {
  nowMs(): number;
  nowMicros(): bigint;
  isoNow(): string;
}

export class SystemClock implements Clock {
  public nowMs(): number {
    return Date.now();
  }

  public nowMicros(): bigint {
    return process.hrtime.bigint() / 1_000n;
  }

  public isoNow(): string {
    return new Date(this.nowMs()).toISOString();
  }
}

export class VirtualClock implements Clock {
  private currentMs: number;
  private monotonicMicros: bigint;

  public constructor(initialEpochMs = 1_700_000_000_000) {
    if (!Number.isFinite(initialEpochMs) || initialEpochMs < 0) {
      throw new RangeError('initialEpochMs must be a non-negative finite number');
    }
    this.currentMs = Math.floor(initialEpochMs);
    this.monotonicMicros = BigInt(this.currentMs) * 1_000n;
  }

  public nowMs(): number {
    return this.currentMs;
  }

  public nowMicros(): bigint {
    return this.monotonicMicros;
  }

  public isoNow(): string {
    return new Date(this.currentMs).toISOString();
  }

  public advanceMs(deltaMs: number): void {
    if (!Number.isFinite(deltaMs) || deltaMs < 0) {
      throw new RangeError('deltaMs must be a non-negative finite number');
    }
    const wholeMs = Math.floor(deltaMs);
    this.currentMs += wholeMs;
    this.monotonicMicros += BigInt(wholeMs) * 1_000n;
  }

  public advanceMicros(deltaMicros: bigint): void {
    if (deltaMicros < 0n) {
      throw new RangeError('deltaMicros must be non-negative');
    }
    this.monotonicMicros += deltaMicros;
    this.currentMs = Number(this.monotonicMicros / 1_000n);
  }

  public setNowMs(targetEpochMs: number): void {
    if (!Number.isFinite(targetEpochMs) || targetEpochMs < this.currentMs) {
      throw new RangeError('targetEpochMs must be finite and monotonic (>= current time)');
    }
    const delta = Math.floor(targetEpochMs) - this.currentMs;
    this.advanceMs(delta);
  }
}
