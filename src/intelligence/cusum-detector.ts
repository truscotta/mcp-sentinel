import { createSentinelError, type SentinelError } from '../types/errors.js';
import type { IntelligenceConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';

export interface SpendAnomalySnapshot {
  readonly sampleCount: number;
  readonly meanMicroUsd: number;
  readonly stdDevMicroUsd: number;
  readonly zScore: number;
  readonly cusumHighMicroUsd: number;
  readonly isZScoreSpike: boolean;
  readonly isCusumDriftBreach: boolean;
}

interface WelfordCusumState {
  count: number;
  mean: number;
  m2: number;
  cusumPlus: number;
}

const MIN_SAMPLES_FOR_ZSCORE = 5;

/**
 * Dual Statistical FinOps Burn-Rate Detector combining:
 * 1. Welford's O(1) numerically stable online variance for instant Z-score spike detection.
 * 2. Page's Upper Tabular CUSUM sequential change-point test with a poison-resistant
 *    in-control reference baseline to catch stealthy "salami-slicing" budget drains.
 */
export class CusumAnomalyDetector {
  private readonly config: IntelligenceConfig;
  private readonly sessions = new Map<string, WelfordCusumState>();
  private readonly maxSessions: number;

  public constructor(config: IntelligenceConfig, maxSessions = 4_096) {
    this.config = config;
    this.maxSessions = maxSessions;
  }

  private getOrCreateState(sessionId: string): WelfordCusumState {
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

    const fresh: WelfordCusumState = {
      count: 0,
      mean: 0,
      m2: 0,
      cusumPlus: 0,
    };
    this.sessions.set(sessionId, fresh);
    return fresh;
  }

  private computeStdDev(state: WelfordCusumState): number {
    if (state.count < 2) {
      return 0;
    }
    return Math.sqrt(state.m2 / (state.count - 1));
  }

  public checkProjectedSpend(
    sessionId: string,
    estimatedMicroUsd: number,
  ): Result<SpendAnomalySnapshot, SentinelError> {
    const safeCost = Math.max(0, Math.floor(estimatedMicroUsd));
    const state = this.sessions.get(sessionId);

    if (!this.config.cusumEnabled || state === undefined || state.count === 0) {
      return ok({
        sampleCount: state?.count ?? 0,
        meanMicroUsd: state?.mean ?? 0,
        stdDevMicroUsd: 0,
        zScore: 0,
        cusumHighMicroUsd: state?.cusumPlus ?? 0,
        isZScoreSpike: false,
        isCusumDriftBreach: false,
      });
    }

    const stdDev = this.computeStdDev(state);
    const zScore =
      state.count >= MIN_SAMPLES_FOR_ZSCORE && stdDev > 0
        ? (safeCost - state.mean) / stdDev
        : 0;

    const projectedCusum = Math.max(
      0,
      state.cusumPlus + (safeCost - state.mean - this.config.cusumDriftMicroUsd),
    );

    const isZScoreSpike =
      state.count >= MIN_SAMPLES_FOR_ZSCORE && zScore > this.config.zScoreThreshold;
    const isCusumDriftBreach =
      state.count >= MIN_SAMPLES_FOR_ZSCORE &&
      projectedCusum > this.config.cusumThresholdMicroUsd;

    const snapshot: SpendAnomalySnapshot = {
      sampleCount: state.count,
      meanMicroUsd: state.mean,
      stdDevMicroUsd: stdDev,
      zScore,
      cusumHighMicroUsd: projectedCusum,
      isZScoreSpike,
      isCusumDriftBreach,
    };

    if (isCusumDriftBreach) {
      return err(
        createSentinelError(
          'BUDGET_EXCEEDED',
          `CUSUM cumulative spend drift breached threshold (${Math.round(projectedCusum)} uUSD > ${this.config.cusumThresholdMicroUsd} uUSD)`,
          'cusum-anomaly-detector',
          {
            anomalyType: 'CUSUM_DRIFT_BREACH',
            projectedCusumMicroUsd: Math.round(projectedCusum),
            thresholdMicroUsd: this.config.cusumThresholdMicroUsd,
            meanMicroUsd: Math.round(state.mean),
          },
        ),
      );
    }

    if (isZScoreSpike) {
      return err(
        createSentinelError(
          'BUDGET_EXCEEDED',
          `Welford burn-rate Z-score spike blocked (${zScore.toFixed(2)}σ > ${this.config.zScoreThreshold}σ on ${safeCost} uUSD call)`,
          'cusum-anomaly-detector',
          {
            anomalyType: 'WELFORD_ZSCORE_SPIKE',
            zScore: Number(zScore.toFixed(4)),
            thresholdSigma: this.config.zScoreThreshold,
            estimatedMicroUsd: safeCost,
            meanMicroUsd: Math.round(state.mean),
          },
        ),
      );
    }

    return ok(snapshot);
  }

  public recordActualSpend(sessionId: string, actualMicroUsd: number): SpendAnomalySnapshot {
    const x = Math.max(0, Math.floor(actualMicroUsd));
    const state = this.getOrCreateState(sessionId);

    if (state.count < MIN_SAMPLES_FOR_ZSCORE) {
      state.count += 1;
      const delta = x - state.mean;
      state.mean += delta / state.count;
      const delta2 = x - state.mean;
      state.m2 += delta * delta2;

      return {
        sampleCount: state.count,
        meanMicroUsd: state.mean,
        stdDevMicroUsd: this.computeStdDev(state),
        zScore: 0,
        cusumHighMicroUsd: 0,
        isZScoreSpike: false,
        isCusumDriftBreach: false,
      };
    }

    const baselineMean = state.mean;
    const baselineStdDev = this.computeStdDev(state);
    const zScore = baselineStdDev > 0 ? (x - baselineMean) / baselineStdDev : 0;

    state.cusumPlus = Math.max(
      0,
      state.cusumPlus + (x - baselineMean - this.config.cusumDriftMicroUsd),
    );

    const isZScoreSpike = zScore > this.config.zScoreThreshold;
    const isCusumDriftBreach = state.cusumPlus > this.config.cusumThresholdMicroUsd;

    if (state.cusumPlus === 0 && !isZScoreSpike) {
      state.count += 1;
      const delta = x - state.mean;
      state.mean += delta / state.count;
      const delta2 = x - state.mean;
      state.m2 += delta * delta2;
    }

    return {
      sampleCount: state.count,
      meanMicroUsd: state.mean,
      stdDevMicroUsd: this.computeStdDev(state),
      zScore,
      cusumHighMicroUsd: state.cusumPlus,
      isZScoreSpike,
      isCusumDriftBreach,
    };
  }

  public resetSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }
}
