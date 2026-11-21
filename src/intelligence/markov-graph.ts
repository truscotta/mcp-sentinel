import { matchToolGlob } from '../ifc/security-lattice.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import type { IntelligenceConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';

export const MARKOV_START_STATE = '__SESSION_START__';

export interface ForbiddenTransitionRule {
  readonly fromPattern: string;
  readonly toPattern: string;
  readonly reason?: string;
}

export interface SeedTransitionEntry {
  readonly fromTool: string;
  readonly toTool: string;
  readonly count: number;
}

export interface MarkovTransitionVerdict {
  readonly previousTool: string;
  readonly nextTool: string;
  readonly outgoingTotalSamples: number;
  readonly transitionProbability: number;
  readonly isStatisticalAnomaly: boolean;
}

/**
 * First-Order Markov Call-Graph Analyzer.
 * Models empirical tool transition probabilities P(T_t | T_{t-1}) with poison-resistant
 * updates (rejected transitions never pollute baseline counts) alongside deterministic
 * forbidden call-edge policies.
 */
export class MarkovCallGraph {
  private readonly config: IntelligenceConfig;
  private readonly outgoingTotals = new Map<string, number>();
  private readonly edgeCounts = new Map<string, Map<string, number>>();
  private readonly sessionLastTool = new Map<string, string>();
  private readonly forbiddenEdges: ForbiddenTransitionRule[] = [];
  private readonly enforceStatisticalBlock: boolean;
  private readonly maxSessions: number;

  public constructor(
    config: IntelligenceConfig,
    options?: {
      readonly forbiddenEdges?: readonly ForbiddenTransitionRule[];
      readonly seedTransitions?: readonly SeedTransitionEntry[];
      readonly enforceStatisticalBlock?: boolean;
      readonly maxSessions?: number;
    },
  ) {
    this.config = config;
    this.enforceStatisticalBlock = options?.enforceStatisticalBlock ?? false;
    this.maxSessions = options?.maxSessions ?? 4_096;

    if (options?.forbiddenEdges !== undefined) {
      this.forbiddenEdges.push(...options.forbiddenEdges);
    }
    if (options?.seedTransitions !== undefined) {
      this.seedBaselineTransitions(options.seedTransitions);
    }
  }

  public addForbiddenTransition(rule: ForbiddenTransitionRule): void {
    this.forbiddenEdges.push(rule);
  }

  public seedBaselineTransitions(entries: readonly SeedTransitionEntry[]): void {
    for (const entry of entries) {
      if (!Number.isFinite(entry.count) || entry.count <= 0) {
        continue;
      }
      const wholeCount = Math.floor(entry.count);
      this.incrementEdgeCount(entry.fromTool, entry.toTool, wholeCount);
    }
  }

  private incrementEdgeCount(fromTool: string, toTool: string, delta: number): void {
    let targets = this.edgeCounts.get(fromTool);
    if (targets === undefined) {
      targets = new Map<string, number>();
      this.edgeCounts.set(fromTool, targets);
    }
    targets.set(toTool, (targets.get(toTool) ?? 0) + delta);
    this.outgoingTotals.set(fromTool, (this.outgoingTotals.get(fromTool) ?? 0) + delta);
  }

  public getTransitionProbability(fromTool: string, toTool: string): {
    readonly probability: number;
    readonly totalSamples: number;
  } {
    const total = this.outgoingTotals.get(fromTool) ?? 0;
    if (total === 0) {
      return { probability: 1, totalSamples: 0 };
    }
    const edgeCount = this.edgeCounts.get(fromTool)?.get(toTool) ?? 0;
    return {
      probability: edgeCount / total,
      totalSamples: total,
    };
  }

  /**
   * Evaluates transition `previousTool -> nextTool`.
   * Rejects deterministic forbidden edges immediately and flags rare statistical
   * transitions once `totalSamples >= markovMinSamples`.
   */
  public evaluateAndAdvance(
    sessionId: string,
    nextTool: string,
  ): Result<MarkovTransitionVerdict, SentinelError> {
    const previousTool = this.sessionLastTool.get(sessionId) ?? MARKOV_START_STATE;

    if (!this.config.markovEnabled) {
      this.setSessionLastTool(sessionId, nextTool);
      return ok({
        previousTool,
        nextTool,
        outgoingTotalSamples: 0,
        transitionProbability: 1,
        isStatisticalAnomaly: false,
      });
    }

    for (const rule of this.forbiddenEdges) {
      if (
        matchToolGlob(rule.fromPattern, previousTool) &&
        matchToolGlob(rule.toPattern, nextTool)
      ) {
        return err(
          createSentinelError(
            'POLICY_VIOLATION',
            `Forbidden call-graph transition "${previousTool}" -> "${nextTool}"${rule.reason ? `: ${rule.reason}` : ''}`,
            'markov-call-graph',
            {
              previousTool,
              nextTool,
              fromPattern: rule.fromPattern,
              toPattern: rule.toPattern,
            },
          ),
        );
      }
    }

    const { probability, totalSamples } = this.getTransitionProbability(previousTool, nextTool);
    const isStatisticalAnomaly =
      totalSamples >= this.config.markovMinSamples &&
      probability < this.config.markovAnomalyThreshold;

    if (isStatisticalAnomaly && this.enforceStatisticalBlock) {
      return err(
        createSentinelError(
          'POLICY_VIOLATION',
          `Anomalous Markov tool transition "${previousTool}" -> "${nextTool}" (P=${probability.toFixed(4)} < ${this.config.markovAnomalyThreshold} over ${totalSamples} samples)`,
          'markov-call-graph',
          {
            previousTool,
            nextTool,
            transitionProbability: probability,
            outgoingTotalSamples: totalSamples,
            threshold: this.config.markovAnomalyThreshold,
          },
        ),
      );
    }

    // Poison-resistant update: only non-anomalous or bootstrap transitions update baseline weights
    if (!isStatisticalAnomaly) {
      this.incrementEdgeCount(previousTool, nextTool, 1);
    }
    this.setSessionLastTool(sessionId, nextTool);

    return ok({
      previousTool,
      nextTool,
      outgoingTotalSamples: totalSamples,
      transitionProbability: probability,
      isStatisticalAnomaly,
    });
  }

  private setSessionLastTool(sessionId: string, toolName: string): void {
    if (this.sessionLastTool.has(sessionId)) {
      this.sessionLastTool.delete(sessionId);
    } else if (this.sessionLastTool.size >= this.maxSessions) {
      const oldest = this.sessionLastTool.keys().next().value;
      if (oldest !== undefined) {
        this.sessionLastTool.delete(oldest);
      }
    }
    this.sessionLastTool.set(sessionId, toolName);
  }

  public resetSession(sessionId: string): void {
    this.sessionLastTool.delete(sessionId);
  }
}
