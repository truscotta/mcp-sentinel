import { createSentinelError, type SentinelError } from '../types/errors.js';
import {
  CONFIDENTIALITY_RANK,
  DEFAULT_SESSION_LABEL,
  DEFAULT_TOOL_CLASSIFICATION,
  INTEGRITY_RANK,
  RANK_TO_CONFIDENTIALITY,
  RANK_TO_INTEGRITY,
  type ConfidentialityLevel,
  type IntegrityLevel,
  type SecurityLabel,
  type ToolSecurityClassification,
} from '../types/lattice.js';
import type { LatticeIfcConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';

export type ResolvedToolClassification = Required<ToolSecurityClassification>;

export interface SessionFlowVerdict {
  readonly sessionLabelBefore: SecurityLabel;
  readonly classification: ResolvedToolClassification;
}

/**
 * Linear-time O(N + M) glob matcher supporting `*` and `?` wildcards
 * with zero regular-expression backtracking risk.
 */
export function matchToolGlob(pattern: string, text: string): boolean {
  let p = 0;
  let t = 0;
  let starIdx = -1;
  let matchIdx = 0;

  while (t < text.length) {
    if (p < pattern.length && (pattern[p] === '?' || pattern[p] === text[t])) {
      p += 1;
      t += 1;
    } else if (p < pattern.length && pattern[p] === '*') {
      starIdx = p;
      matchIdx = t;
      p += 1;
    } else if (starIdx !== -1) {
      p = starIdx + 1;
      matchIdx += 1;
      t = matchIdx;
    } else {
      return false;
    }
  }

  while (p < pattern.length && pattern[p] === '*') {
    p += 1;
  }

  return p === pattern.length;
}

/**
 * Confidentiality Join (Least Upper Bound ⊔): output is at least as secret
 * as the most confidential input observed in the session.
 */
export function joinConfidentiality(
  a: ConfidentialityLevel,
  b: ConfidentialityLevel,
): ConfidentialityLevel {
  const maxRank = Math.max(CONFIDENTIALITY_RANK[a], CONFIDENTIALITY_RANK[b]) as 0 | 1 | 2 | 3;
  return RANK_TO_CONFIDENTIALITY[maxRank];
}

/**
 * Confidentiality Meet (Greatest Lower Bound ⊓).
 */
export function meetConfidentiality(
  a: ConfidentialityLevel,
  b: ConfidentialityLevel,
): ConfidentialityLevel {
  const minRank = Math.min(CONFIDENTIALITY_RANK[a], CONFIDENTIALITY_RANK[b]) as 0 | 1 | 2 | 3;
  return RANK_TO_CONFIDENTIALITY[minRank];
}

/**
 * Integrity Meet (Greatest Lower Bound ⊓): session integrity degrades to the
 * least-trusted input consumed (Biba taint propagation).
 */
export function meetIntegrity(a: IntegrityLevel, b: IntegrityLevel): IntegrityLevel {
  const minRank = Math.min(INTEGRITY_RANK[a], INTEGRITY_RANK[b]) as 0 | 1 | 2 | 3;
  return RANK_TO_INTEGRITY[minRank];
}

/**
 * Integrity Join (Least Upper Bound ⊔).
 */
export function joinIntegrity(a: IntegrityLevel, b: IntegrityLevel): IntegrityLevel {
  const maxRank = Math.max(INTEGRITY_RANK[a], INTEGRITY_RANK[b]) as 0 | 1 | 2 | 3;
  return RANK_TO_INTEGRITY[maxRank];
}

export function combineSessionWithObservation(
  current: SecurityLabel,
  observed: SecurityLabel,
): SecurityLabel {
  return {
    confidentiality: joinConfidentiality(current.confidentiality, observed.confidentiality),
    integrity: meetIntegrity(current.integrity, observed.integrity),
  };
}

/**
 * Enforces the Dual Security Lattice invariant:
 * 1. Bell-LaPadula *-Property (No Write Down): session confidentiality <= sink clearance.
 * 2. Biba *-Property (No Write Up): session integrity >= sink required integrity.
 */
export function verifyLatticeFlow(
  sessionLabel: SecurityLabel,
  toolName: string,
  classification: ResolvedToolClassification,
): Result<void, SentinelError> {
  const sessionConfRank = CONFIDENTIALITY_RANK[sessionLabel.confidentiality];
  const maxSinkConfRank = CONFIDENTIALITY_RANK[classification.maxSinkConfidentiality];

  if (sessionConfRank > maxSinkConfRank) {
    return err(
      createSentinelError(
        'LATTICE_VIOLATION',
        `Bell-LaPadula confidentiality violation on "${toolName}": session holds ${sessionLabel.confidentiality} data which cannot flow into a ${classification.maxSinkConfidentiality} sink`,
        'lattice-ifc',
        {
          violationType: 'CONFIDENTIALITY_NO_WRITE_DOWN',
          toolName,
          sessionConfidentiality: sessionLabel.confidentiality,
          maxSinkConfidentiality: classification.maxSinkConfidentiality,
        },
      ),
    );
  }

  const sessionIntRank = INTEGRITY_RANK[sessionLabel.integrity];
  const minReqIntRank = INTEGRITY_RANK[classification.minRequiredIntegrity];

  if (sessionIntRank < minReqIntRank) {
    return err(
      createSentinelError(
        'LATTICE_VIOLATION',
        `Biba integrity violation on "${toolName}": session integrity is tainted (${sessionLabel.integrity}) below required ${classification.minRequiredIntegrity} threshold`,
        'lattice-ifc',
        {
          violationType: 'INTEGRITY_NO_WRITE_UP',
          toolName,
          sessionIntegrity: sessionLabel.integrity,
          minRequiredIntegrity: classification.minRequiredIntegrity,
        },
      ),
    );
  }

  return ok(undefined);
}

interface SessionLatticeRecord {
  label: SecurityLabel;
  readonly taintTags: Set<string>;
}

/**
 * Stateful per-session Information Flow Control (IFC) lattice monitor
 * blocking "Lethal Trifecta" toxic flows across multi-step agent executions.
 */
export class SecurityLatticeEngine {
  private readonly config: LatticeIfcConfig;
  private readonly sessions = new Map<string, SessionLatticeRecord>();
  private readonly maxTrackedSessions: number;

  public constructor(config: LatticeIfcConfig, maxTrackedSessions = 4_096) {
    this.config = config;
    this.maxTrackedSessions = maxTrackedSessions;
  }

  public resolveToolClassification(toolName: string): ResolvedToolClassification {
    const fallbackBase: ResolvedToolClassification = {
      readConfidentiality:
        this.config.defaultClassification?.readConfidentiality ??
        DEFAULT_TOOL_CLASSIFICATION.readConfidentiality,
      readIntegrity:
        this.config.defaultClassification?.readIntegrity ??
        DEFAULT_TOOL_CLASSIFICATION.readIntegrity,
      maxSinkConfidentiality:
        this.config.defaultClassification?.maxSinkConfidentiality ??
        DEFAULT_TOOL_CLASSIFICATION.maxSinkConfidentiality,
      minRequiredIntegrity:
        this.config.defaultClassification?.minRequiredIntegrity ??
        DEFAULT_TOOL_CLASSIFICATION.minRequiredIntegrity,
      categories:
        this.config.defaultClassification?.categories ?? DEFAULT_TOOL_CLASSIFICATION.categories,
    };

    const exact = this.config.toolClassifications[toolName];
    if (exact !== undefined) {
      return this.mergeClassification(fallbackBase, exact);
    }

    for (const [pattern, spec] of Object.entries(this.config.toolClassifications)) {
      if ((pattern.includes('*') || pattern.includes('?')) && matchToolGlob(pattern, toolName)) {
        return this.mergeClassification(fallbackBase, spec);
      }
    }

    return fallbackBase;
  }

  private mergeClassification(
    base: ResolvedToolClassification,
    override: ToolSecurityClassification,
  ): ResolvedToolClassification {
    return {
      readConfidentiality: override.readConfidentiality ?? base.readConfidentiality,
      readIntegrity: override.readIntegrity ?? base.readIntegrity,
      maxSinkConfidentiality: override.maxSinkConfidentiality ?? base.maxSinkConfidentiality,
      minRequiredIntegrity: override.minRequiredIntegrity ?? base.minRequiredIntegrity,
      categories: override.categories ?? base.categories,
    };
  }

  private getOrCreateSession(sessionId: string): SessionLatticeRecord {
    const existing = this.sessions.get(sessionId);
    if (existing !== undefined) {
      // Refresh LRU insertion order
      this.sessions.delete(sessionId);
      this.sessions.set(sessionId, existing);
      return existing;
    }

    if (this.sessions.size >= this.maxTrackedSessions) {
      const oldestKey = this.sessions.keys().next().value;
      if (oldestKey !== undefined) {
        this.sessions.delete(oldestKey);
      }
    }

    const initial: SessionLatticeRecord = {
      label: this.config.initialLabel ?? DEFAULT_SESSION_LABEL,
      taintTags: new Set<string>(),
    };
    this.sessions.set(sessionId, initial);
    return initial;
  }

  public getSessionLabel(sessionId: string): SecurityLabel {
    const existing = this.sessions.get(sessionId);
    if (existing !== undefined) {
      return existing.label;
    }
    return this.config.initialLabel ?? DEFAULT_SESSION_LABEL;
  }

  public getSessionTaintTags(sessionId: string): readonly string[] {
    const existing = this.sessions.get(sessionId);
    if (existing === undefined) {
      return [];
    }
    return Array.from(existing.taintTags);
  }

  public checkPreCallFlow(
    sessionId: string,
    toolName: string,
  ): Result<SessionFlowVerdict, SentinelError> {
    const classification = this.resolveToolClassification(toolName);
    const currentLabel = this.getSessionLabel(sessionId);

    if (!this.config.enabled) {
      return ok({ sessionLabelBefore: currentLabel, classification });
    }

    const flowCheck = verifyLatticeFlow(currentLabel, toolName, classification);
    if (!flowCheck.ok) {
      return flowCheck;
    }

    return ok({
      sessionLabelBefore: currentLabel,
      classification,
    });
  }

  public recordPostCallObservation(
    sessionId: string,
    toolName: string,
    extraTaintTags?: readonly string[],
  ): SecurityLabel {
    const classification = this.resolveToolClassification(toolName);
    const record = this.getOrCreateSession(sessionId);

    if (this.config.enabled) {
      record.label = combineSessionWithObservation(record.label, {
        confidentiality: classification.readConfidentiality,
        integrity: classification.readIntegrity,
      });

      for (const category of classification.categories) {
        if (category === 'UNTRUSTED_SOURCE' || category === 'SENSITIVE_SOURCE') {
          record.taintTags.add(`${category}:${toolName}`);
        }
      }
    }

    if (extraTaintTags !== undefined) {
      for (const tag of extraTaintTags) {
        record.taintTags.add(tag);
      }
    }

    return record.label;
  }

  public elevateConfidentiality(
    sessionId: string,
    level: ConfidentialityLevel,
    reasonTag?: string,
  ): SecurityLabel {
    const record = this.getOrCreateSession(sessionId);
    record.label = {
      confidentiality: joinConfidentiality(record.label.confidentiality, level),
      integrity: record.label.integrity,
    };
    if (reasonTag !== undefined) {
      record.taintTags.add(reasonTag);
    }
    return record.label;
  }

  public degradeIntegrity(
    sessionId: string,
    level: IntegrityLevel,
    reasonTag?: string,
  ): SecurityLabel {
    const record = this.getOrCreateSession(sessionId);
    record.label = {
      confidentiality: record.label.confidentiality,
      integrity: meetIntegrity(record.label.integrity, level),
    };
    if (reasonTag !== undefined) {
      record.taintTags.add(reasonTag);
    }
    return record.label;
  }

  public resetSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }
}
