import { canonicalHashHex } from '../core/canonical.js';
import type { Clock } from '../core/clock.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import type { JsonValue } from '../types/jsonrpc.js';
import {
  CONFIDENTIALITY_RANK,
  type ConfidentialityLevel,
  INTEGRITY_RANK,
  type IntegrityLevel,
  type ProvenanceHop,
  type SecurityLabel,
} from '../types/lattice.js';
import { err, ok, type Result } from '../types/result.js';

export interface RecordProvenanceHopInput {
  readonly sessionId: string;
  readonly toolName: string;
  readonly labelApplied: SecurityLabel;
  readonly payloadSample?: JsonValue;
  readonly parentHopIds?: readonly string[];
}

interface SessionDagState {
  readonly hops: Map<string, ProvenanceHop>;
  readonly frontierIds: Set<string>;
  sequence: number;
}

/**
 * Causal Provenance Directed Acyclic Graph (DAG) tracking exact data lineage
 * across tool invocations to attribute root-cause blame on lattice violations.
 */
export class ProvenanceDag {
  private readonly clock: Clock;
  private readonly sessions = new Map<string, SessionDagState>();
  private readonly maxHopsPerSession: number;
  private readonly maxSessions: number;

  public constructor(clock: Clock, maxHopsPerSession = 512, maxSessions = 2_048) {
    this.clock = clock;
    this.maxHopsPerSession = maxHopsPerSession;
    this.maxSessions = maxSessions;
  }

  private getOrCreateSession(sessionId: string): SessionDagState {
    const existing = this.sessions.get(sessionId);
    if (existing !== undefined) {
      return existing;
    }

    if (this.sessions.size >= this.maxSessions) {
      const oldestSession = this.sessions.keys().next().value;
      if (oldestSession !== undefined) {
        this.sessions.delete(oldestSession);
      }
    }

    const created: SessionDagState = {
      hops: new Map<string, ProvenanceHop>(),
      frontierIds: new Set<string>(),
      sequence: 0,
    };
    this.sessions.set(sessionId, created);
    return created;
  }

  public recordHop(input: RecordProvenanceHopInput): Result<ProvenanceHop, SentinelError> {
    const state = this.getOrCreateSession(input.sessionId);

    const parents =
      input.parentHopIds !== undefined
        ? [...input.parentHopIds]
        : Array.from(state.frontierIds);

    for (const parentId of parents) {
      if (!state.hops.has(parentId)) {
        return err(
          createSentinelError(
            'INVALID_PARAMS',
            `Unknown provenance parent hop "${parentId}" in session "${input.sessionId}"`,
            'provenance-dag',
            { parentId, sessionId: input.sessionId },
          ),
        );
      }
    }

    // Evict oldest hop if session exceeds hop ceiling while keeping parent references valid
    if (state.hops.size >= this.maxHopsPerSession) {
      const oldestHopId = state.hops.keys().next().value;
      if (oldestHopId !== undefined) {
        state.hops.delete(oldestHopId);
        state.frontierIds.delete(oldestHopId);
      }
    }

    const validParents = parents.filter((id) => state.hops.has(id));
    state.sequence += 1;
    const timestampMs = this.clock.nowMs();
    const hopId = `hop_${state.sequence}_${timestampMs.toString(36)}`;

    const digestResult = canonicalHashHex({
      hopId,
      toolName: input.toolName,
      parents: validParents,
      label: input.labelApplied,
      sample: input.payloadSample ?? null,
    });
    if (!digestResult.ok) {
      return digestResult;
    }

    const hop: ProvenanceHop = {
      hopId,
      parentHopIds: validParents,
      toolName: input.toolName,
      timestampMs,
      labelApplied: input.labelApplied,
      digestHex: digestResult.value,
    };

    state.hops.set(hopId, hop);
    for (const consumedParent of validParents) {
      state.frontierIds.delete(consumedParent);
    }
    state.frontierIds.add(hopId);

    return ok(hop);
  }

  public getSessionFrontier(sessionId: string): readonly string[] {
    const state = this.sessions.get(sessionId);
    if (state === undefined) {
      return [];
    }
    return Array.from(state.frontierIds);
  }

  public exportSessionLineage(sessionId: string): readonly ProvenanceHop[] {
    const state = this.sessions.get(sessionId);
    if (state === undefined) {
      return [];
    }
    return Array.from(state.hops.values());
  }

  /**
   * Backward causal traversal over the session DAG returning all ancestor hops
   * reachable from the current frontier in chronological order.
   */
  public traceCausalAncestors(
    sessionId: string,
    fromHopIds?: readonly string[],
  ): readonly ProvenanceHop[] {
    const state = this.sessions.get(sessionId);
    if (state === undefined) {
      return [];
    }

    const seeds = fromHopIds ?? Array.from(state.frontierIds);
    const visited = new Set<string>();
    const queue: string[] = [...seeds];
    const collected: ProvenanceHop[] = [];

    while (queue.length > 0) {
      const currentId = queue.shift();
      if (currentId === undefined || visited.has(currentId)) {
        continue;
      }
      visited.add(currentId);

      const hop = state.hops.get(currentId);
      if (hop === undefined) {
        continue;
      }
      collected.push(hop);

      for (const parentId of hop.parentHopIds) {
        if (!visited.has(parentId)) {
          queue.push(parentId);
        }
      }
    }

    collected.sort((a, b) => a.timestampMs - b.timestampMs);
    return collected;
  }

  /**
   * Pinpoints exact ancestor hops that introduced confidentiality >= `minLevel`.
   */
  public explainConfidentialityBlame(
    sessionId: string,
    minLevel: ConfidentialityLevel,
  ): readonly ProvenanceHop[] {
    const threshold = CONFIDENTIALITY_RANK[minLevel];
    return this.traceCausalAncestors(sessionId).filter(
      (hop) => CONFIDENTIALITY_RANK[hop.labelApplied.confidentiality] >= threshold,
    );
  }

  /**
   * Pinpoints exact ancestor hops that degraded integrity <= `atOrBelowLevel`.
   */
  public explainIntegrityTaintBlame(
    sessionId: string,
    atOrBelowLevel: IntegrityLevel,
  ): readonly ProvenanceHop[] {
    const ceiling = INTEGRITY_RANK[atOrBelowLevel];
    return this.traceCausalAncestors(sessionId).filter(
      (hop) => INTEGRITY_RANK[hop.labelApplied.integrity] <= ceiling,
    );
  }

  public clearSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }
}
