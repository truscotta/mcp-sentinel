import { VirtualClock } from '../core/clock.js';
import { SentinelKernel, type UpstreamMcpHandler } from '../core/engine.js';
import type { SentinelError } from '../types/errors.js';
import {
  createJsonRpcSuccessResponse,
  isJsonObject,
  type JsonRpcRequest,
} from '../types/jsonrpc.js';
import type { SentinelPolicy } from '../types/policy.js';
import { ok, type Result } from '../types/result.js';
import { type ForensicAuditRecord, parseAuditJsonl } from './flight-recorder.js';

export interface ReplayDivergenceItem {
  readonly sequence: number;
  readonly requestId: string;
  readonly tenantId: string;
  readonly sessionId: string;
  readonly toolName: string;
  readonly baselineBlocked: boolean;
  readonly candidateBlocked: boolean;
  readonly candidateErrorCode?: number;
  readonly candidateStage?: string;
  readonly candidateReason?: string;
  readonly financialImpactMicroUsd: number;
}

export interface DifferentialReplayReport {
  readonly totalToolCallsReplayed: number;
  readonly baselineAllowedCount: number;
  readonly baselineBlockedCount: number;
  readonly candidateAllowedCount: number;
  readonly candidateBlockedCount: number;
  readonly newlyBlockedCount: number;
  readonly newlyPermittedCount: number;
  readonly preventedSpendMicroUsd: number;
  readonly divergences: readonly ReplayDivergenceItem[];
}

function createEnforcedReplayPolicy(source: SentinelPolicy): SentinelPolicy {
  return {
    ...source,
    mode: 'ENFORCE',
    forensics: {
      ...source.forensics,
      enabled: false,
      signTreeHeads: false,
    },
    telemetry: {
      ...source.telemetry,
      enabled: false,
    },
    idempotency: {
      ...source.idempotency,
      enabled: false,
    },
  };
}

/**
 * Counterfactual Policy Replayer.
 * Backtests a candidate `SentinelPolicy` against historical `ForensicAuditRecord`
 * traces (or compares Baseline Policy A vs Candidate Policy B) using deterministic
 * `VirtualClock` time-travel to quantify exact security impact and prevented spend.
 */
export class CounterfactualPolicyReplayer {
  private readonly maxDivergencesRecorded: number;

  public constructor(maxDivergencesRecorded = 256) {
    this.maxDivergencesRecorded = maxDivergencesRecorded;
  }

  public async replayJsonl(params: {
    readonly jsonlContent: string;
    readonly candidatePolicy: SentinelPolicy;
    readonly baselinePolicy?: SentinelPolicy;
  }): Promise<Result<DifferentialReplayReport, SentinelError>> {
    const parsed = parseAuditJsonl(params.jsonlContent);
    if (!parsed.ok) {
      return parsed;
    }
    return this.replayRecords({
      records: parsed.value,
      candidatePolicy: params.candidatePolicy,
      ...(params.baselinePolicy !== undefined ? { baselinePolicy: params.baselinePolicy } : {}),
    });
  }

  public async replayRecords(params: {
    readonly records: readonly ForensicAuditRecord[];
    readonly candidatePolicy: SentinelPolicy;
    readonly baselinePolicy?: SentinelPolicy;
  }): Promise<Result<DifferentialReplayReport, SentinelError>> {
    const toolCallRecords = params.records.filter(
      (r) => r.method === 'tools/call' && typeof r.toolName === 'string',
    );

    const firstTimestamp = toolCallRecords[0]?.timestampMs ?? 1_700_000_000_000;
    const candidateClock = new VirtualClock(firstTimestamp);
    const candidateKernelRes = SentinelKernel.create(
      createEnforcedReplayPolicy(params.candidatePolicy),
      { clock: candidateClock },
    );
    if (!candidateKernelRes.ok) {
      return candidateKernelRes;
    }
    const candidateKernel = candidateKernelRes.value;

    let baselineKernel: SentinelKernel | null = null;
    let baselineClock: VirtualClock | null = null;
    if (params.baselinePolicy !== undefined) {
      baselineClock = new VirtualClock(firstTimestamp);
      const baseRes = SentinelKernel.create(
        createEnforcedReplayPolicy(params.baselinePolicy),
        { clock: baselineClock },
      );
      if (!baseRes.ok) {
        return baseRes;
      }
      baselineKernel = baseRes.value;
    }

    const syntheticUpstream: UpstreamMcpHandler = async (req: JsonRpcRequest) =>
      createJsonRpcSuccessResponse(req.id, {
        content: [{ type: 'text', text: 'counterfactual_replay_stub' }],
      });

    let baselineAllowedCount = 0;
    let baselineBlockedCount = 0;
    let candidateAllowedCount = 0;
    let candidateBlockedCount = 0;
    let newlyBlockedCount = 0;
    let newlyPermittedCount = 0;
    let preventedSpendMicroUsd = 0;
    const divergences: ReplayDivergenceItem[] = [];

    for (const rec of toolCallRecords) {
      const toolName = rec.toolName ?? 'unknown_tool';
      if (rec.timestampMs > candidateClock.nowMs()) {
        candidateClock.setNowMs(rec.timestampMs);
      }
      if (baselineClock !== null && rec.timestampMs > baselineClock.nowMs()) {
        baselineClock.setNowMs(rec.timestampMs);
      }

      const syntheticReq: JsonRpcRequest = {
        jsonrpc: '2.0',
        id: rec.sequence,
        method: 'tools/call',
        params: {
          name: toolName,
          arguments: rec.sanitizedArgs ?? {},
          _meta: {
            tenantId: rec.tenantId,
            sessionId: rec.sessionId,
            traceparent: rec.traceparent,
          },
        },
      };

      let baselineBlocked: boolean;
      if (baselineKernel !== null) {
        const baseResp = await baselineKernel.handleRequest(syntheticReq, syntheticUpstream);
        baselineBlocked = 'error' in baseResp;
      } else {
        baselineBlocked = rec.outcome === 'BLOCKED';
      }

      if (baselineBlocked) {
        baselineBlockedCount += 1;
      } else {
        baselineAllowedCount += 1;
      }

      const candResp = await candidateKernel.handleRequest(syntheticReq, syntheticUpstream);
      const candidateBlocked = 'error' in candResp;

      if (candidateBlocked) {
        candidateBlockedCount += 1;
      } else {
        candidateAllowedCount += 1;
      }

      if (baselineBlocked !== candidateBlocked) {
        const impactMicroUsd =
          rec.settledMicroUsd > 0 ? rec.settledMicroUsd : rec.estimatedMicroUsd;

        if (!baselineBlocked && candidateBlocked) {
          newlyBlockedCount += 1;
          preventedSpendMicroUsd += impactMicroUsd;
        } else if (baselineBlocked && !candidateBlocked) {
          newlyPermittedCount += 1;
        }

        if (divergences.length < this.maxDivergencesRecorded) {
          let candidateStage: string | undefined;
          let candidateErrorCode: number | undefined;
          let candidateReason: string | undefined;

          if ('error' in candResp) {
            candidateErrorCode = candResp.error.code;
            candidateReason = candResp.error.message;
            if (isJsonObject(candResp.error.data) && typeof candResp.error.data.stage === 'string') {
              candidateStage = candResp.error.data.stage;
            }
          }

          divergences.push({
            sequence: rec.sequence,
            requestId: rec.requestId,
            tenantId: rec.tenantId,
            sessionId: rec.sessionId,
            toolName,
            baselineBlocked,
            candidateBlocked,
            financialImpactMicroUsd: impactMicroUsd,
            ...(candidateErrorCode !== undefined ? { candidateErrorCode } : {}),
            ...(candidateStage !== undefined ? { candidateStage } : {}),
            ...(candidateReason !== undefined ? { candidateReason } : {}),
          });
        }
      }
    }

    return ok({
      totalToolCallsReplayed: toolCallRecords.length,
      baselineAllowedCount,
      baselineBlockedCount,
      candidateAllowedCount,
      candidateBlockedCount,
      newlyBlockedCount,
      newlyPermittedCount,
      preventedSpendMicroUsd,
      divergences,
    });
  }
}
