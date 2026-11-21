import { verifyMacaroon } from '../capabilities/macaroon.js';
import { MirageDeceptionEngine } from '../deception/mirage-tools.js';
import { EpistemicWatermarkEngine } from '../deception/watermark.js';
import { SplPolicyEngine } from '../dsl/vm.js';
import {
  type AuditDecisionOutcome,
  type ForensicAuditRecord,
  ForensicFlightRecorder,
} from '../forensics/flight-recorder.js';
import { CircuitBreakerRegistry } from '../guards/circuit-breaker.js';
import { IdempotencyCoalescer } from '../guards/idempotency-coalescer.js';
import { PayloadFirewall } from '../guards/payload-firewall.js';
import { HierarchicalRateLimiter } from '../guards/rate-limiter.js';
import { HitlApprovalGate, type HitlWebhookTransport } from '../hitl/approval-gate.js';
import { ProvenanceDag } from '../ifc/provenance-dag.js';
import { SecurityLatticeEngine } from '../ifc/security-lattice.js';
import { CusumAnomalyDetector } from '../intelligence/cusum-detector.js';
import {
  type ForbiddenTransitionRule,
  MarkovCallGraph,
  type SeedTransitionEntry,
} from '../intelligence/markov-graph.js';
import { SimHashLoopDetector } from '../intelligence/simhash.js';
import { calculateActualCallMicroUsd, estimatePreCallMicroUsd } from '../ledger/cost-model.js';
import { MicroUsdLedger } from '../ledger/micro-ledger.js';
import { InjectionShield } from '../security/injection-shield.js';
import { KillSwitch } from '../security/kill-switch.js';
import { SchemaLockGuard } from '../security/schema-lock.js';
import { ObservabilityServer } from '../telemetry/observability-server.js';
import {
  createSentinelError,
  type SentinelError,
  toJsonRpcErrorObject,
} from '../types/errors.js';
import {
  createJsonRpcErrorResponse,
  createJsonRpcSuccessResponse,
  isJsonObject,
  isToolsCallParams,
  type JsonObject,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type JsonValue,
  type McpToolsListResult,
} from '../types/jsonrpc.js';
import {
  DEFAULT_SENTINEL_POLICY,
  type ExecutionMode,
  type SentinelPolicy,
} from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';
import { ReversibleContextVault } from '../vault/context-vault.js';
import { type Clock, SystemClock } from './clock.js';
import { createExecutionContext, formatTraceparent } from './context.js';

export type UpstreamMcpHandler = (request: JsonRpcRequest) => Promise<JsonRpcResponse>;

export interface SentinelKernelOptions {
  readonly clock?: Clock;
  readonly hitlTransport?: HitlWebhookTransport;
  readonly flightRecorder?: ForensicFlightRecorder;
  readonly observability?: ObservabilityServer;
  readonly forbiddenMarkovEdges?: readonly ForbiddenTransitionRule[];
  readonly seedMarkovTransitions?: readonly SeedTransitionEntry[];
}

function isMcpToolsListResult(value: JsonValue): value is JsonObject & McpToolsListResult {
  if (!isJsonObject(value) || !Array.isArray(value.tools)) {
    return false;
  }
  return value.tools.every(
    (item) =>
      isJsonObject(item) &&
      typeof item.name === 'string' &&
      isJsonObject(item.inputSchema) &&
      item.inputSchema.type === 'object',
  );
}

/**
 * Safely merges a partial JSON configuration object onto `DEFAULT_SENTINEL_POLICY`
 * so CLI and SDK consumers can override individual subsections cleanly.
 */
export function mergeSentinelPolicy(rawConfig: unknown): Result<SentinelPolicy, SentinelError> {
  if (!isJsonObject(rawConfig)) {
    return err(
      createSentinelError(
        'INVALID_PARAMS',
        'Policy configuration root must be a JSON object',
        'policy-loader',
      ),
    );
  }

  const modeRaw = rawConfig.mode;
  if (
    modeRaw !== undefined &&
    modeRaw !== 'ENFORCE' &&
    modeRaw !== 'SHADOW' &&
    modeRaw !== 'AUDIT_ONLY'
  ) {
    return err(
      createSentinelError(
        'INVALID_PARAMS',
        `Invalid execution mode "${String(modeRaw)}"; expected ENFORCE, SHADOW, or AUDIT_ONLY`,
        'policy-loader',
      ),
    );
  }

  const merged: SentinelPolicy = {
    version: '1.0',
    mode: (modeRaw as ExecutionMode | undefined) ?? DEFAULT_SENTINEL_POLICY.mode,
    maxVmGas:
      typeof rawConfig.maxVmGas === 'number'
        ? rawConfig.maxVmGas
        : DEFAULT_SENTINEL_POLICY.maxVmGas,
    splRules: Array.isArray(rawConfig.splRules)
      ? (rawConfig.splRules as unknown as SentinelPolicy['splRules'])
      : DEFAULT_SENTINEL_POLICY.splRules,
    firewall: isJsonObject(rawConfig.firewall)
      ? { ...DEFAULT_SENTINEL_POLICY.firewall, ...(rawConfig.firewall as Partial<SentinelPolicy['firewall']>) }
      : DEFAULT_SENTINEL_POLICY.firewall,
    rateLimiter: isJsonObject(rawConfig.rateLimiter)
      ? { ...DEFAULT_SENTINEL_POLICY.rateLimiter, ...(rawConfig.rateLimiter as Partial<SentinelPolicy['rateLimiter']>) }
      : DEFAULT_SENTINEL_POLICY.rateLimiter,
    circuitBreaker: isJsonObject(rawConfig.circuitBreaker)
      ? { ...DEFAULT_SENTINEL_POLICY.circuitBreaker, ...(rawConfig.circuitBreaker as Partial<SentinelPolicy['circuitBreaker']>) }
      : DEFAULT_SENTINEL_POLICY.circuitBreaker,
    idempotency: isJsonObject(rawConfig.idempotency)
      ? { ...DEFAULT_SENTINEL_POLICY.idempotency, ...(rawConfig.idempotency as Partial<SentinelPolicy['idempotency']>) }
      : DEFAULT_SENTINEL_POLICY.idempotency,
    schemaLock: isJsonObject(rawConfig.schemaLock)
      ? { ...DEFAULT_SENTINEL_POLICY.schemaLock, ...(rawConfig.schemaLock as Partial<SentinelPolicy['schemaLock']>) }
      : DEFAULT_SENTINEL_POLICY.schemaLock,
    injectionShield: isJsonObject(rawConfig.injectionShield)
      ? { ...DEFAULT_SENTINEL_POLICY.injectionShield, ...(rawConfig.injectionShield as Partial<SentinelPolicy['injectionShield']>) }
      : DEFAULT_SENTINEL_POLICY.injectionShield,
    deception: isJsonObject(rawConfig.deception)
      ? { ...DEFAULT_SENTINEL_POLICY.deception, ...(rawConfig.deception as Partial<SentinelPolicy['deception']>) }
      : DEFAULT_SENTINEL_POLICY.deception,
    lattice: isJsonObject(rawConfig.lattice)
      ? { ...DEFAULT_SENTINEL_POLICY.lattice, ...(rawConfig.lattice as Partial<SentinelPolicy['lattice']>) }
      : DEFAULT_SENTINEL_POLICY.lattice,
    intelligence: isJsonObject(rawConfig.intelligence)
      ? { ...DEFAULT_SENTINEL_POLICY.intelligence, ...(rawConfig.intelligence as Partial<SentinelPolicy['intelligence']>) }
      : DEFAULT_SENTINEL_POLICY.intelligence,
    vault: isJsonObject(rawConfig.vault)
      ? { ...DEFAULT_SENTINEL_POLICY.vault, ...(rawConfig.vault as Partial<SentinelPolicy['vault']>) }
      : DEFAULT_SENTINEL_POLICY.vault,
    ledger: isJsonObject(rawConfig.ledger)
      ? { ...DEFAULT_SENTINEL_POLICY.ledger, ...(rawConfig.ledger as Partial<SentinelPolicy['ledger']>) }
      : DEFAULT_SENTINEL_POLICY.ledger,
    hitl: isJsonObject(rawConfig.hitl)
      ? { ...DEFAULT_SENTINEL_POLICY.hitl, ...(rawConfig.hitl as Partial<SentinelPolicy['hitl']>) }
      : DEFAULT_SENTINEL_POLICY.hitl,
    forensics: isJsonObject(rawConfig.forensics)
      ? { ...DEFAULT_SENTINEL_POLICY.forensics, ...(rawConfig.forensics as Partial<SentinelPolicy['forensics']>) }
      : DEFAULT_SENTINEL_POLICY.forensics,
    telemetry: isJsonObject(rawConfig.telemetry)
      ? { ...DEFAULT_SENTINEL_POLICY.telemetry, ...(rawConfig.telemetry as Partial<SentinelPolicy['telemetry']>) }
      : DEFAULT_SENTINEL_POLICY.telemetry,
    macaroons: isJsonObject(rawConfig.macaroons)
      ? { ...DEFAULT_SENTINEL_POLICY.macaroons, ...(rawConfig.macaroons as Partial<SentinelPolicy['macaroons']>) }
      : DEFAULT_SENTINEL_POLICY.macaroons,
  };

  return ok(merged);
}

/**
 * SentinelKernel: Deterministic 11-Stage Zero-Trust Runtime Security Mesh
 * and FinOps Firewall for MCP & AI Agents.
 */
export class SentinelKernel {
  public readonly policy: SentinelPolicy;
  public readonly clock: Clock;
  public readonly killSwitch: KillSwitch;
  public readonly schemaLock: SchemaLockGuard;
  public readonly injectionShield: InjectionShield;
  public readonly mirage: MirageDeceptionEngine;
  public readonly watermarks: EpistemicWatermarkEngine;
  public readonly lattice: SecurityLatticeEngine;
  public readonly provenance: ProvenanceDag;
  public readonly simhashLoop: SimHashLoopDetector;
  public readonly markovGraph: MarkovCallGraph;
  public readonly cusumDetector: CusumAnomalyDetector;
  public readonly firewall: PayloadFirewall;
  public readonly rateLimiter: HierarchicalRateLimiter;
  public readonly circuitBreaker: CircuitBreakerRegistry;
  public readonly idempotency: IdempotencyCoalescer<JsonRpcResponse>;
  public readonly hitlGate: HitlApprovalGate;
  public readonly vault: ReversibleContextVault;
  public readonly ledger: MicroUsdLedger;
  public readonly splEngine: SplPolicyEngine;
  public readonly flightRecorder: ForensicFlightRecorder;
  public readonly observability: ObservabilityServer;

  private constructor(deps: {
    readonly policy: SentinelPolicy;
    readonly clock: Clock;
    readonly firewall: PayloadFirewall;
    readonly vault: ReversibleContextVault;
    readonly splEngine: SplPolicyEngine;
    readonly options?: SentinelKernelOptions;
  }) {
    this.policy = deps.policy;
    this.clock = deps.clock;
    this.firewall = deps.firewall;
    this.vault = deps.vault;
    this.splEngine = deps.splEngine;

    this.killSwitch = new KillSwitch(deps.clock);
    this.schemaLock = new SchemaLockGuard(deps.policy.schemaLock);
    this.injectionShield = new InjectionShield(deps.policy.injectionShield);
    this.mirage = new MirageDeceptionEngine(deps.policy.deception);
    this.watermarks = new EpistemicWatermarkEngine(deps.policy.deception);
    this.lattice = new SecurityLatticeEngine(deps.policy.lattice);
    this.provenance = new ProvenanceDag(deps.clock);
    this.simhashLoop = new SimHashLoopDetector(deps.policy.intelligence);
    this.markovGraph = new MarkovCallGraph(deps.policy.intelligence, {
      ...(deps.options?.forbiddenMarkovEdges !== undefined
        ? { forbiddenEdges: deps.options.forbiddenMarkovEdges }
        : {}),
      ...(deps.options?.seedMarkovTransitions !== undefined
        ? { seedTransitions: deps.options.seedMarkovTransitions }
        : {}),
    });
    this.cusumDetector = new CusumAnomalyDetector(deps.policy.intelligence);
    this.rateLimiter = new HierarchicalRateLimiter(deps.policy.rateLimiter, deps.clock);
    this.circuitBreaker = new CircuitBreakerRegistry(deps.policy.circuitBreaker, deps.clock);
    this.idempotency = new IdempotencyCoalescer<JsonRpcResponse>(
      deps.policy.idempotency,
      deps.clock,
    );
    this.hitlGate = new HitlApprovalGate(
      deps.policy.hitl,
      deps.clock,
      deps.options?.hitlTransport,
    );
    this.ledger = new MicroUsdLedger(deps.policy.ledger, deps.clock);
    this.flightRecorder =
      deps.options?.flightRecorder ??
      new ForensicFlightRecorder(deps.policy.forensics, deps.clock);
    this.observability =
      deps.options?.observability ?? new ObservabilityServer(deps.policy.telemetry, deps.clock);
  }

  public static create(
    policy: SentinelPolicy = DEFAULT_SENTINEL_POLICY,
    options?: SentinelKernelOptions,
  ): Result<SentinelKernel, SentinelError> {
    const clock = options?.clock ?? new SystemClock();

    const firewallRes = PayloadFirewall.create(policy.firewall);
    if (!firewallRes.ok) {
      return firewallRes;
    }

    const vaultRes = ReversibleContextVault.create(policy.vault, clock);
    if (!vaultRes.ok) {
      return vaultRes;
    }

    const splRes = SplPolicyEngine.compile(policy.splRules, policy.maxVmGas);
    if (!splRes.ok) {
      return splRes;
    }

    return ok(
      new SentinelKernel({
        policy,
        clock,
        firewall: firewallRes.value,
        vault: vaultRes.value,
        splEngine: splRes.value,
        ...(options !== undefined ? { options } : {}),
      }),
    );
  }

  /**
   * Processes any MCP JSON-RPC 2.0 request through the Sentinel Zero-Trust pipeline.
   */
  public async handleRequest(
    request: JsonRpcRequest,
    upstream: UpstreamMcpHandler,
  ): Promise<JsonRpcResponse> {
    if (request.method === 'tools/list') {
      return this.handleToolsList(request, upstream);
    }
    if (request.method === 'tools/call') {
      return this.handleToolsCall(request, upstream);
    }
    return this.handleGenericPassthrough(request, upstream);
  }

  private emitAudit(
    params: {
      readonly requestId: string;
      readonly traceparent: string;
      readonly tenantId: string;
      readonly sessionId: string;
      readonly method: string;
      readonly toolName?: string;
      readonly outcome: AuditDecisionOutcome;
      readonly stage: string;
      readonly startedAtMicros: bigint;
      readonly estimatedMicroUsd: number;
      readonly settledMicroUsd: number;
      readonly sanitizedArgs?: JsonObject;
      readonly sentinelError?: SentinelError;
      readonly reason?: string;
      readonly pseudonymizedCount?: number;
    },
  ): ForensicAuditRecord | null {
    const elapsedMicros = Number(
      this.clock.nowMicros() >= params.startedAtMicros
        ? this.clock.nowMicros() - params.startedAtMicros
        : 0n,
    );
    const label = this.lattice.getSessionLabel(params.sessionId);

    const recRes = this.flightRecorder.record({
      requestId: params.requestId,
      traceparent: params.traceparent,
      tenantId: params.tenantId,
      sessionId: params.sessionId,
      method: params.method,
      mode: this.policy.mode,
      outcome: params.outcome,
      stage: params.stage,
      latencyMicros: elapsedMicros,
      estimatedMicroUsd: params.estimatedMicroUsd,
      settledMicroUsd: params.settledMicroUsd,
      confidentiality: label.confidentiality,
      integrity: label.integrity,
      ...(params.toolName !== undefined ? { toolName: params.toolName } : {}),
      ...(params.sanitizedArgs !== undefined ? { sanitizedArgs: params.sanitizedArgs } : {}),
      ...(params.sentinelError !== undefined
        ? {
            errorCode: params.sentinelError.code,
            errorName: params.sentinelError.name,
            reason: params.sentinelError.message,
          }
        : {}),
      ...(params.reason !== undefined && params.sentinelError === undefined
        ? { reason: params.reason }
        : {}),
    });

    if (!recRes.ok) {
      return null;
    }

    this.observability.recordAuditEvent(recRes.value, {
      ...(params.pseudonymizedCount !== undefined
        ? { pseudonymizedCount: params.pseudonymizedCount }
        : {}),
      activeLockdowns: this.killSwitch.listActiveLockdowns().length,
      merkleTreeSize: this.flightRecorder.getTreeSize(),
    });

    return recRes.value;
  }

  private async handleToolsList(
    request: JsonRpcRequest,
    upstream: UpstreamMcpHandler,
  ): Promise<JsonRpcResponse> {
    const meta = isJsonObject(request.params?._meta) ? request.params._meta : undefined;
    const ctx = createExecutionContext(this.clock, {
      jsonRpcId: request.id,
      method: request.method,
      mode: this.policy.mode,
      ...(meta !== undefined ? { meta } : {}),
    });
    const traceparent = formatTraceparent(ctx.trace);

    if (this.policy.mode !== 'AUDIT_ONLY') {
      const lockCheck = this.killSwitch.assertPermitted(ctx.tenantId, ctx.sessionId);
      if (!lockCheck.ok && this.policy.mode === 'ENFORCE') {
        this.emitAudit({
          requestId: ctx.requestId,
          traceparent,
          tenantId: ctx.tenantId,
          sessionId: ctx.sessionId,
          method: ctx.method,
          outcome: 'BLOCKED',
          stage: lockCheck.error.stage,
          startedAtMicros: ctx.startedAtMicros,
          estimatedMicroUsd: 0,
          settledMicroUsd: 0,
          sentinelError: lockCheck.error,
        });
        return createJsonRpcErrorResponse(request.id, toJsonRpcErrorObject(lockCheck.error));
      }
    }

    let upstreamResp: JsonRpcResponse;
    try {
      upstreamResp = await upstream(request);
    } catch (cause: unknown) {
      const detail = cause instanceof Error ? cause.message : String(cause);
      const upstreamErr = createSentinelError(
        'INTERNAL_ERROR',
        `Upstream tools/list failed: ${detail}`,
        'upstream-transport',
      );
      this.emitAudit({
        requestId: ctx.requestId,
        traceparent,
        tenantId: ctx.tenantId,
        sessionId: ctx.sessionId,
        method: ctx.method,
        outcome: 'UPSTREAM_ERROR',
        stage: 'upstream-transport',
        startedAtMicros: ctx.startedAtMicros,
        estimatedMicroUsd: 0,
        settledMicroUsd: 0,
        sentinelError: upstreamErr,
      });
      return createJsonRpcErrorResponse(request.id, toJsonRpcErrorObject(upstreamErr));
    }

    if ('error' in upstreamResp || !isMcpToolsListResult(upstreamResp.result)) {
      this.emitAudit({
        requestId: ctx.requestId,
        traceparent,
        tenantId: ctx.tenantId,
        sessionId: ctx.sessionId,
        method: ctx.method,
        outcome: 'error' in upstreamResp ? 'UPSTREAM_ERROR' : 'ALLOWED',
        stage: 'tools-list',
        startedAtMicros: ctx.startedAtMicros,
        estimatedMicroUsd: 0,
        settledMicroUsd: 0,
      });
      return upstreamResp;
    }

    const schemaCheck = this.schemaLock.verifyAndSanitizeToolsList(upstreamResp.result);
    if (!schemaCheck.ok) {
      if (this.policy.mode === 'ENFORCE') {
        this.emitAudit({
          requestId: ctx.requestId,
          traceparent,
          tenantId: ctx.tenantId,
          sessionId: ctx.sessionId,
          method: ctx.method,
          outcome: 'BLOCKED',
          stage: schemaCheck.error.stage,
          startedAtMicros: ctx.startedAtMicros,
          estimatedMicroUsd: 0,
          settledMicroUsd: 0,
          sentinelError: schemaCheck.error,
        });
        return createJsonRpcErrorResponse(request.id, toJsonRpcErrorObject(schemaCheck.error));
      }

      const withDecoys = this.mirage.injectHoneyTools(upstreamResp.result);
      this.emitAudit({
        requestId: ctx.requestId,
        traceparent,
        tenantId: ctx.tenantId,
        sessionId: ctx.sessionId,
        method: ctx.method,
        outcome: 'SHADOW_FLAGGED',
        stage: schemaCheck.error.stage,
        startedAtMicros: ctx.startedAtMicros,
        estimatedMicroUsd: 0,
        settledMicroUsd: 0,
        sentinelError: schemaCheck.error,
      });
      return createJsonRpcSuccessResponse(request.id, withDecoys as unknown as JsonValue);
    }

    const finalToolsList = this.mirage.injectHoneyTools(schemaCheck.value.sanitizedResult);
    this.emitAudit({
      requestId: ctx.requestId,
      traceparent,
      tenantId: ctx.tenantId,
      sessionId: ctx.sessionId,
      method: ctx.method,
      outcome: 'ALLOWED',
      stage: 'schema-lock',
      startedAtMicros: ctx.startedAtMicros,
      estimatedMicroUsd: 0,
      settledMicroUsd: 0,
    });

    return createJsonRpcSuccessResponse(request.id, finalToolsList as unknown as JsonValue);
  }

  private async handleToolsCall(
    request: JsonRpcRequest,
    upstream: UpstreamMcpHandler,
  ): Promise<JsonRpcResponse> {
    if (!isToolsCallParams(request.params)) {
      const paramErr = createSentinelError(
        'INVALID_PARAMS',
        'Invalid MCP tools/call parameters: expected { name: string, arguments?: object }',
        'jsonrpc-validation',
      );
      return createJsonRpcErrorResponse(request.id, toJsonRpcErrorObject(paramErr));
    }

    const toolName = request.params.name.trim();
    const rawArgs: JsonObject = request.params.arguments ?? {};
    const meta = isJsonObject(request.params._meta) ? request.params._meta : undefined;
    const capField = this.policy.macaroons.metadataField;
    const macaroonToken =
      meta !== undefined && typeof meta[capField] === 'string'
        ? (meta[capField] as string)
        : undefined;

    const ctx = createExecutionContext(this.clock, {
      jsonRpcId: request.id,
      method: request.method,
      toolName,
      mode: this.policy.mode,
      ...(meta !== undefined ? { meta } : {}),
      ...(macaroonToken !== undefined ? { macaroonToken } : {}),
    });
    const traceparent = formatTraceparent(ctx.trace);

    // Sanitize preview of outbound arguments so forensic logs never store accidental raw secrets
    const outboundPreview = this.vault.pseudonymizeInbound({
      tenantId: ctx.tenantId,
      sessionId: ctx.sessionId,
      payload: rawArgs,
    });
    const auditSafeArgs = isJsonObject(outboundPreview.sanitizedPayload)
      ? outboundPreview.sanitizedPayload
      : {};

    const preEstimate = estimatePreCallMicroUsd(toolName, rawArgs, this.policy.ledger);
    const shadowFailures: SentinelError[] = [];

    const failOrShadow = (guardError: SentinelError): JsonRpcResponse | null => {
      if (this.policy.mode === 'ENFORCE') {
        this.emitAudit({
          requestId: ctx.requestId,
          traceparent,
          tenantId: ctx.tenantId,
          sessionId: ctx.sessionId,
          method: ctx.method,
          toolName,
          outcome: 'BLOCKED',
          stage: guardError.stage,
          startedAtMicros: ctx.startedAtMicros,
          estimatedMicroUsd: preEstimate.estimatedMicroUsd,
          settledMicroUsd: 0,
          sanitizedArgs: auditSafeArgs,
          sentinelError: guardError,
        });
        return createJsonRpcErrorResponse(request.id, toJsonRpcErrorObject(guardError));
      }
      if (this.policy.mode === 'SHADOW') {
        shadowFailures.push(guardError);
      }
      return null;
    };

    if (this.policy.mode !== 'AUDIT_ONLY') {
      // Stage 1: Emergency Kill-Switch Quarantine
      const lockCheck = this.killSwitch.assertPermitted(ctx.tenantId, ctx.sessionId);
      if (!lockCheck.ok) {
        const early = failOrShadow(lockCheck.error);
        if (early !== null) return early;
      }

      // Stage 2: Mirage Honey-Tool Active Deception Trap
      if (this.mirage.isHoneyTool(toolName)) {
        const trap = this.mirage.triggerHoneyTrap({
          toolName,
          args: auditSafeArgs,
          tenantId: ctx.tenantId,
          sessionId: ctx.sessionId,
        });
        if (this.policy.mode === 'ENFORCE') {
          this.killSwitch.lockSession(ctx.sessionId, {
            reason: trap.error.message,
            triggeredByStage: 'mirage-deception',
            evidence: { honeyTool: toolName, argumentsDigestHex: trap.argumentsDigestHex },
          });
          const early = failOrShadow(trap.error);
          if (early !== null) return early;
        }
        // In SHADOW mode, return realistic canary-laced decoy without hitting upstream
        this.emitAudit({
          requestId: ctx.requestId,
          traceparent,
          tenantId: ctx.tenantId,
          sessionId: ctx.sessionId,
          method: ctx.method,
          toolName,
          outcome: 'SHADOW_FLAGGED',
          stage: trap.error.stage,
          startedAtMicros: ctx.startedAtMicros,
          estimatedMicroUsd: 0,
          settledMicroUsd: 0,
          sanitizedArgs: auditSafeArgs,
          sentinelError: trap.error,
        });
        return createJsonRpcSuccessResponse(
          request.id,
          trap.decoyShadowResult as unknown as JsonValue,
        );
      }

      // Stage 3: HMAC-SHA256 Attenuated Capability Macaroon Verification
      if (this.policy.macaroons.enabled) {
        if (!this.policy.macaroons.rootKeyHex || ctx.macaroonToken === undefined) {
          const missingCap = createSentinelError(
            'CAPABILITY_DENIED',
            `Missing required capability Macaroon in _meta.${capField}`,
            'macaroon-verify',
            { toolName },
          );
          const early = failOrShadow(missingCap);
          if (early !== null) return early;
        } else {
          const capRes = verifyMacaroon(
            this.policy.macaroons.rootKeyHex,
            ctx.macaroonToken,
            {
              method: ctx.method,
              toolName,
              tenantId: ctx.tenantId,
              sessionId: ctx.sessionId,
              args: rawArgs,
              estimatedCallMicroUsd: preEstimate.estimatedMicroUsd,
              sessionSpentMicroUsd: this.ledger.getSessionExposureMicroUsd(
                ctx.tenantId,
                ctx.sessionId,
              ),
              sessionConfidentiality: this.lattice.getSessionLabel(ctx.sessionId).confidentiality,
            },
            this.clock,
          );
          if (!capRes.ok) {
            const early = failOrShadow(capRes.error);
            if (early !== null) return early;
          }
        }
      }

      // Stage 4: Bell-LaPadula x Biba Dual Security Lattice Pre-Call Flow
      const latticeRes = this.lattice.checkPreCallFlow(ctx.sessionId, toolName);
      if (!latticeRes.ok) {
        const blameHops =
          latticeRes.error.metadata?.violationType === 'CONFIDENTIALITY_NO_WRITE_DOWN'
            ? this.provenance.explainConfidentialityBlame(ctx.sessionId, 'CONFIDENTIAL')
            : this.provenance.explainIntegrityTaintBlame(ctx.sessionId, 'UNTRUSTED');
        const enrichedLatticeErr = createSentinelError(
          latticeRes.error.name,
          latticeRes.error.message,
          latticeRes.error.stage,
          {
            ...(latticeRes.error.metadata ?? {}),
            causalBlameTools: blameHops.map((h) => h.toolName),
          },
        );
        const early = failOrShadow(enrichedLatticeErr);
        if (early !== null) return early;
      }

      // Stage 5: Epistemic Canary Honeytoken Exfiltration Tripwire
      const canaryCheck = this.watermarks.assertNoCanaryExfiltration(rawArgs);
      if (!canaryCheck.ok) {
        if (this.policy.mode === 'ENFORCE') {
          this.killSwitch.lockSession(ctx.sessionId, {
            reason: canaryCheck.error.message,
            triggeredByStage: 'epistemic-watermark',
          });
        }
        const early = failOrShadow(canaryCheck.error);
        if (early !== null) return early;
      }

      // Stage 6: Zero-Trust Payload/SSRF Firewall, Rate Limiter & Circuit Breaker
      const fwRes = this.firewall.inspectToolCall(toolName, rawArgs);
      if (!fwRes.ok) {
        const early = failOrShadow(fwRes.error);
        if (early !== null) return early;
      }

      const rlRes = this.rateLimiter.acquire(ctx.tenantId, ctx.sessionId, toolName);
      if (!rlRes.ok) {
        const early = failOrShadow(rlRes.error);
        if (early !== null) return early;
      }

      const cbRes = this.circuitBreaker.beforeCall(toolName);
      if (!cbRes.ok) {
        const early = failOrShadow(cbRes.error);
        if (early !== null) return early;
      }

      // Stage 7: Behavioral Intelligence (64-bit SimHash Loop, Markov Graph & CUSUM/Z-Score)
      const loopRes = this.simhashLoop.evaluateAndRecord(ctx.sessionId, toolName, rawArgs);
      if (!loopRes.ok) {
        const early = failOrShadow(loopRes.error);
        if (early !== null) return early;
      }

      const markovRes = this.markovGraph.evaluateAndAdvance(ctx.sessionId, toolName);
      if (!markovRes.ok) {
        const early = failOrShadow(markovRes.error);
        if (early !== null) return early;
      }

      const cusumRes = this.cusumDetector.checkProjectedSpend(
        ctx.sessionId,
        preEstimate.estimatedMicroUsd,
      );
      if (!cusumRes.ok) {
        const early = failOrShadow(cusumRes.error);
        if (early !== null) return early;
      }

      // Stage 8: SPL Stack Bytecode VM & Cryptographic HITL Webhook Gate
      const classification = this.lattice.resolveToolClassification(toolName);
      const currentLabel = this.lattice.getSessionLabel(ctx.sessionId);
      const splVerdict = this.splEngine.evaluate({
        method: ctx.method,
        toolName,
        args: rawArgs,
        tenantId: ctx.tenantId,
        sessionId: ctx.sessionId,
        confidentiality: currentLabel.confidentiality,
        integrity: currentLabel.integrity,
        taintLabels: this.lattice.getSessionTaintTags(ctx.sessionId),
        toolCategories: classification.categories,
        sessionSpentMicroUsd: this.ledger.getSessionExposureMicroUsd(ctx.tenantId, ctx.sessionId),
        estimatedCallMicroUsd: preEstimate.estimatedMicroUsd,
        payloadBytes: preEstimate.inputBytes,
      });

      if (!splVerdict.ok) {
        const early = failOrShadow(splVerdict.error);
        if (early !== null) return early;
      } else if (splVerdict.value.action === 'DENY') {
        const denyErr = createSentinelError(
          'POLICY_VIOLATION',
          `SPL rule "${splVerdict.value.matchedRuleId ?? 'deny'}" denied call to "${toolName}"${splVerdict.value.description ? `: ${splVerdict.value.description}` : ''}`,
          'spl-policy-vm',
          {
            ruleId: splVerdict.value.matchedRuleId ?? null,
            gasUsed: splVerdict.value.totalGasUsed,
          },
        );
        const early = failOrShadow(denyErr);
        if (early !== null) return early;
      } else if (this.policy.mode === 'ENFORCE') {
        const hitlRes = await this.hitlGate.checkOrRequestApproval({
          requestId: ctx.requestId,
          tenantId: ctx.tenantId,
          sessionId: ctx.sessionId,
          toolName,
          sanitizedArguments: auditSafeArgs,
          estimatedMicroUsd: preEstimate.estimatedMicroUsd,
          splAction: splVerdict.value.action,
          ...(splVerdict.value.matchedRuleId !== undefined
            ? { splRuleId: splVerdict.value.matchedRuleId }
            : {}),
        });
        if (!hitlRes.ok) {
          const early = failOrShadow(hitlRes.error);
          if (early !== null) return early;
        }
      }
    }

    // Stage 9: Conditional Lattice Vault Detokenization & 2-Phase Micro-USD RESERVE
    const resolvedClassification = this.lattice.resolveToolClassification(toolName);
    let effectiveOutboundArgs: JsonObject = rawArgs;

    const detokRes = this.vault.detokenizeOutboundConditional({
      tenantId: ctx.tenantId,
      sessionId: ctx.sessionId,
      toolName,
      args: rawArgs,
      targetMaxSinkConfidentiality: resolvedClassification.maxSinkConfidentiality,
    });

    if (!detokRes.ok) {
      const early = failOrShadow(detokRes.error);
      if (early !== null) return early;
    } else {
      effectiveOutboundArgs = detokRes.value.detokenizedArgs;
    }

    const reservationRes = this.ledger.reserve({
      tenantId: ctx.tenantId,
      sessionId: ctx.sessionId,
      toolName,
      estimatedMicroUsd: preEstimate.estimatedMicroUsd,
    });

    if (!reservationRes.ok) {
      if (this.policy.mode === 'ENFORCE') {
        const early = failOrShadow(reservationRes.error);
        if (early !== null) return early;
      }
      shadowFailures.push(reservationRes.error);
    }

    const reservationId = reservationRes.ok ? reservationRes.value.reservationId : null;

    const outboundRequest: JsonRpcRequest = {
      jsonrpc: '2.0',
      id: request.id,
      method: request.method,
      params: {
        ...request.params,
        name: toolName,
        arguments: effectiveOutboundArgs,
        _meta: {
          ...(meta ?? {}),
          traceparent,
        },
      },
    };

    // Stage 10: Idempotent Coalesced Upstream Execution
    const coalescedRes = await this.idempotency.executeOrCoalesce(
      {
        tenantId: ctx.tenantId,
        sessionId: ctx.sessionId,
        method: ctx.method,
        toolName,
        args: rawArgs,
      },
      async (): Promise<Result<JsonRpcResponse, SentinelError>> => {
        try {
          const resp = await upstream(outboundRequest);
          return ok(resp);
        } catch (cause: unknown) {
          const detail = cause instanceof Error ? cause.message : String(cause);
          return err(
            createSentinelError(
              'INTERNAL_ERROR',
              `Upstream MCP server execution failed on "${toolName}": ${detail}`,
              'upstream-transport',
              { toolName },
            ),
          );
        }
      },
    );

    if (!coalescedRes.ok) {
      if (reservationId !== null) {
        this.ledger.rollback(reservationId);
      }
      this.circuitBreaker.recordFailure(toolName);
      const digestRes = this.idempotency.computeKey({
        tenantId: ctx.tenantId,
        sessionId: ctx.sessionId,
        method: ctx.method,
        toolName,
        args: rawArgs,
      });
      if (digestRes.ok) {
        this.simhashLoop.markLastCallFailed(ctx.sessionId, digestRes.value);
      }

      this.emitAudit({
        requestId: ctx.requestId,
        traceparent,
        tenantId: ctx.tenantId,
        sessionId: ctx.sessionId,
        method: ctx.method,
        toolName,
        outcome: 'UPSTREAM_ERROR',
        stage: coalescedRes.error.stage,
        startedAtMicros: ctx.startedAtMicros,
        estimatedMicroUsd: preEstimate.estimatedMicroUsd,
        settledMicroUsd: 0,
        sanitizedArgs: auditSafeArgs,
        sentinelError: coalescedRes.error,
      });
      return createJsonRpcErrorResponse(request.id, toJsonRpcErrorObject(coalescedRes.error));
    }

    const { value: upstreamResponse, source: executionSource } = coalescedRes.value;

    if (executionSource === 'CACHE_HIT') {
      if (reservationId !== null) {
        this.ledger.rollback(reservationId);
      }
      this.emitAudit({
        requestId: ctx.requestId,
        traceparent,
        tenantId: ctx.tenantId,
        sessionId: ctx.sessionId,
        method: ctx.method,
        toolName,
        outcome: 'CACHE_HIT',
        stage: 'idempotency-coalescer',
        startedAtMicros: ctx.startedAtMicros,
        estimatedMicroUsd: preEstimate.estimatedMicroUsd,
        settledMicroUsd: 0,
        sanitizedArgs: auditSafeArgs,
      });
      return 'result' in upstreamResponse
        ? createJsonRpcSuccessResponse(request.id, upstreamResponse.result)
        : createJsonRpcErrorResponse(request.id, upstreamResponse.error);
    }

    if ('error' in upstreamResponse) {
      if (reservationId !== null) {
        this.ledger.rollback(reservationId);
      }
      this.circuitBreaker.recordFailure(toolName);
      this.emitAudit({
        requestId: ctx.requestId,
        traceparent,
        tenantId: ctx.tenantId,
        sessionId: ctx.sessionId,
        method: ctx.method,
        toolName,
        outcome: 'UPSTREAM_ERROR',
        stage: 'upstream-rpc-error',
        startedAtMicros: ctx.startedAtMicros,
        estimatedMicroUsd: preEstimate.estimatedMicroUsd,
        settledMicroUsd: 0,
        sanitizedArgs: auditSafeArgs,
        reason: upstreamResponse.error.message,
      });
      return createJsonRpcErrorResponse(request.id, upstreamResponse.error);
    }

    // Stage 11: Inbound Injection Shield, Reversible Vault Pseudonymization, Lattice Update & Ledger COMMIT
    this.circuitBreaker.recordSuccess(toolName);

    const shieldRes = this.injectionShield.inspectAndSanitize(upstreamResponse.result);
    if (!shieldRes.ok) {
      if (reservationId !== null) {
        this.ledger.rollback(reservationId);
      }
      if (this.policy.mode === 'ENFORCE') {
        this.lattice.degradeIntegrity(ctx.sessionId, 'UNTRUSTED', `injection:${toolName}`);
        this.emitAudit({
          requestId: ctx.requestId,
          traceparent,
          tenantId: ctx.tenantId,
          sessionId: ctx.sessionId,
          method: ctx.method,
          toolName,
          outcome: 'BLOCKED',
          stage: shieldRes.error.stage,
          startedAtMicros: ctx.startedAtMicros,
          estimatedMicroUsd: preEstimate.estimatedMicroUsd,
          settledMicroUsd: 0,
          sanitizedArgs: auditSafeArgs,
          sentinelError: shieldRes.error,
        });
        return createJsonRpcErrorResponse(request.id, toJsonRpcErrorObject(shieldRes.error));
      }
      shadowFailures.push(shieldRes.error);
    }

    const postShieldPayload = shieldRes.ok ? shieldRes.value.sanitizedPayload : upstreamResponse.result;
    if (shieldRes.ok && shieldRes.value.findings.length > 0) {
      this.lattice.degradeIntegrity(ctx.sessionId, 'UNTRUSTED', `inbound_injection:${toolName}`);
    }

    const inboundVaultReport = this.vault.pseudonymizeInbound({
      tenantId: ctx.tenantId,
      sessionId: ctx.sessionId,
      payload: postShieldPayload,
      minimumOriginConfidentiality: resolvedClassification.readConfidentiality,
    });

    const updatedLabel = this.lattice.recordPostCallObservation(ctx.sessionId, toolName);
    if (inboundVaultReport.highestConfidentiality !== null) {
      this.lattice.elevateConfidentiality(
        ctx.sessionId,
        inboundVaultReport.highestConfidentiality,
        `vault_pii:${toolName}`,
      );
    }

    this.provenance.recordHop({
      sessionId: ctx.sessionId,
      toolName,
      labelApplied: this.lattice.getSessionLabel(ctx.sessionId),
      payloadSample: {
        pseudonymizedCount: inboundVaultReport.pseudonymizedCount,
        baseLabel: updatedLabel,
      },
    });

    const costBreakdown = calculateActualCallMicroUsd(
      toolName,
      effectiveOutboundArgs,
      inboundVaultReport.sanitizedPayload,
      this.policy.ledger,
    );

    const settledMicroUsd =
      executionSource === 'COALESCED_IN_FLIGHT' ? 0 : costBreakdown.actualMicroUsd;

    if (reservationId !== null) {
      if (executionSource === 'COALESCED_IN_FLIGHT') {
        this.ledger.rollback(reservationId);
      } else {
        this.ledger.commit(reservationId, settledMicroUsd);
        this.cusumDetector.recordActualSpend(ctx.sessionId, settledMicroUsd);
      }
    }

    const firstShadowFailure = shadowFailures[0];
    const finalOutcome: AuditDecisionOutcome =
      firstShadowFailure !== undefined ? 'SHADOW_FLAGGED' : 'ALLOWED';

    this.emitAudit({
      requestId: ctx.requestId,
      traceparent,
      tenantId: ctx.tenantId,
      sessionId: ctx.sessionId,
      method: ctx.method,
      toolName,
      outcome: finalOutcome,
      stage: firstShadowFailure !== undefined ? firstShadowFailure.stage : 'completed',
      startedAtMicros: ctx.startedAtMicros,
      estimatedMicroUsd: preEstimate.estimatedMicroUsd,
      settledMicroUsd,
      sanitizedArgs: auditSafeArgs,
      pseudonymizedCount: inboundVaultReport.pseudonymizedCount,
      ...(firstShadowFailure !== undefined ? { sentinelError: firstShadowFailure } : {}),
    });

    return createJsonRpcSuccessResponse(request.id, inboundVaultReport.sanitizedPayload);
  }

  private async handleGenericPassthrough(
    request: JsonRpcRequest,
    upstream: UpstreamMcpHandler,
  ): Promise<JsonRpcResponse> {
    const meta = isJsonObject(request.params?._meta) ? request.params._meta : undefined;
    const ctx = createExecutionContext(this.clock, {
      jsonRpcId: request.id,
      method: request.method,
      mode: this.policy.mode,
      ...(meta !== undefined ? { meta } : {}),
    });
    const traceparent = formatTraceparent(ctx.trace);

    if (this.policy.mode === 'ENFORCE') {
      const lockCheck = this.killSwitch.assertPermitted(ctx.tenantId, ctx.sessionId);
      if (!lockCheck.ok) {
        this.emitAudit({
          requestId: ctx.requestId,
          traceparent,
          tenantId: ctx.tenantId,
          sessionId: ctx.sessionId,
          method: ctx.method,
          outcome: 'BLOCKED',
          stage: lockCheck.error.stage,
          startedAtMicros: ctx.startedAtMicros,
          estimatedMicroUsd: 0,
          settledMicroUsd: 0,
          sentinelError: lockCheck.error,
        });
        return createJsonRpcErrorResponse(request.id, toJsonRpcErrorObject(lockCheck.error));
      }
    }

    try {
      const response = await upstream(request);
      if ('result' in response && request.method === 'resources/read') {
        const shieldRes = this.injectionShield.inspectAndSanitize(response.result);
        const payload = shieldRes.ok ? shieldRes.value.sanitizedPayload : response.result;
        const vaulted = this.vault.pseudonymizeInbound({
          tenantId: ctx.tenantId,
          sessionId: ctx.sessionId,
          payload,
        });
        this.emitAudit({
          requestId: ctx.requestId,
          traceparent,
          tenantId: ctx.tenantId,
          sessionId: ctx.sessionId,
          method: ctx.method,
          outcome: 'ALLOWED',
          stage: 'resources-read',
          startedAtMicros: ctx.startedAtMicros,
          estimatedMicroUsd: 0,
          settledMicroUsd: 0,
          pseudonymizedCount: vaulted.pseudonymizedCount,
        });
        return createJsonRpcSuccessResponse(request.id, vaulted.sanitizedPayload);
      }

      this.emitAudit({
        requestId: ctx.requestId,
        traceparent,
        tenantId: ctx.tenantId,
        sessionId: ctx.sessionId,
        method: ctx.method,
        outcome: 'error' in response ? 'UPSTREAM_ERROR' : 'ALLOWED',
        stage: 'passthrough',
        startedAtMicros: ctx.startedAtMicros,
        estimatedMicroUsd: 0,
        settledMicroUsd: 0,
      });
      return response;
    } catch (cause: unknown) {
      const detail = cause instanceof Error ? cause.message : String(cause);
      const transportErr = createSentinelError(
        'INTERNAL_ERROR',
        `Upstream error on "${request.method}": ${detail}`,
        'upstream-transport',
      );
      this.emitAudit({
        requestId: ctx.requestId,
        traceparent,
        tenantId: ctx.tenantId,
        sessionId: ctx.sessionId,
        method: ctx.method,
        outcome: 'UPSTREAM_ERROR',
        stage: 'upstream-transport',
        startedAtMicros: ctx.startedAtMicros,
        estimatedMicroUsd: 0,
        settledMicroUsd: 0,
        sentinelError: transportErr,
      });
      return createJsonRpcErrorResponse(request.id, toJsonRpcErrorObject(transportErr));
    }
  }
}
