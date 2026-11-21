import { randomBytes } from 'node:crypto';
import {
  canonicalHashHex,
  canonicalizeJson,
  constantTimeEqualHex,
  hmacSha256Hex,
} from '../core/canonical.js';
import type { Clock } from '../core/clock.js';
import { matchToolGlob } from '../ifc/security-lattice.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import { isJsonObject, type JsonObject } from '../types/jsonrpc.js';
import type { HitlApprovalConfig, PolicyDecisionAction } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';

export interface HitlWebhookRequestEnvelope {
  readonly version: '1.0';
  readonly requestId: string;
  readonly nonce: string;
  readonly timestampMs: number;
  readonly expiresAtMs: number;
  readonly tenantId: string;
  readonly sessionId: string;
  readonly toolName: string;
  readonly argumentsDigestHex: string;
  readonly sanitizedArguments: JsonObject;
  readonly estimatedMicroUsd: number;
  readonly reason: string;
}

export interface HitlWebhookWireResponse {
  readonly status: number;
  readonly bodyText: string;
  readonly signatureHeader?: string;
}

export type HitlWebhookTransport = (params: {
  readonly url: string;
  readonly bodyJson: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly timeoutMs: number;
}) => Promise<HitlWebhookWireResponse>;

export interface HitlApprovalResult {
  readonly required: boolean;
  readonly approvedBy?: string;
  readonly nonce?: string;
  readonly triggerReason?: string;
}

const defaultFetchTransport: HitlWebhookTransport = async ({
  url,
  bodyJson,
  headers,
  timeoutMs,
}) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: bodyJson,
      signal: controller.signal,
    });
    const bodyText = await response.text();
    const sigHeader = response.headers.get('x-sentinel-signature-256');
    return {
      status: response.status,
      bodyText,
      ...(sigHeader !== null ? { signatureHeader: sigHeader } : {}),
    };
  } finally {
    clearTimeout(timer);
  }
};

/**
 * Cryptographic Human-in-the-Loop (HITL) Webhook Approval Gate.
 * Dispatches HMAC-SHA256 signed, nonce-bound approval challenges for high-risk
 * or high-cost MCP tool calls and verifies operator responses in constant time.
 */
export class HitlApprovalGate {
  private readonly config: HitlApprovalConfig;
  private readonly clock: Clock;
  private readonly transport: HitlWebhookTransport;

  public constructor(
    config: HitlApprovalConfig,
    clock: Clock,
    transport: HitlWebhookTransport = defaultFetchTransport,
  ) {
    this.config = config;
    this.clock = clock;
    this.transport = transport;
  }

  public determineTriggerReason(params: {
    readonly splAction: PolicyDecisionAction;
    readonly splRuleId?: string;
    readonly toolName: string;
    readonly estimatedMicroUsd: number;
  }): string | null {
    if (params.splAction === 'REQUIRE_APPROVAL') {
      return `SPL rule "${params.splRuleId ?? 'require_approval'}" mandated human approval`;
    }

    if (!this.config.enabled) {
      return null;
    }

    if (
      this.config.approvalRequiredTools !== undefined &&
      this.config.approvalRequiredTools.some((pattern) => matchToolGlob(pattern, params.toolName))
    ) {
      return `Tool "${params.toolName}" matches approvalRequiredTools policy`;
    }

    if (
      this.config.highCostThresholdMicroUsd !== undefined &&
      params.estimatedMicroUsd >= this.config.highCostThresholdMicroUsd
    ) {
      return `Estimated cost (${params.estimatedMicroUsd} uUSD) reached HITL threshold (${this.config.highCostThresholdMicroUsd} uUSD)`;
    }

    return null;
  }

  public async checkOrRequestApproval(params: {
    readonly requestId: string;
    readonly tenantId: string;
    readonly sessionId: string;
    readonly toolName: string;
    readonly sanitizedArguments: JsonObject;
    readonly estimatedMicroUsd: number;
    readonly splAction: PolicyDecisionAction;
    readonly splRuleId?: string;
  }): Promise<Result<HitlApprovalResult, SentinelError>> {
    const triggerReason = this.determineTriggerReason({
      splAction: params.splAction,
      toolName: params.toolName,
      estimatedMicroUsd: params.estimatedMicroUsd,
      ...(params.splRuleId !== undefined ? { splRuleId: params.splRuleId } : {}),
    });

    if (triggerReason === null) {
      return ok({ required: false });
    }

    if (!this.config.enabled || !this.config.webhookUrl) {
      return err(
        createSentinelError(
          'APPROVAL_REJECTED',
          `Human approval required (${triggerReason}), but no HITL webhook is configured; failing closed`,
          'hitl-approval-gate',
          { toolName: params.toolName, triggerReason },
        ),
      );
    }

    const argsDigestRes = canonicalHashHex(params.sanitizedArguments);
    if (!argsDigestRes.ok) {
      return argsDigestRes;
    }

    const nowMs = this.clock.nowMs();
    const nonce = randomBytes(16).toString('hex');
    const envelope: HitlWebhookRequestEnvelope = {
      version: '1.0',
      requestId: params.requestId,
      nonce,
      timestampMs: nowMs,
      expiresAtMs: nowMs + this.config.timeoutMs,
      tenantId: params.tenantId,
      sessionId: params.sessionId,
      toolName: params.toolName,
      argumentsDigestHex: argsDigestRes.value,
      sanitizedArguments: params.sanitizedArguments,
      estimatedMicroUsd: params.estimatedMicroUsd,
      reason: triggerReason,
    };

    const canonicalBodyRes = canonicalizeJson(envelope);
    if (!canonicalBodyRes.ok) {
      return canonicalBodyRes;
    }
    const bodyJson = canonicalBodyRes.value;

    const headers: Record<string, string> = {
      'content-type': 'application/json',
      'x-sentinel-request-id': params.requestId,
      'x-sentinel-nonce': nonce,
      'x-sentinel-timestamp': String(nowMs),
    };

    if (this.config.hmacSecret !== undefined && this.config.hmacSecret.length > 0) {
      const signingInput = `${nowMs}.${nonce}.${bodyJson}`;
      const sigHex = hmacSha256Hex(this.config.hmacSecret, signingInput);
      headers['x-sentinel-signature-256'] = `sha256=${sigHex}`;
    }

    let wireResponse: HitlWebhookWireResponse;
    try {
      wireResponse = await this.transport({
        url: this.config.webhookUrl,
        bodyJson,
        headers,
        timeoutMs: this.config.timeoutMs,
      });
    } catch (cause: unknown) {
      const message = cause instanceof Error ? cause.message : String(cause);
      return err(
        createSentinelError(
          'APPROVAL_REJECTED',
          `HITL approval webhook failed or timed out after ${this.config.timeoutMs}ms: ${message}`,
          'hitl-approval-gate',
          { toolName: params.toolName, nonce, triggerReason },
        ),
      );
    }

    if (wireResponse.status < 200 || wireResponse.status >= 300) {
      return err(
        createSentinelError(
          'APPROVAL_REJECTED',
          `HITL approval webhook returned non-2xx HTTP status ${wireResponse.status}`,
          'hitl-approval-gate',
          { toolName: params.toolName, httpStatus: wireResponse.status, nonce },
        ),
      );
    }

    // Verify response authenticity when HMAC secret is configured
    if (this.config.hmacSecret !== undefined && this.config.hmacSecret.length > 0) {
      const rawSig = wireResponse.signatureHeader ?? '';
      const providedHex = rawSig.startsWith('sha256=') ? rawSig.slice(7) : rawSig;
      const expectedRespHex = hmacSha256Hex(
        this.config.hmacSecret,
        `${nonce}.${wireResponse.bodyText}`,
      );
      if (!constantTimeEqualHex(expectedRespHex, providedHex)) {
        return err(
          createSentinelError(
            'APPROVAL_REJECTED',
            'HITL webhook response failed constant-time HMAC-SHA256 verification',
            'hitl-approval-gate',
            { toolName: params.toolName, nonce },
          ),
        );
      }
    }

    let parsedBody: unknown;
    try {
      parsedBody = JSON.parse(wireResponse.bodyText);
    } catch {
      return err(
        createSentinelError(
          'APPROVAL_REJECTED',
          'HITL webhook returned malformed JSON decision payload',
          'hitl-approval-gate',
          { toolName: params.toolName, nonce },
        ),
      );
    }

    if (!isJsonObject(parsedBody) || parsedBody.nonce !== nonce) {
      return err(
        createSentinelError(
          'APPROVAL_REJECTED',
          'HITL webhook response nonce mismatch (anti-replay check failed)',
          'hitl-approval-gate',
          { toolName: params.toolName, expectedNonce: nonce },
        ),
      );
    }

    if (parsedBody.approved !== true) {
      const operatorReason =
        typeof parsedBody.reason === 'string' ? parsedBody.reason : 'Denied by human reviewer';
      return err(
        createSentinelError(
          'APPROVAL_REJECTED',
          `Human reviewer rejected "${params.toolName}": ${operatorReason}`,
          'hitl-approval-gate',
          {
            toolName: params.toolName,
            nonce,
            operatorReason,
          },
        ),
      );
    }

    const approvedBy =
      typeof parsedBody.approvedBy === 'string' ? parsedBody.approvedBy : 'verified-webhook';

    return ok({
      required: true,
      approvedBy,
      nonce,
      triggerReason,
    });
  }
}
