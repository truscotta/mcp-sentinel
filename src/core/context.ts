import { randomBytes } from 'node:crypto';
import type { JsonObject, JsonRpcId } from '../types/jsonrpc.js';
import type { ExecutionMode } from '../types/policy.js';
import type { Clock } from './clock.js';

export interface W3CTraceContext {
  readonly version: '00';
  readonly traceId: string;
  readonly spanId: string;
  readonly traceFlags: string;
}

export interface ExecutionContext {
  readonly requestId: string;
  readonly jsonRpcId: JsonRpcId;
  readonly tenantId: string;
  readonly sessionId: string;
  readonly method: string;
  readonly toolName?: string;
  readonly startedAtMs: number;
  readonly startedAtMicros: bigint;
  readonly mode: ExecutionMode;
  readonly trace: W3CTraceContext;
  readonly macaroonToken?: string;
}

export interface CreateExecutionContextInput {
  readonly jsonRpcId: JsonRpcId;
  readonly method: string;
  readonly toolName?: string;
  readonly tenantId?: string;
  readonly sessionId?: string;
  readonly mode: ExecutionMode;
  readonly traceparent?: string;
  readonly macaroonToken?: string;
  readonly meta?: JsonObject;
}

const TRACEPARENT_REGEX = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;

export function parseTraceparent(header: string): W3CTraceContext | null {
  const match = TRACEPARENT_REGEX.exec(header.trim().toLowerCase());
  if (!match) {
    return null;
  }
  const traceId = match[1];
  const spanId = match[2];
  const traceFlags = match[3];
  if (!traceId || !spanId || !traceFlags) {
    return null;
  }
  if (/^0+$/.test(traceId) || /^0+$/.test(spanId)) {
    return null;
  }
  return {
    version: '00',
    traceId,
    spanId,
    traceFlags,
  };
}

export function createChildTraceContext(parent?: W3CTraceContext | null): W3CTraceContext {
  const traceId = parent ? parent.traceId : randomBytes(16).toString('hex');
  const spanId = randomBytes(8).toString('hex');
  const traceFlags = parent ? parent.traceFlags : '01';
  return {
    version: '00',
    traceId,
    spanId,
    traceFlags,
  };
}

export function formatTraceparent(trace: W3CTraceContext): string {
  return `${trace.version}-${trace.traceId}-${trace.spanId}-${trace.traceFlags}`;
}

export function createExecutionContext(
  clock: Clock,
  input: CreateExecutionContextInput,
): ExecutionContext {
  const metaTraceparent =
    typeof input.meta?.traceparent === 'string' ? input.meta.traceparent : undefined;
  const rawTraceparent = input.traceparent ?? metaTraceparent;
  const parentTrace = rawTraceparent ? parseTraceparent(rawTraceparent) : null;
  const trace = createChildTraceContext(parentTrace);

  const metaTenant = typeof input.meta?.tenantId === 'string' ? input.meta.tenantId : undefined;
  const metaSession = typeof input.meta?.sessionId === 'string' ? input.meta.sessionId : undefined;

  const base: ExecutionContext = {
    requestId: `req_${randomBytes(8).toString('hex')}`,
    jsonRpcId: input.jsonRpcId,
    tenantId: input.tenantId ?? metaTenant ?? 'default-tenant',
    sessionId: input.sessionId ?? metaSession ?? 'default-session',
    method: input.method,
    startedAtMs: clock.nowMs(),
    startedAtMicros: clock.nowMicros(),
    mode: input.mode,
    trace,
  };

  return {
    ...base,
    ...(input.toolName !== undefined ? { toolName: input.toolName } : {}),
    ...(input.macaroonToken !== undefined ? { macaroonToken: input.macaroonToken } : {}),
  };
}
