import type { JsonObject, JsonRpcErrorObject } from './jsonrpc.js';

/**
 * Standardized JSON-RPC 2.0 and mcp-sentinel server error codes (-32001..-32012).
 */
export const SENTINEL_ERROR_CODES = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  POLICY_VIOLATION: -32001,
  BUDGET_EXCEEDED: -32002,
  LOOP_DETECTED: -32003,
  CIRCUIT_OPEN: -32004,
  RATE_LIMITED: -32005,
  LATTICE_VIOLATION: -32006,
  SCHEMA_INTEGRITY_VIOLATION: -32007,
  SESSION_LOCKED: -32008,
  CAPABILITY_DENIED: -32009,
  DECEPTION_TRIPPED: -32010,
  APPROVAL_REJECTED: -32011,
  VAULT_INTEGRITY_ERROR: -32012,
} as const;

export type SentinelErrorName = keyof typeof SENTINEL_ERROR_CODES;

export type SentinelErrorCode = (typeof SENTINEL_ERROR_CODES)[SentinelErrorName];

export interface SentinelError {
  readonly code: SentinelErrorCode;
  readonly name: SentinelErrorName;
  readonly message: string;
  readonly stage: string;
  readonly retryable: boolean;
  readonly metadata?: JsonObject;
}

const RETRYABLE_NAMES: ReadonlySet<SentinelErrorName> = new Set<SentinelErrorName>([
  'CIRCUIT_OPEN',
  'RATE_LIMITED',
]);

export function createSentinelError(
  name: SentinelErrorName,
  message: string,
  stage: string,
  metadata?: JsonObject,
): SentinelError {
  const base: SentinelError = {
    code: SENTINEL_ERROR_CODES[name],
    name,
    message,
    stage,
    retryable: RETRYABLE_NAMES.has(name),
  };
  if (metadata !== undefined) {
    return { ...base, metadata };
  }
  return base;
}

export function toJsonRpcErrorObject(error: SentinelError): JsonRpcErrorObject {
  const data: JsonObject = {
    sentinelError: error.name,
    stage: error.stage,
    retryable: error.retryable,
    ...(error.metadata !== undefined ? { details: error.metadata } : {}),
  };
  return {
    code: error.code,
    message: `[${error.name}] ${error.message}`,
    data,
  };
}
