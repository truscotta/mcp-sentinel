/**
 * Strict JSON-RPC 2.0 and Model Context Protocol (MCP) wire schemas
 * with zero-any runtime type guards.
 */
export type JsonPrimitive = string | number | boolean | null;

export type JsonValue = JsonPrimitive | JsonObject | JsonArray;

export interface JsonObject {
  readonly [key: string]: JsonValue | undefined;
}

export type JsonArray = readonly JsonValue[];

export type JsonRpcId = string | number | null;

export interface JsonRpcRequest {
  readonly jsonrpc: '2.0';
  readonly id: JsonRpcId;
  readonly method: string;
  readonly params?: JsonObject;
}

export interface JsonRpcNotification {
  readonly jsonrpc: '2.0';
  readonly method: string;
  readonly params?: JsonObject;
}

export interface JsonRpcSuccessResponse {
  readonly jsonrpc: '2.0';
  readonly id: JsonRpcId;
  readonly result: JsonValue;
}

export interface JsonRpcErrorObject {
  readonly code: number;
  readonly message: string;
  readonly data?: JsonObject;
}

export interface JsonRpcErrorResponse {
  readonly jsonrpc: '2.0';
  readonly id: JsonRpcId;
  readonly error: JsonRpcErrorObject;
}

export type JsonRpcResponse = JsonRpcSuccessResponse | JsonRpcErrorResponse;

export type JsonRpcMessage = JsonRpcRequest | JsonRpcNotification | JsonRpcResponse;

export interface McpToolInputSchema {
  readonly type: 'object';
  readonly properties?: JsonObject;
  readonly required?: readonly string[];
  readonly additionalProperties?: boolean;
}

export interface McpToolDefinition {
  readonly name: string;
  readonly description?: string;
  readonly inputSchema: McpToolInputSchema;
}

export interface McpToolsListResult {
  readonly tools: readonly McpToolDefinition[];
  readonly nextCursor?: string;
}

export interface McpToolCallParams {
  readonly name: string;
  readonly arguments?: JsonObject;
  readonly _meta?: JsonObject;
}

export interface McpTextContent {
  readonly type: 'text';
  readonly text: string;
}

export interface McpResourceContent {
  readonly type: 'resource';
  readonly resource: {
    readonly uri: string;
    readonly mimeType?: string;
    readonly text?: string;
  };
}

export type McpContentBlock = McpTextContent | McpResourceContent | JsonObject;

export interface McpToolCallResult {
  readonly content: readonly McpContentBlock[];
  readonly isError?: boolean;
  readonly _meta?: JsonObject;
}

export function isJsonObject(value: unknown): value is JsonObject {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

export function isJsonValue(value: unknown, maxDepth = 64): value is JsonValue {
  if (maxDepth < 0) {
    return false;
  }
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  ) {
    return true;
  }
  if (Array.isArray(value)) {
    return value.every((item) => isJsonValue(item, maxDepth - 1));
  }
  if (isJsonObject(value)) {
    return Object.values(value).every(
      (val) => val === undefined || isJsonValue(val, maxDepth - 1),
    );
  }
  return false;
}

export function isJsonRpcId(value: unknown): value is JsonRpcId {
  return (
    value === null ||
    typeof value === 'string' ||
    (typeof value === 'number' && Number.isFinite(value))
  );
}

export function isJsonRpcRequest(value: unknown): value is JsonRpcRequest {
  if (!isJsonObject(value)) {
    return false;
  }
  if (value.jsonrpc !== '2.0' || typeof value.method !== 'string' || value.method.length === 0) {
    return false;
  }
  if (!('id' in value) || !isJsonRpcId(value.id)) {
    return false;
  }
  if (value.params !== undefined && !isJsonObject(value.params)) {
    return false;
  }
  return true;
}

export function isJsonRpcResponse(value: unknown): value is JsonRpcResponse {
  if (!isJsonObject(value) || value.jsonrpc !== '2.0' || !('id' in value) || !isJsonRpcId(value.id)) {
    return false;
  }
  const hasResult = 'result' in value;
  const hasError = 'error' in value && isJsonObject(value.error);
  return (hasResult && !hasError) || (!hasResult && hasError);
}

export function isToolsCallParams(params: JsonObject | undefined): params is JsonObject & McpToolCallParams {
  if (!params || typeof params.name !== 'string' || params.name.trim().length === 0) {
    return false;
  }
  if (params.arguments !== undefined && !isJsonObject(params.arguments)) {
    return false;
  }
  return true;
}

export function createJsonRpcSuccessResponse(
  id: JsonRpcId,
  result: JsonValue,
): JsonRpcSuccessResponse {
  return {
    jsonrpc: '2.0',
    id,
    result,
  };
}

export function createJsonRpcErrorResponse(
  id: JsonRpcId,
  error: JsonRpcErrorObject,
): JsonRpcErrorResponse {
  return {
    jsonrpc: '2.0',
    id,
    error,
  };
}
