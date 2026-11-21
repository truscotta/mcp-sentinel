import type { SentinelKernel, UpstreamMcpHandler } from '../core/engine.js';
import { createSentinelError, toJsonRpcErrorObject } from '../types/errors.js';
import {
  createJsonRpcErrorResponse,
  createJsonRpcSuccessResponse,
  isToolsCallParams,
  type JsonObject,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type JsonValue,
  type McpToolCallResult,
  type McpToolDefinition,
} from '../types/jsonrpc.js';

export type LocalToolHandler = (
  args: JsonObject,
  meta?: JsonObject,
) => Promise<McpToolCallResult | JsonValue>;

interface RegisteredLocalTool {
  readonly definition: McpToolDefinition;
  readonly handler: LocalToolHandler;
}

/**
 * Wraps an arbitrary `UpstreamMcpHandler` with `SentinelKernel` enforcement.
 */
export function createSentinelMiddleware(
  kernel: SentinelKernel,
  upstream: UpstreamMcpHandler,
): UpstreamMcpHandler {
  return async (request: JsonRpcRequest): Promise<JsonRpcResponse> =>
    kernel.handleRequest(request, upstream);
}

function normalizeToolOutput(raw: McpToolCallResult | JsonValue): McpToolCallResult {
  if (
    typeof raw === 'object' &&
    raw !== null &&
    !Array.isArray(raw) &&
    Array.isArray((raw as { readonly content?: unknown }).content)
  ) {
    return raw as McpToolCallResult;
  }
  const serialized = typeof raw === 'string' ? raw : JSON.stringify(raw);
  return {
    content: [{ type: 'text', text: serialized }],
  };
}

/**
 * In-process TypeScript MCP Tool Registry protected directly by `SentinelKernel`.
 * Ideal for embedding governed tool execution inside custom Vercel AI, LangGraph,
 * or OpenAI Agents applications without spawning a separate child process.
 */
export class SentinelProtectedRegistry {
  private readonly kernel: SentinelKernel;
  private readonly tools = new Map<string, RegisteredLocalTool>();
  private callSequence = 0;

  public constructor(kernel: SentinelKernel) {
    this.kernel = kernel;
  }

  public registerTool(definition: McpToolDefinition, handler: LocalToolHandler): this {
    this.tools.set(definition.name, { definition, handler });
    return this;
  }

  public asMcpHandler(): UpstreamMcpHandler {
    const internalDispatcher: UpstreamMcpHandler = async (
      req: JsonRpcRequest,
    ): Promise<JsonRpcResponse> => {
      if (req.method === 'tools/list') {
        const definitions = Array.from(this.tools.values()).map((entry) => entry.definition);
        return createJsonRpcSuccessResponse(req.id, {
          tools: definitions,
        } as unknown as JsonValue);
      }

      if (req.method === 'tools/call') {
        if (!isToolsCallParams(req.params)) {
          const invalid = createSentinelError(
            'INVALID_PARAMS',
            'Invalid tools/call parameters',
            'sdk-registry',
          );
          return createJsonRpcErrorResponse(req.id, toJsonRpcErrorObject(invalid));
        }

        const registered = this.tools.get(req.params.name);
        if (registered === undefined) {
          const missing = createSentinelError(
            'METHOD_NOT_FOUND',
            `Registered MCP tool "${req.params.name}" not found`,
            'sdk-registry',
          );
          return createJsonRpcErrorResponse(req.id, toJsonRpcErrorObject(missing));
        }

        const rawOut = await registered.handler(req.params.arguments ?? {}, req.params._meta);
        const normalized = normalizeToolOutput(rawOut);
        return createJsonRpcSuccessResponse(req.id, normalized as unknown as JsonValue);
      }

      const unknownMethod = createSentinelError(
        'METHOD_NOT_FOUND',
        `Unsupported MCP method "${req.method}" in SentinelProtectedRegistry`,
        'sdk-registry',
      );
      return createJsonRpcErrorResponse(req.id, toJsonRpcErrorObject(unknownMethod));
    };

    return createSentinelMiddleware(this.kernel, internalDispatcher);
  }

  public async listTools(meta?: JsonObject): Promise<JsonRpcResponse> {
    this.callSequence += 1;
    const handler = this.asMcpHandler();
    return handler({
      jsonrpc: '2.0',
      id: `sdk_list_${this.callSequence}`,
      method: 'tools/list',
      ...(meta !== undefined ? { params: { _meta: meta } } : {}),
    });
  }

  public async callTool(
    name: string,
    args: JsonObject = {},
    meta?: JsonObject,
  ): Promise<JsonRpcResponse> {
    this.callSequence += 1;
    const handler = this.asMcpHandler();
    return handler({
      jsonrpc: '2.0',
      id: `sdk_call_${this.callSequence}`,
      method: 'tools/call',
      params: {
        name,
        arguments: args,
        ...(meta !== undefined ? { _meta: meta } : {}),
      },
    });
  }
}
