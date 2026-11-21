import { type ChildProcessWithoutNullStreams, spawn } from 'node:child_process';
import process from 'node:process';
import { createInterface, type Interface as ReadlineInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';
import type { SentinelKernel } from '../core/engine.js';
import { createSentinelError, toJsonRpcErrorObject } from '../types/errors.js';
import {
  createJsonRpcErrorResponse,
  isJsonObject,
  isJsonRpcRequest,
  isJsonRpcResponse,
  type JsonRpcId,
  type JsonRpcRequest,
  type JsonRpcResponse,
} from '../types/jsonrpc.js';

export interface StdioUpstreamSpawnSpec {
  readonly command: string;
  readonly args: readonly string[];
  readonly cwd?: string;
  readonly env?: NodeJS.ProcessEnv;
}

export interface StdioUpstreamStreamsSpec {
  readonly childStdin: Writable;
  readonly childStdout: Readable;
}

export interface StdioReverseProxyOptions {
  readonly kernel: SentinelKernel;
  readonly upstream: StdioUpstreamSpawnSpec | StdioUpstreamStreamsSpec;
  readonly hostInput?: Readable;
  readonly hostOutput?: Writable;
  readonly upstreamTimeoutMs?: number;
}

interface PendingUpstreamCall {
  readonly originalId: JsonRpcId;
  readonly timer: ReturnType<typeof setTimeout>;
  readonly resolve: (response: JsonRpcResponse) => void;
  readonly reject: (reason: Error) => void;
}

function isSpawnSpec(
  spec: StdioUpstreamSpawnSpec | StdioUpstreamStreamsSpec,
): spec is StdioUpstreamSpawnSpec {
  return 'command' in spec;
}

/**
 * Newline-Delimited JSON-RPC 2.0 Stdio Reverse Proxy.
 * Wraps any language-agnostic MCP server process (`Python`, `Go`, `Rust`, `Node`)
 * behind `SentinelKernel` with correlation-safe request multiplexing, timeout
 * enforcement, notification pass-through, and graceful shutdown.
 */
export class StdioReverseProxy {
  private readonly kernel: SentinelKernel;
  private readonly upstreamSpec: StdioUpstreamSpawnSpec | StdioUpstreamStreamsSpec;
  private readonly hostInput: Readable;
  private readonly hostOutput: Writable;
  private readonly upstreamTimeoutMs: number;

  private childProcess: ChildProcessWithoutNullStreams | null = null;
  private hostReader: ReadlineInterface | null = null;
  private childReader: ReadlineInterface | null = null;
  private childWritable: Writable | null = null;
  private readonly pendingCalls = new Map<string, PendingUpstreamCall>();
  private wireCounter = 0;
  private stopped = false;

  public constructor(options: StdioReverseProxyOptions) {
    this.kernel = options.kernel;
    this.upstreamSpec = options.upstream;
    this.hostInput = options.hostInput ?? process.stdin;
    this.hostOutput = options.hostOutput ?? process.stdout;
    this.upstreamTimeoutMs = options.upstreamTimeoutMs ?? 30_000;
  }

  public async start(): Promise<void> {
    this.stopped = false;

    if (this.kernel.policy.telemetry.enabled) {
      await this.kernel.observability.start();
    }

    let childStdout: Readable;
    if (isSpawnSpec(this.upstreamSpec)) {
      const spawned = spawn(this.upstreamSpec.command, [...this.upstreamSpec.args], {
        cwd: this.upstreamSpec.cwd ?? process.cwd(),
        env: this.upstreamSpec.env ?? process.env,
        stdio: ['pipe', 'pipe', 'inherit'],
      });
      this.childProcess = spawned;
      this.childWritable = spawned.stdin;
      childStdout = spawned.stdout;

      spawned.once('exit', (code, signal) => {
        this.rejectAllPending(
          new Error(
            `Upstream MCP child process exited (code=${String(code)}, signal=${String(signal)})`,
          ),
        );
      });

      spawned.once('error', (errObj) => {
        this.rejectAllPending(errObj);
      });
    } else {
      this.childWritable = this.upstreamSpec.childStdin;
      childStdout = this.upstreamSpec.childStdout;
    }

    this.childReader = createInterface({
      input: childStdout,
      crlfDelay: Number.POSITIVE_INFINITY,
    });
    this.childReader.on('line', (line) => {
      this.onUpstreamLine(line);
    });

    this.hostReader = createInterface({
      input: this.hostInput,
      crlfDelay: Number.POSITIVE_INFINITY,
    });
    this.hostReader.on('line', (line) => {
      void this.onHostLine(line);
    });
  }

  public async stop(): Promise<void> {
    if (this.stopped) {
      return;
    }
    this.stopped = true;

    this.hostReader?.close();
    this.hostReader = null;

    this.childReader?.close();
    this.childReader = null;

    this.rejectAllPending(new Error('StdioReverseProxy stopped'));

    if (this.childProcess !== null) {
      const proc = this.childProcess;
      this.childProcess = null;
      if (proc.exitCode === null && !proc.killed) {
        proc.kill('SIGTERM');
      }
    }

    if (this.kernel.policy.telemetry.enabled) {
      await this.kernel.observability.stop();
    }
  }

  private writeToHost(message: unknown): void {
    if (!this.stopped && !this.hostOutput.writableEnded) {
      this.hostOutput.write(`${JSON.stringify(message)}\n`);
    }
  }

  private writeToChild(message: unknown): void {
    if (!this.stopped && this.childWritable !== null && !this.childWritable.writableEnded) {
      this.childWritable.write(`${JSON.stringify(message)}\n`);
    }
  }

  private async onHostLine(rawLine: string): Promise<void> {
    const trimmed = rawLine.trim();
    if (trimmed.length === 0) {
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      const parseErr = createSentinelError(
        'PARSE_ERROR',
        'Invalid JSON received on MCP stdio stream',
        'stdio-proxy',
      );
      this.writeToHost(createJsonRpcErrorResponse(null, toJsonRpcErrorObject(parseErr)));
      return;
    }

    if (isJsonRpcRequest(parsed)) {
      const response = await this.kernel.handleRequest(parsed, (forwardedReq) =>
        this.dispatchToUpstream(forwardedReq),
      );
      this.writeToHost(response);
      return;
    }

    // Notifications (`jsonrpc: "2.0"`, `method` without `id`) pass straight through when unlocked
    if (isJsonObject(parsed) && parsed.jsonrpc === '2.0' && typeof parsed.method === 'string') {
      this.writeToChild(parsed);
      return;
    }

    const invalidReq = createSentinelError(
      'INVALID_REQUEST',
      'Malformed JSON-RPC 2.0 envelope received on stdio stream',
      'stdio-proxy',
    );
    this.writeToHost(createJsonRpcErrorResponse(null, toJsonRpcErrorObject(invalidReq)));
  }

  private dispatchToUpstream(request: JsonRpcRequest): Promise<JsonRpcResponse> {
    if (this.stopped || this.childWritable === null) {
      return Promise.reject(new Error('Upstream MCP stdio channel is closed'));
    }

    this.wireCounter += 1;
    const wireId = `ms_wire_${this.wireCounter}`;

    return new Promise<JsonRpcResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingCalls.delete(wireId);
        reject(
          new Error(
            `Upstream MCP server timed out after ${this.upstreamTimeoutMs}ms on "${request.method}"`,
          ),
        );
      }, this.upstreamTimeoutMs);

      this.pendingCalls.set(wireId, {
        originalId: request.id,
        timer,
        resolve,
        reject,
      });

      const wireEnvelope: JsonRpcRequest = {
        ...request,
        id: wireId,
      };

      this.writeToChild(wireEnvelope);
    });
  }

  private onUpstreamLine(rawLine: string): void {
    const trimmed = rawLine.trim();
    if (trimmed.length === 0) {
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      return;
    }

    if (isJsonRpcResponse(parsed) && typeof parsed.id === 'string') {
      const pending = this.pendingCalls.get(parsed.id);
      if (pending !== undefined) {
        clearTimeout(pending.timer);
        this.pendingCalls.delete(parsed.id);
        if ('result' in parsed) {
          pending.resolve({
            jsonrpc: '2.0',
            id: pending.originalId,
            result: parsed.result,
          });
        } else {
          pending.resolve({
            jsonrpc: '2.0',
            id: pending.originalId,
            error: parsed.error,
          });
        }
        return;
      }
    }

    // Forward server-initiated notifications or unsolicited messages transparently
    if (isJsonObject(parsed) && parsed.jsonrpc === '2.0') {
      this.writeToHost(parsed);
    }
  }

  private rejectAllPending(reason: Error): void {
    for (const [wireId, entry] of this.pendingCalls.entries()) {
      clearTimeout(entry.timer);
      entry.reject(reason);
      this.pendingCalls.delete(wireId);
    }
  }
}
