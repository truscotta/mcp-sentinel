import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Clock } from '../core/clock.js';
import type { ForensicAuditRecord } from '../forensics/flight-recorder.js';
import type { TelemetryConfig } from '../types/policy.js';

function escapePrometheusLabel(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
}

/**
 * Lightweight zero-dependency observability HTTP server exposing:
 * - `GET /metrics`: Prometheus text exposition format v0.0.4
 * - `GET /healthz`: Liveness, uptime, Merkle tree size, and active lockdown count
 * - `GET /events` : Real-time Server-Sent Events (SSE) stream for `sentinel-studio`
 */
export class ObservabilityServer {
  private readonly config: TelemetryConfig;
  private readonly clock: Clock;
  private readonly startedAtMs: number;
  private server: Server | null = null;
  private boundPort: number | null = null;

  private readonly requestCounters = new Map<string, number>();
  private readonly blockedCounters = new Map<string, number>();
  private readonly tenantSpendMicroUsd = new Map<string, number>();
  private readonly sseClients = new Set<ServerResponse>();

  private totalPseudonymizedEntities = 0;
  private latencyMicrosSum = 0;
  private latencyMicrosCount = 0;
  private latestMerkleTreeSize = 0;
  private activeLockdownsCount = 0;

  public constructor(config: TelemetryConfig, clock: Clock) {
    this.config = config;
    this.clock = clock;
    this.startedAtMs = clock.nowMs();
  }

  public recordAuditEvent(
    record: ForensicAuditRecord,
    extras?: {
      readonly pseudonymizedCount?: number;
      readonly activeLockdowns?: number;
      readonly merkleTreeSize?: number;
    },
  ): void {
    const toolLabel = record.toolName ?? '_non_tool_';
    const reqKey = `${escapePrometheusLabel(record.method)}|${escapePrometheusLabel(toolLabel)}|${escapePrometheusLabel(record.outcome)}`;
    this.requestCounters.set(reqKey, (this.requestCounters.get(reqKey) ?? 0) + 1);

    if (record.outcome === 'BLOCKED' || record.outcome === 'SHADOW_FLAGGED') {
      const errLabel = record.errorName ?? 'POLICY_VIOLATION';
      const blockKey = `${escapePrometheusLabel(record.stage)}|${escapePrometheusLabel(errLabel)}|${escapePrometheusLabel(record.outcome)}`;
      this.blockedCounters.set(blockKey, (this.blockedCounters.get(blockKey) ?? 0) + 1);
    }

    if (record.settledMicroUsd > 0) {
      const tenantLabel = escapePrometheusLabel(record.tenantId);
      this.tenantSpendMicroUsd.set(
        tenantLabel,
        (this.tenantSpendMicroUsd.get(tenantLabel) ?? 0) + record.settledMicroUsd,
      );
    }

    this.latencyMicrosSum += Math.max(0, record.latencyMicros);
    this.latencyMicrosCount += 1;

    if (extras?.pseudonymizedCount !== undefined && extras.pseudonymizedCount > 0) {
      this.totalPseudonymizedEntities += extras.pseudonymizedCount;
    }
    if (extras?.activeLockdowns !== undefined) {
      this.activeLockdownsCount = extras.activeLockdowns;
    }
    this.latestMerkleTreeSize = extras?.merkleTreeSize ?? record.sequence + 1;

    if (this.sseClients.size > 0) {
      const frame = `id: ${record.sequence}\nevent: audit\ndata: ${JSON.stringify(record)}\n\n`;
      for (const res of this.sseClients) {
        if (!res.writableEnded) {
          res.write(frame);
        }
      }
    }
  }

  public renderPrometheusMetrics(): string {
    const lines: string[] = [
      '# HELP mcp_sentinel_requests_total Total MCP JSON-RPC requests processed by Sentinel.',
      '# TYPE mcp_sentinel_requests_total counter',
    ];

    for (const [compositeKey, count] of this.requestCounters.entries()) {
      const [method = '', tool = '', outcome = ''] = compositeKey.split('|');
      lines.push(
        `mcp_sentinel_requests_total{method="${method}",tool="${tool}",outcome="${outcome}"} ${count}`,
      );
    }

    lines.push(
      '# HELP mcp_sentinel_guard_interventions_total Total blocked or shadow-flagged calls by stage.',
      '# TYPE mcp_sentinel_guard_interventions_total counter',
    );
    for (const [compositeKey, count] of this.blockedCounters.entries()) {
      const [stage = '', errorName = '', outcome = ''] = compositeKey.split('|');
      lines.push(
        `mcp_sentinel_guard_interventions_total{stage="${stage}",error="${errorName}",outcome="${outcome}"} ${count}`,
      );
    }

    lines.push(
      '# HELP mcp_sentinel_spend_settled_micro_usd_total Settled integer Micro-USD spend per tenant.',
      '# TYPE mcp_sentinel_spend_settled_micro_usd_total counter',
    );
    for (const [tenant, microUsd] of this.tenantSpendMicroUsd.entries()) {
      lines.push(`mcp_sentinel_spend_settled_micro_usd_total{tenant="${tenant}"} ${microUsd}`);
    }

    lines.push(
      '# HELP mcp_sentinel_vault_pseudonymized_total Total sensitive entities pseudonymized by AES-256-GCM vault.',
      '# TYPE mcp_sentinel_vault_pseudonymized_total counter',
      `mcp_sentinel_vault_pseudonymized_total ${this.totalPseudonymizedEntities}`,
      '# HELP mcp_sentinel_merkle_tree_size Current number of leaves in the RFC-6962 forensic Merkle tree.',
      '# TYPE mcp_sentinel_merkle_tree_size gauge',
      `mcp_sentinel_merkle_tree_size ${this.latestMerkleTreeSize}`,
      '# HELP mcp_sentinel_active_lockdowns Number of active Kill-Switch quarantines.',
      '# TYPE mcp_sentinel_active_lockdowns gauge',
      `mcp_sentinel_active_lockdowns ${this.activeLockdownsCount}`,
      '# HELP mcp_sentinel_call_latency_micros_sum Cumulative processing latency in microseconds.',
      '# TYPE mcp_sentinel_call_latency_micros_sum counter',
      `mcp_sentinel_call_latency_micros_sum ${this.latencyMicrosSum}`,
      '# HELP mcp_sentinel_call_latency_micros_count Total calls measured for latency.',
      '# TYPE mcp_sentinel_call_latency_micros_count counter',
      `mcp_sentinel_call_latency_micros_count ${this.latencyMicrosCount}`,
      '',
    );

    return lines.join('\n');
  }

  public getBoundPort(): number | null {
    return this.boundPort;
  }

  public async start(): Promise<number> {
    if (this.server !== null && this.boundPort !== null) {
      return this.boundPort;
    }

    return new Promise<number>((resolve, reject) => {
      const srv = createServer((req, res) => this.handleHttpRequest(req, res));

      srv.once('error', (errObj) => {
        reject(errObj);
      });

      srv.listen(this.config.port, this.config.host, () => {
        this.server = srv;
        const addr = srv.address() as AddressInfo | null;
        this.boundPort = addr?.port ?? this.config.port;
        resolve(this.boundPort);
      });
    });
  }

  public async stop(): Promise<void> {
    for (const client of this.sseClients) {
      if (!client.writableEnded) {
        client.end();
      }
    }
    this.sseClients.clear();

    const activeServer = this.server;
    this.server = null;
    this.boundPort = null;

    if (activeServer === null) {
      return;
    }

    return new Promise<void>((resolve, reject) => {
      activeServer.close((closeErr) => {
        if (closeErr) {
          reject(closeErr);
          return;
        }
        resolve();
      });
    });
  }

  private handleHttpRequest(req: IncomingMessage, res: ServerResponse): void {
    const method = req.method ?? 'GET';
    const rawUrl = req.url ?? '/';
    const pathname = rawUrl.split('?')[0] ?? '/';

    res.setHeader('Access-Control-Allow-Origin', '*');

    if (method !== 'GET') {
      res.writeHead(405, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'Method Not Allowed' }));
      return;
    }

    if (pathname === '/healthz') {
      const body = JSON.stringify({
        status: 'ok',
        uptimeMs: Math.max(0, this.clock.nowMs() - this.startedAtMs),
        merkleTreeSize: this.latestMerkleTreeSize,
        activeLockdowns: this.activeLockdownsCount,
        connectedSseClients: this.sseClients.size,
      });
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(body);
      return;
    }

    if (pathname === '/metrics') {
      const metricsText = this.renderPrometheusMetrics();
      res.writeHead(200, {
        'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
        'Cache-Control': 'no-store',
      });
      res.end(metricsText);
      return;
    }

    if (pathname === '/events') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
      });
      res.write(': connected to mcp-sentinel live telemetry\n\n');
      this.sseClients.add(res);

      req.on('close', () => {
        this.sseClients.delete(res);
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'Not Found', endpoints: ['/healthz', '/metrics', '/events'] }));
  }
}
