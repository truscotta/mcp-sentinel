import { describe, expect, it } from 'vitest';
import { VirtualClock } from '../../src/core/clock.js';
import { CircuitBreakerRegistry } from '../../src/guards/circuit-breaker.js';
import { IdempotencyCoalescer } from '../../src/guards/idempotency-coalescer.js';
import { PayloadFirewall } from '../../src/guards/payload-firewall.js';
import { HierarchicalRateLimiter } from '../../src/guards/rate-limiter.js';
import { ok } from '../../src/types/result.js';

describe('Zero-Trust Payload/SSRF Firewall and Resilience Mesh', () => {
  it('blocks IPv4, IPv6, IPv4-mapped IPv6 metadata SSRF, path traversal, and SQL drops', () => {
    const fwRes = PayloadFirewall.create({
      maxPayloadBytes: 2_048,
      maxDepth: 6,
      blockSsrf: true,
      blockPathTraversal: true,
      blockedPatterns: ['(?i)\\bDROP\\s+TABLE\\b'],
      allowedTools: ['http_*', 'fs_*', 'sql_*'],
      deniedTools: ['http_internal_debug'],
    });
    expect(fwRes.ok).toBe(true);
    if (!fwRes.ok) return;
    const fw = fwRes.value;

    // Clean external HTTPS call passes
    expect(
      fw.inspectToolCall('http_fetch', { url: 'https://api.github.com/repos/truscotta/mcp-sentinel' })
        .ok,
    ).toBe(true);

    // Denylist & non-allowlist blocked
    expect(fw.inspectToolCall('http_internal_debug', {}).ok).toBe(false);
    expect(fw.inspectToolCall('unlisted_tool', {}).ok).toBe(false);

    // Cloud IMDSv1/v2 IPv4, IPv4-mapped IPv6, Loopback IPv6, Link-Local IPv6, and file:// scheme
    const ssrfVectors = [
      'http://169.254.169.254/latest/meta-data/iam/',
      'http://[::ffff:169.254.169.254]/latest/meta-data/',
      'http://[::1]:8080/admin',
      'http://[fe80::1]/config',
      'http://metadata.google.internal/computeMetadata/v1/',
      'file:///etc/passwd',
    ];
    for (const vector of ssrfVectors) {
      const check = fw.inspectToolCall('http_fetch', { endpoint: vector });
      expect(check.ok).toBe(false);
    }

    // Path traversal & encoded traversal
    expect(fw.inspectToolCall('fs_read', { path: '../../etc/shadow' }).ok).toBe(false);
    expect(fw.inspectToolCall('fs_read', { path: '%2e%2e%2fsecret.key' }).ok).toBe(false);

    // Destructive SQL pattern
    expect(fw.inspectToolCall('sql_query', { q: 'DROP TABLE customers;' }).ok).toBe(false);
  });

  it('enforces transactional 3-tier rate limits and deterministic circuit breaker recovery', () => {
    const clock = new VirtualClock();
    const limiter = new HierarchicalRateLimiter(
      {
        enabled: true,
        tenant: { capacity: 10, refillPerSecond: 1 },
        session: { capacity: 5, refillPerSecond: 1 },
        perTool: { slow_api: { capacity: 1, refillPerSecond: 1 } },
      },
      clock,
    );

    expect(limiter.acquire('t1', 's1', 'slow_api').ok).toBe(true);
    // Second immediate call fails on TOOL tier without draining TENANT/SESSION tokens
    const rateLimited = limiter.acquire('t1', 's1', 'slow_api');
    expect(rateLimited.ok).toBe(false);

    // Advance VirtualClock by 1,000ms -> 1 token refilled -> succeeds
    clock.advanceMs(1_000);
    expect(limiter.acquire('t1', 's1', 'slow_api').ok).toBe(true);

    // Circuit Breaker: CLOSED -> OPEN -> HALF_OPEN single-probe -> CLOSED
    const breaker = new CircuitBreakerRegistry(
      {
        enabled: true,
        failureThreshold: 2,
        recoveryTimeoutMs: 10_000,
        halfOpenSuccessThreshold: 2,
      },
      clock,
    );

    expect(breaker.beforeCall('flaky_db').ok).toBe(true);
    breaker.recordFailure('flaky_db');
    expect(breaker.beforeCall('flaky_db').ok).toBe(true);
    breaker.recordFailure('flaky_db');

    // Now OPEN
    expect(breaker.snapshot('flaky_db').state).toBe('OPEN');
    expect(breaker.beforeCall('flaky_db').ok).toBe(false);

    // Advance past recoveryTimeoutMs -> admits exactly 1 HALF_OPEN probe while blocking concurrent second probe
    clock.advanceMs(10_000);
    const probe1 = breaker.beforeCall('flaky_db');
    expect(probe1.ok && probe1.value).toBe('HALF_OPEN');
    expect(breaker.beforeCall('flaky_db').ok).toBe(false);

    breaker.recordSuccess('flaky_db');
    expect(breaker.snapshot('flaky_db').state).toBe('HALF_OPEN');
    expect(breaker.beforeCall('flaky_db').ok).toBe(true);
    breaker.recordSuccess('flaky_db');
    expect(breaker.snapshot('flaky_db').state).toBe('CLOSED');
  });

  it('coalesces concurrent identical in-flight calls and serves subsequent TTL cache hits', async () => {
    const clock = new VirtualClock();
    const coalescer = new IdempotencyCoalescer<{ readonly answer: number }>(
      {
        enabled: true,
        ttlMs: 5_000,
        maxEntries: 64,
        coalesceInFlight: true,
      },
      clock,
    );

    let upstreamInvocations = 0;
    const keyInput = {
      tenantId: 't1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'expensive_report',
      args: { quarter: 'Q4', year: 2026 },
    };

    const runExecutor = () =>
      coalescer.executeOrCoalesce(keyInput, async () => {
        upstreamInvocations += 1;
        await Promise.resolve();
        return ok({ answer: 42 });
      });

    const [r1, r2, r3] = await Promise.all([runExecutor(), runExecutor(), runExecutor()]);
    expect(upstreamInvocations).toBe(1);
    expect(r1.ok && r1.value.source).toBe('EXECUTED');
    expect(r2.ok && r2.value.source).toBe('COALESCED_IN_FLIGHT');
    expect(r3.ok && r3.value.source).toBe('COALESCED_IN_FLIGHT');

    const cached = await runExecutor();
    expect(cached.ok && cached.value.source).toBe('CACHE_HIT');
    expect(upstreamInvocations).toBe(1);

    clock.advanceMs(5_001);
    expect(coalescer.purgeExpired()).toBe(1);
  });
});
