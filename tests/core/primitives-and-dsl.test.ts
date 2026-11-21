import { describe, expect, it } from 'vitest';
import {
  canonicalHashHex,
  canonicalizeJson,
  constantTimeEqualHex,
  fnv1a64,
  hmacSha256Hex,
  sha256Hex,
} from '../../src/core/canonical.js';
import { SystemClock, VirtualClock } from '../../src/core/clock.js';
import {
  createExecutionContext,
  formatTraceparent,
  parseTraceparent,
} from '../../src/core/context.js';
import { analyzePolicyRules, compileSafeRegex } from '../../src/dsl/analyzer.js';
import { SplPolicyEngine } from '../../src/dsl/vm.js';
import {
  andThen,
  collectResults,
  err,
  isErr,
  isOk,
  mapErr,
  mapResult,
  ok,
  tryAsync,
  trySync,
  unwrapOr,
} from '../../src/types/result.js';

describe('Result<T, E> algebraic combinators and Clocks', () => {
  it('propagates Ok and Err values across all functional combinators', async () => {
    const good = ok(21);
    const bad = err('boom');

    expect(isOk(good)).toBe(true);
    expect(isErr(bad)).toBe(true);
    expect(unwrapOr(mapResult(good, (x) => x * 2), 0)).toBe(42);
    expect(unwrapOr(mapResult(bad, (x: number) => x * 2), 99)).toBe(99);

    const remapped = mapErr(bad, (e) => `err:${e}`);
    expect(!remapped.ok && remapped.error).toBe('err:boom');

    const chained = andThen(good, (v) => (v > 10 ? ok(v + 1) : err('small')));
    expect(unwrapOr(chained, 0)).toBe(22);

    const collectedOk = collectResults([ok(1), ok(2), ok(3)]);
    expect(collectedOk.ok && collectedOk.value).toEqual([1, 2, 3]);

    const collectedErr = collectResults([ok(1), err('halt'), ok(3)]);
    expect(!collectedErr.ok && collectedErr.error).toBe('halt');

    const syncCaught = trySync(
      () => {
        throw new Error('sync_fail');
      },
      (e) => (e instanceof Error ? e.message : 'unknown'),
    );
    expect(!syncCaught.ok && syncCaught.error).toBe('sync_fail');

    const asyncOk = await tryAsync(async () => 'done', String);
    expect(asyncOk.ok && asyncOk.value).toBe('done');
  });

  it('advances VirtualClock deterministically and reads SystemClock', () => {
    const sys = new SystemClock();
    expect(sys.nowMs()).toBeGreaterThan(1_700_000_000_000);
    expect(sys.nowMicros()).toBeGreaterThan(0n);
    expect(sys.isoNow()).toContain('T');

    const vclock = new VirtualClock(1_700_000_000_000);
    const initialMicros = vclock.nowMicros();
    vclock.advanceMs(250);
    expect(vclock.nowMs()).toBe(1_700_000_000_250);
    expect(vclock.nowMicros() - initialMicros).toBe(250_000n);

    vclock.advanceMicros(1_500n);
    expect(vclock.nowMs()).toBe(1_700_000_000_251);

    vclock.setNowMs(1_700_000_005_000);
    expect(vclock.nowMs()).toBe(1_700_000_005_000);
    expect(() => vclock.advanceMs(-1)).toThrow(RangeError);
    expect(() => vclock.setNowMs(1_700_000_000_000)).toThrow(RangeError);
  });
});

describe('RFC-8785 Canonical JSON, Hashing, and W3C TraceContext', () => {
  it('produces identical SHA-256 digests regardless of key order and rejects cycles/NaN', () => {
    const objA = { b: [1, true, null, -0], a: { z: 'hi', y: undefined, x: 'ok' } };
    const objB = { a: { x: 'ok', z: 'hi' }, b: [1, true, null, 0] };

    const hashA = canonicalHashHex(objA);
    const hashB = canonicalHashHex(objB);
    expect(hashA.ok).toBe(true);
    expect(hashB.ok).toBe(true);
    if (hashA.ok && hashB.ok) {
      expect(hashA.value).toBe(hashB.value);
      expect(constantTimeEqualHex(hashA.value, hashB.value)).toBe(true);
    }

    expect(constantTimeEqualHex('abcd', 'abce')).toBe(false);
    expect(constantTimeEqualHex('zz', 'zz')).toBe(false);
    expect(sha256Hex('sentinel')).toHaveLength(64);
    expect(hmacSha256Hex('secret', 'payload')).toHaveLength(64);
    expect(fnv1a64('alpha')).not.toBe(fnv1a64('beta'));

    const nanRes = canonicalizeJson({ bad: Number.NaN });
    expect(nanRes.ok).toBe(false);

    const cyclic: Record<string, unknown> = { name: 'loop' };
    cyclic.self = cyclic;
    expect(canonicalizeJson(cyclic).ok).toBe(false);
  });

  it('parses valid W3C traceparent headers and rejects all-zero IDs', () => {
    const validHeader = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
    const parsed = parseTraceparent(validHeader);
    expect(parsed).not.toBeNull();
    if (parsed !== null) {
      expect(parsed.traceId).toBe('4bf92f3577b34da6a3ce929d0e0e4736');
    }

    expect(
      parseTraceparent('00-00000000000000000000000000000000-00f067aa0ba902b7-01'),
    ).toBeNull();

    const clock = new VirtualClock();
    const ctx = createExecutionContext(clock, {
      jsonRpcId: 1,
      method: 'tools/call',
      toolName: 'db_query',
      mode: 'ENFORCE',
      traceparent: validHeader,
      meta: { tenantId: 'acme', sessionId: 'sess-1' },
    });

    expect(ctx.tenantId).toBe('acme');
    expect(ctx.sessionId).toBe('sess-1');
    expect(ctx.trace.traceId).toBe('4bf92f3577b34da6a3ce929d0e0e4736');
    expect(ctx.trace.spanId).not.toBe('00f067aa0ba902b7');
    expect(formatTraceparent(ctx.trace)).toMatch(/^00-4bf92f3577b34da6a3ce929d0e0e4736-/);
  });
});

describe('Sentinel Policy Language (SPL) Compiler, Static Analyzer, and Bytecode VM', () => {
  it('rejects ReDoS patterns, prototype access, and contradictory equal-priority rules', () => {
    expect(compileSafeRegex('(a+)+$').ok).toBe(false);
    expect(compileSafeRegex('(?i)^select\\s+').ok).toBe(true);

    const protoCheck = analyzePolicyRules([
      {
        id: 'proto-attempt',
        priority: 10,
        effect: 'DENY',
        expression: 'args.__proto__ == "polluted"',
      },
    ]);
    expect(protoCheck.ok).toBe(false);

    const conflictCheck = analyzePolicyRules([
      {
        id: 'rule-allow',
        priority: 50,
        effect: 'ALLOW',
        expression: 'tool.name == "shell_exec" and tenant == "prod"',
      },
      {
        id: 'rule-deny',
        priority: 50,
        effect: 'DENY',
        expression: 'tenant == "prod" and tool.name == "shell_exec"',
      },
    ]);
    expect(conflictCheck.ok).toBe(false);

    const shadowedReport = analyzePolicyRules([
      { id: 'catch-all', priority: 100, effect: 'ALLOW', expression: 'true' },
      { id: 'unreachable', priority: 10, effect: 'DENY', expression: 'tool.name == "rm"' },
    ]);
    expect(shadowedReport.ok).toBe(true);
    if (shadowedReport.ok) {
      expect(shadowedReport.value.warnings.length).toBeGreaterThan(0);
    }
  });

  it('executes compiled SPL bytecode with built-ins, short-circuit logic, and gas limits', () => {
    const engineRes = SplPolicyEngine.compile(
      [
        {
          id: 'block-high-entropy-exfil',
          priority: 100,
          effect: 'DENY',
          expression:
            'has_category("EXTERNAL_SINK") and (entropy(args["token"]) > 3.8 or taint.has("SECRET"))',
        },
        {
          id: 'approve-expensive-sql',
          priority: 80,
          effect: 'REQUIRE_APPROVAL',
          expression:
            'tool.name in ["sql_exec", "db_mutate"] and (cost.estimated_usd() >= 0.05 or lower(args.query) matches "(?i)^delete\\s+from")',
        },
      ],
      1_500,
    );
    expect(engineRes.ok).toBe(true);
    if (!engineRes.ok) return;

    const exfilVerdict = engineRes.value.evaluate({
      method: 'tools/call',
      toolName: 'webhook_post',
      args: { token: 'xK9#mP2$vL8@qR5!zW3&nJ7*bF4^hD1' },
      tenantId: 't1',
      sessionId: 's1',
      confidentiality: 'INTERNAL',
      integrity: 'VERIFIED',
      taintLabels: [],
      toolCategories: ['EXTERNAL_SINK'],
      sessionSpentMicroUsd: 10_000,
      estimatedCallMicroUsd: 5_000,
      payloadBytes: 64,
    });
    expect(exfilVerdict.ok).toBe(true);
    if (exfilVerdict.ok) {
      expect(exfilVerdict.value.action).toBe('DENY');
      expect(exfilVerdict.value.matchedRuleId).toBe('block-high-entropy-exfil');
    }

    const sqlVerdict = engineRes.value.evaluate({
      method: 'tools/call',
      toolName: 'sql_exec',
      args: { query: 'DELETE FROM audit_events WHERE id = 1' },
      tenantId: 't1',
      sessionId: 's1',
      confidentiality: 'INTERNAL',
      integrity: 'VERIFIED',
      taintLabels: [],
      toolCategories: ['DESTRUCTIVE_SINK'],
      sessionSpentMicroUsd: 0,
      estimatedCallMicroUsd: 1_000,
      payloadBytes: 48,
    });
    expect(sqlVerdict.ok && sqlVerdict.value.action).toBe('REQUIRE_APPROVAL');

    // Verify strict gas exhaustion on ultra-low gas ceiling
    const tinyGasEngine = SplPolicyEngine.compile(
      [
        {
          id: 'tight-gas',
          priority: 10,
          effect: 'DENY',
          expression: 'starts_with(lower(args.path), "/etc") and len(args.path) > 2',
        },
      ],
      3,
    );
    expect(tinyGasEngine.ok).toBe(true);
    if (!tinyGasEngine.ok) return;

    const outOfGas = tinyGasEngine.value.evaluate({
      method: 'tools/call',
      toolName: 'fs_read',
      args: { path: '/etc/hosts' },
      tenantId: 't1',
      sessionId: 's1',
      confidentiality: 'PUBLIC',
      integrity: 'VERIFIED',
      taintLabels: [],
      toolCategories: ['SENSITIVE_SOURCE'],
      sessionSpentMicroUsd: 0,
      estimatedCallMicroUsd: 100,
      payloadBytes: 20,
    });
    expect(outOfGas.ok).toBe(false);
  });
});
