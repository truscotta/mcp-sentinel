import { describe, expect, it } from 'vitest';
import { hmacSha256Hex } from '../../src/core/canonical.js';
import { VirtualClock } from '../../src/core/clock.js';
import { HitlApprovalGate } from '../../src/hitl/approval-gate.js';
import {
  calculateActualCallMicroUsd,
  estimatePreCallMicroUsd,
  formatMicroUsdAsUsd,
} from '../../src/ledger/cost-model.js';
import { MicroUsdLedger } from '../../src/ledger/micro-ledger.js';

describe('4-Tier Atomic Two-Phase Micro-USD Ledger and HMAC HITL Gate', () => {
  it('prevents parallel reservation overspending and settles exact integer Micro-USD', () => {
    expect(formatMicroUsdAsUsd(1_250_500)).toBe('1.250500');
    expect(formatMicroUsdAsUsd(45)).toBe('0.000045');

    const clock = new VirtualClock();
    const ledgerConfig = {
      enabled: true,
      maxGlobalMicroUsd: 1_000_000,
      maxTenantMicroUsd: 500_000,
      maxSessionMicroUsd: 100_000,
      maxPerToolMicroUsd: { paid_search: 70_000 },
      defaultToolPricing: {
        baseMicroUsd: 10_000,
        inputByteMicroUsd: 2,
        outputByteMicroUsd: 1,
      },
    };

    const pre = estimatePreCallMicroUsd('paid_search', { q: 'mcp security' }, ledgerConfig);
    expect(pre.estimatedMicroUsd).toBeGreaterThan(10_000);

    const actual = calculateActualCallMicroUsd(
      'paid_search',
      { q: 'mcp security' },
      { hits: ['a', 'b'] },
      ledgerConfig,
    );
    expect(actual.actualMicroUsd).toBeGreaterThan(10_000);

    const ledger = new MicroUsdLedger(ledgerConfig, clock);

    // Reserve 40,000 uUSD twice concurrently against 70,000 uUSD per-tool cap -> 2nd must fail!
    const rsv1 = ledger.reserve({
      tenantId: 't1',
      sessionId: 's1',
      toolName: 'paid_search',
      estimatedMicroUsd: 40_000,
    });
    expect(rsv1.ok).toBe(true);

    const rsv2Overflow = ledger.reserve({
      tenantId: 't1',
      sessionId: 's1',
      toolName: 'paid_search',
      estimatedMicroUsd: 40_000,
    });
    expect(rsv2Overflow.ok).toBe(false);

    if (!rsv1.ok) return;

    // Commit actual 25,000 uUSD -> frees 15,000 uUSD headroom (45,000 uUSD remaining on tool cap)
    const committed = ledger.commit(rsv1.value.reservationId, 25_000);
    expect(committed.ok).toBe(true);
    // Double commit on settled reservation is rejected
    expect(ledger.commit(rsv1.value.reservationId, 25_000).ok).toBe(false);

    // Now reserving 40,000 uUSD succeeds (25,000 + 40,000 <= 70,000)
    const rsv3 = ledger.reserve({
      tenantId: 't1',
      sessionId: 's1',
      toolName: 'paid_search',
      estimatedMicroUsd: 40_000,
    });
    expect(rsv3.ok).toBe(true);

    // Reap stale reservations after advancing clock
    clock.advanceMs(120_000);
    expect(ledger.reapStaleReservations(60_000)).toBe(1);
    expect(ledger.getSnapshot('t1', 's1').sessionReservedMicroUsd).toBe(0);
    expect(ledger.getSnapshot('t1', 's1').sessionSettledMicroUsd).toBe(25_000);
  });

  it('verifies HMAC-SHA256 signed HITL webhook approvals and rejects tampered responses', async () => {
    const clock = new VirtualClock(1_700_000_000_000);
    const hmacSecret = 'enterprise-hitl-signing-secret';

    const gate = new HitlApprovalGate(
      {
        enabled: true,
        webhookUrl: 'https://approvals.internal/mcp-hook',
        hmacSecret,
        timeoutMs: 5_000,
        highCostThresholdMicroUsd: 100_000,
        approvalRequiredTools: ['prod_db_*'],
      },
      clock,
      async ({ bodyJson, headers }) => {
        const parsedReq = JSON.parse(bodyJson) as { readonly nonce: string };
        const timestamp = headers['x-sentinel-timestamp'] ?? '';
        const expectedReqSig = `sha256=${hmacSha256Hex(hmacSecret, `${timestamp}.${parsedReq.nonce}.${bodyJson}`)}`;
        expect(headers['x-sentinel-signature-256']).toBe(expectedReqSig);

        const decisionJson = JSON.stringify({
          approved: true,
          nonce: parsedReq.nonce,
          approvedBy: 'secops@acme.io',
        });
        const respSig = `sha256=${hmacSha256Hex(hmacSecret, `${parsedReq.nonce}.${decisionJson}`)}`;

        return {
          status: 200,
          bodyText: decisionJson,
          signatureHeader: respSig,
        };
      },
    );

    const approved = await gate.checkOrRequestApproval({
      requestId: 'req_1',
      tenantId: 'acme',
      sessionId: 's1',
      toolName: 'prod_db_migrate',
      sanitizedArguments: { version: '2026_11' },
      estimatedMicroUsd: 10_000,
      splAction: 'ALLOW',
    });
    expect(approved.ok).toBe(true);
    if (approved.ok) {
      expect(approved.value.required).toBe(true);
      expect(approved.value.approvedBy).toBe('secops@acme.io');
    }

    // Tampered response signature must fail closed
    const badSigGate = new HitlApprovalGate(
      {
        enabled: true,
        webhookUrl: 'https://approvals.internal/mcp-hook',
        hmacSecret,
        timeoutMs: 5_000,
        approvalRequiredTools: ['prod_db_*'],
      },
      clock,
      async ({ bodyJson }) => {
        const parsedReq = JSON.parse(bodyJson) as { readonly nonce: string };
        return {
          status: 200,
          bodyText: JSON.stringify({ approved: true, nonce: parsedReq.nonce }),
          signatureHeader: `sha256=${'0'.repeat(64)}`,
        };
      },
    );

    const rejectedTamper = await badSigGate.checkOrRequestApproval({
      requestId: 'req_2',
      tenantId: 'acme',
      sessionId: 's1',
      toolName: 'prod_db_migrate',
      sanitizedArguments: {},
      estimatedMicroUsd: 1_000,
      splAction: 'ALLOW',
    });
    expect(rejectedTamper.ok).toBe(false);
  });
});
