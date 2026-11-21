import { describe, expect, it } from 'vitest';
import { VirtualClock } from '../../src/core/clock.js';
import { DEFAULT_SENTINEL_POLICY } from '../../src/types/policy.js';
import { ReversibleContextVault } from '../../src/vault/context-vault.js';
import { passesLuhnCheck, shannonEntropyBits } from '../../src/vault/luhn-and-entropy.js';

describe('Bi-Directional AES-256-GCM Format-Preserving Context Vault', () => {
  it('pseudonymizes PII/secrets into valid synthetic formats and enforces lattice clearance on detokenization', () => {
    const clock = new VirtualClock();
    const vaultRes = ReversibleContextVault.create(
      {
        ...DEFAULT_SENTINEL_POLICY.vault,
        ttlMs: 30_000,
        customPatterns: { internal_emp_id: 'EMP-[0-9]{6}' },
      },
      clock,
    );
    expect(vaultRes.ok).toBe(true);
    if (!vaultRes.ok) return;
    const vault = vaultRes.value;

    expect(shannonEntropyBits('aaaa')).toBe(0);

    const rawUpstreamCustomer = {
      email: 'alice.cto@enterprise.io',
      card: '4532015112830366',
      ssn: '123-45-6789',
      phone: '+14155552671',
      apiKey: 'sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789',
      employeeCode: 'EMP-849201',
      traceUuid: '550e8400-e29b-41d4-a716-446655440000',
    };

    const inbound = vault.pseudonymizeInbound({
      tenantId: 'acme',
      sessionId: 'sess-vault',
      payload: rawUpstreamCustomer,
    });

    expect(inbound.pseudonymizedCount).toBe(6);
    expect(inbound.highestConfidentiality).toBe('SECRET');

    const masked = inbound.sanitizedPayload as Record<string, string>;
    // UUIDv4 must NOT be falsely flagged as a secret
    expect(masked.traceUuid).toBe('550e8400-e29b-41d4-a716-446655440000');

    // Synthetic aliases preserve domain formats (valid email, Luhn-valid card, 900-SSN, +1-555-01XX phone)
    expect(masked.email).toMatch(/^syn_[0-9a-f]{10}@sentinel\.vault$/);
    expect(masked.card).not.toBe(rawUpstreamCustomer.card);
    expect(passesLuhnCheck(masked.card ?? '')).toBe(true);
    expect(masked.ssn).toMatch(/^900-\d{2}-\d{4}$/);
    expect(masked.phone).toMatch(/^\+1[2-9]\d{2}55501\d{2}$/);
    expect(masked.apiKey).toMatch(/^syn_sec_[0-9a-f]{20}$/);

    // Attempting to send SECRET card alias to a PUBLIC sink is blocked by Bell-LaPadula check
    const unauthorizedEgress = vault.detokenizeOutboundConditional({
      tenantId: 'acme',
      sessionId: 'sess-vault',
      toolName: 'public_webhook',
      args: { cardNumber: masked.card ?? '' },
      targetMaxSinkConfidentiality: 'PUBLIC',
    });
    expect(unauthorizedEgress.ok).toBe(false);
    if (!unauthorizedEgress.ok) {
      expect(unauthorizedEgress.error.code).toBe(-32006);
    }

    // Sending aliases to an authorized SECRET payment processor restores exact plaintext
    const authorizedEgress = vault.detokenizeOutboundConditional({
      tenantId: 'acme',
      sessionId: 'sess-vault',
      toolName: 'stripe_charge_internal',
      args: {
        receiptEmail: masked.email ?? '',
        cardNumber: masked.card ?? '',
        emp: masked.employeeCode ?? '',
      },
      targetMaxSinkConfidentiality: 'SECRET',
    });
    expect(authorizedEgress.ok).toBe(true);
    if (authorizedEgress.ok) {
      expect(authorizedEgress.value.restoredCount).toBe(3);
      expect(authorizedEgress.value.detokenizedArgs).toEqual({
        receiptEmail: 'alice.cto@enterprise.io',
        cardNumber: '4532015112830366',
        emp: 'EMP-849201',
      });
    }

    // Cross-session replay of synthetic alias is rejected
    const crossSessionAttempt = vault.detokenizeOutboundConditional({
      tenantId: 'acme',
      sessionId: 'different-session',
      toolName: 'stripe_charge_internal',
      args: { receiptEmail: masked.email ?? '' },
      targetMaxSinkConfidentiality: 'SECRET',
    });
    expect(crossSessionAttempt.ok).toBe(false);

    // Expired vault entries fail closed and wipe ciphertext
    clock.advanceMs(31_000);
    const expiredAttempt = vault.detokenizeOutboundConditional({
      tenantId: 'acme',
      sessionId: 'sess-vault',
      toolName: 'stripe_charge_internal',
      args: { receiptEmail: masked.email ?? '' },
      targetMaxSinkConfidentiality: 'SECRET',
    });
    expect(expiredAttempt.ok).toBe(false);

    vault.destroySession('acme', 'sess-vault');
  });
});
