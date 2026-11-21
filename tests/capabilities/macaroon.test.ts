import { describe, expect, it } from 'vitest';
import {
  attenuateMacaroon,
  deserializeMacaroon,
  MacaroonCaveats,
  mintMacaroon,
  serializeMacaroon,
  verifyMacaroon,
} from '../../src/capabilities/macaroon.js';
import { VirtualClock } from '../../src/core/clock.js';

describe('HMAC-SHA256 Capability Macaroons with Offline Attenuation', () => {
  const ROOT_SECRET = 'super-secret-sentinel-root-key-32b';

  it('mints, attenuates offline without root key, serializes, and enforces caveats', () => {
    const clock = new VirtualClock(1_700_000_000_000);

    const rootRes = mintMacaroon(ROOT_SECRET, {
      location: 'sentinel-orchestrator',
      caveats: [
        MacaroonCaveats.bindTenant('tenant-alpha'),
        MacaroonCaveats.expiresAtMs(clock.nowMs() + 60_000),
      ],
    });
    expect(rootRes.ok).toBe(true);
    if (!rootRes.ok) return;

    // Sub-agent delegation: narrow scope offline WITHOUT needing ROOT_SECRET
    const delegatedRes = attenuateMacaroon(rootRes.value, [
      MacaroonCaveats.bindSession('sess-sub-1'),
      MacaroonCaveats.allowMethods(['tools/call', 'tools/list']),
      MacaroonCaveats.allowTools(['fs_*', 'search_*']),
      MacaroonCaveats.denyTools(['fs_delete*']),
      MacaroonCaveats.requireArgPrefix('path', '/workspace/project-a/'),
      MacaroonCaveats.maxCallMicroUsd(50_000),
      MacaroonCaveats.maxSessionMicroUsd(200_000),
      MacaroonCaveats.maxConfidentiality('CONFIDENTIAL'),
    ]);
    expect(delegatedRes.ok).toBe(true);
    if (!delegatedRes.ok) return;

    const wireToken = serializeMacaroon(delegatedRes.value);
    const roundtrip = deserializeMacaroon(wireToken);
    expect(roundtrip.ok).toBe(true);

    // Authorized call within attenuated bounds succeeds
    const validCheck = verifyMacaroon(
      ROOT_SECRET,
      wireToken,
      {
        method: 'tools/call',
        toolName: 'fs_read',
        tenantId: 'tenant-alpha',
        sessionId: 'sess-sub-1',
        args: { path: '/workspace/project-a/README.md' },
        estimatedCallMicroUsd: 10_000,
        sessionSpentMicroUsd: 40_000,
        sessionConfidentiality: 'INTERNAL',
      },
      clock,
    );
    expect(validCheck.ok).toBe(true);

    // Path prefix escape is blocked
    const escapedPath = verifyMacaroon(
      ROOT_SECRET,
      wireToken,
      {
        method: 'tools/call',
        toolName: 'fs_read',
        tenantId: 'tenant-alpha',
        sessionId: 'sess-sub-1',
        args: { path: '/workspace/project-b/secrets.env' },
        estimatedCallMicroUsd: 10_000,
        sessionSpentMicroUsd: 40_000,
        sessionConfidentiality: 'INTERNAL',
      },
      clock,
    );
    expect(escapedPath.ok).toBe(false);

    // Denied sub-tool pattern is blocked
    const deniedTool = verifyMacaroon(
      ROOT_SECRET,
      wireToken,
      {
        method: 'tools/call',
        toolName: 'fs_delete_all',
        tenantId: 'tenant-alpha',
        sessionId: 'sess-sub-1',
        args: { path: '/workspace/project-a/tmp' },
        estimatedCallMicroUsd: 5_000,
        sessionSpentMicroUsd: 0,
        sessionConfidentiality: 'PUBLIC',
      },
      clock,
    );
    expect(deniedTool.ok).toBe(false);

    // Advancing VirtualClock past expiration immediately revokes token
    clock.advanceMs(61_000);
    const expiredCheck = verifyMacaroon(
      ROOT_SECRET,
      wireToken,
      {
        method: 'tools/call',
        toolName: 'fs_read',
        tenantId: 'tenant-alpha',
        sessionId: 'sess-sub-1',
        args: { path: '/workspace/project-a/README.md' },
        estimatedCallMicroUsd: 1_000,
        sessionSpentMicroUsd: 0,
        sessionConfidentiality: 'PUBLIC',
      },
      clock,
    );
    expect(expiredCheck.ok).toBe(false);
  });

  it('rejects caveat stripping, forged signatures, and unrecognized caveats', () => {
    const clock = new VirtualClock();
    expect(mintMacaroon('short-key').ok).toBe(false);

    const minted = mintMacaroon(ROOT_SECRET, {
      caveats: [MacaroonCaveats.allowTools(['read_only'])],
    });
    expect(minted.ok).toBe(true);
    if (!minted.ok) return;

    // Attacker strips caveat while keeping signature
    const strippedTamper = verifyMacaroon(
      ROOT_SECRET,
      { ...minted.value, caveats: [] },
      {
        method: 'tools/call',
        toolName: 'admin_drop_db',
        tenantId: 't1',
        sessionId: 's1',
        estimatedCallMicroUsd: 0,
        sessionSpentMicroUsd: 0,
        sessionConfidentiality: 'PUBLIC',
      },
      clock,
    );
    expect(strippedTamper.ok).toBe(false);

    // Unknown caveat predicate must fail closed
    const unknownCaveat = attenuateMacaroon(minted.value, ['custom_unknown_predicate > 99']);
    expect(unknownCaveat.ok).toBe(true);
    if (!unknownCaveat.ok) return;

    const verifyUnknown = verifyMacaroon(
      ROOT_SECRET,
      unknownCaveat.value,
      {
        method: 'tools/call',
        toolName: 'read_only',
        tenantId: 't1',
        sessionId: 's1',
        estimatedCallMicroUsd: 0,
        sessionSpentMicroUsd: 0,
        sessionConfidentiality: 'PUBLIC',
      },
      clock,
    );
    expect(verifyUnknown.ok).toBe(false);
  });
});
