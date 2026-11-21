import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { VirtualClock } from '../../src/core/clock.js';
import { SentinelKernel } from '../../src/core/engine.js';
import { CounterfactualPolicyReplayer } from '../../src/forensics/counterfactual-replayer.js';
import {
  generateEd25519KeyPair,
  signMerkleTreeHead,
  verifySignedTreeHead,
} from '../../src/forensics/ed25519-notary.js';
import { verifyJsonlAuditLog } from '../../src/forensics/flight-recorder.js';
import {
  Rfc6962MerkleTree,
  verifyConsistencyProof,
  verifyInclusionProof,
} from '../../src/forensics/merkle-tree.js';
import { createJsonRpcSuccessResponse } from '../../src/types/jsonrpc.js';
import { createDefaultPolicy, DEFAULT_SENTINEL_POLICY } from '../../src/types/policy.js';

describe('RFC-6962 Merkle Proofs, Ed25519 Signed Tree Heads, and Counterfactual Replay', () => {
  it('generates and verifies O(log2 N) inclusion & consistency proofs across odd/even sizes', () => {
    const tree = new Rfc6962MerkleTree();
    for (let i = 0; i < 11; i += 1) {
      tree.appendRawLeaf(`audit-event-${i}`);
    }
    expect(tree.size).toBe(11);

    for (let idx = 0; idx < 11; idx += 1) {
      const incRes = tree.generateInclusionProof(idx);
      expect(incRes.ok).toBe(true);
      if (incRes.ok) {
        expect(verifyInclusionProof(incRes.value)).toBe(true);
        // Flip a single hex nibble in rootHashHex -> verification must fail
        const flippedChar = incRes.value.rootHashHex[0] === 'a' ? 'b' : 'a';
        const forgedRoot = `${flippedChar}${incRes.value.rootHashHex.slice(1)}`;
        expect(verifyInclusionProof({ ...incRes.value, rootHashHex: forgedRoot })).toBe(false);
      }
    }

    for (const oldSize of [1, 3, 4, 7, 8, 10, 11]) {
      const consRes = tree.generateConsistencyProof(oldSize, 11);
      expect(consRes.ok).toBe(true);
      if (consRes.ok) {
        expect(verifyConsistencyProof(consRes.value)).toBe(true);
      }
    }

    const kp = generateEd25519KeyPair();
    const otherKp = generateEd25519KeyPair();
    const rootRes = tree.rootHashHex();
    expect(rootRes.ok).toBe(true);
    if (!rootRes.ok) return;

    const sthRes = signMerkleTreeHead({
      treeSize: tree.size,
      timestampMs: 1_700_000_000_000,
      rootHashHex: rootRes.value,
      privateKeyPem: kp.privateKeyPem,
      publicKeyPem: kp.publicKeyPem,
    });
    expect(sthRes.ok).toBe(true);
    if (sthRes.ok) {
      const okSig = verifySignedTreeHead(sthRes.value, kp.publicKeyPem);
      expect(okSig.ok && okSig.value).toBe(true);
      const wrongKey = verifySignedTreeHead(sthRes.value, otherKp.publicKeyPem);
      expect(wrongKey.ok && wrongKey.value).toBe(false);
    }
  });

  it('verifies Ed25519-signed JSONL audit logs, detects tampering, and runs differential replay', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'sentinel-forensics-'));
    try {
      const logPath = join(tempDir, 'session.audit.jsonl');
      const kp = generateEd25519KeyPair();
      const clock = new VirtualClock(1_700_000_000_000);

      const permissivePolicy = createDefaultPolicy({
        mode: 'AUDIT_ONLY',
        forensics: {
          enabled: true,
          logFilePath: logPath,
          signTreeHeads: true,
          privateKeyPem: kp.privateKeyPem,
          publicKeyPem: kp.publicKeyPem,
        },
      });

      const kernelRes = SentinelKernel.create(permissivePolicy, { clock });
      expect(kernelRes.ok).toBe(true);
      if (!kernelRes.ok) return;

      const upstream = async (req: { readonly id: string | number | null }) =>
        createJsonRpcSuccessResponse(req.id, { content: [{ type: 'text', text: 'ok' }] });

      await kernelRes.value.handleRequest(
        {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'safe_read', arguments: { file: 'notes.md' } },
        },
        upstream,
      );
      clock.advanceMs(500);

      await kernelRes.value.handleRequest(
        {
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: {
            name: 'http_fetch',
            arguments: { url: 'http://169.254.169.254/latest/meta-data/' },
          },
        },
        upstream,
      );

      const jsonlText = readFileSync(logPath, 'utf8');
      const verified = verifyJsonlAuditLog(jsonlText, kp.publicKeyPem);
      expect(verified.ok).toBe(true);
      if (verified.ok) {
        expect(verified.value.verifiedRecords).toBe(2);
        expect(verified.value.verifiedSignatures).toBe(2);
      }

      // Modify a single field inside the JSONL log -> Merkle & Ed25519 verifier must reject
      const tamperedText = jsonlText.replace('safe_read', 'forged_tool');
      writeFileSync(join(tempDir, 'tampered.jsonl'), tamperedText, 'utf8');
      expect(verifyJsonlAuditLog(tamperedText, kp.publicKeyPem).ok).toBe(false);

      // Counterfactual Replay: test strict ENFORCE policy against the historical AUDIT_ONLY log
      const strictCandidate = createDefaultPolicy({ mode: 'ENFORCE' });
      const replayer = new CounterfactualPolicyReplayer();
      const diffRes = await replayer.replayJsonl({
        jsonlContent: jsonlText,
        candidatePolicy: strictCandidate,
        baselinePolicy: { ...DEFAULT_SENTINEL_POLICY, firewall: { ...DEFAULT_SENTINEL_POLICY.firewall, blockSsrf: false } },
      });

      expect(diffRes.ok).toBe(true);
      if (diffRes.ok) {
        expect(diffRes.value.totalToolCallsReplayed).toBe(2);
        expect(diffRes.value.newlyBlockedCount).toBe(1);
        expect(diffRes.value.preventedSpendMicroUsd).toBeGreaterThan(0);
        expect(diffRes.value.divergences[0]?.toolName).toBe('http_fetch');
      }
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
