import { describe, expect, it } from 'vitest';
import { VirtualClock } from '../../src/core/clock.js';
import { ProvenanceDag } from '../../src/ifc/provenance-dag.js';
import {
  joinConfidentiality,
  joinIntegrity,
  matchToolGlob,
  meetConfidentiality,
  meetIntegrity,
  SecurityLatticeEngine,
} from '../../src/ifc/security-lattice.js';

describe('Dual Security Lattice (Bell-LaPadula x Biba) and Provenance DAG', () => {
  it('computes exact lattice join/meet operations and glob matches', () => {
    expect(joinConfidentiality('INTERNAL', 'SECRET')).toBe('SECRET');
    expect(meetConfidentiality('INTERNAL', 'SECRET')).toBe('INTERNAL');
    expect(meetIntegrity('VERIFIED', 'UNTRUSTED')).toBe('UNTRUSTED');
    expect(joinIntegrity('UNTRUSTED', 'SYSTEM')).toBe('SYSTEM');

    expect(matchToolGlob('github_*_issue', 'github_read_issue')).toBe(true);
    expect(matchToolGlob('db_?et', 'db_get')).toBe(true);
    expect(matchToolGlob('db_?et', 'db_delete')).toBe(false);
  });

  it('blocks the Lethal Trifecta toxic flow and attributes causal blame via ProvenanceDag', () => {
    const clock = new VirtualClock();
    const dag = new ProvenanceDag(clock);
    const lattice = new SecurityLatticeEngine({
      enabled: true,
      toolClassifications: {
        web_fetch_untrusted: {
          readConfidentiality: 'PUBLIC',
          readIntegrity: 'UNTRUSTED',
          maxSinkConfidentiality: 'PUBLIC',
          minRequiredIntegrity: 'UNTRUSTED',
          categories: ['UNTRUSTED_SOURCE'],
        },
        vault_read_payroll: {
          readConfidentiality: 'SECRET',
          readIntegrity: 'VERIFIED',
          maxSinkConfidentiality: 'SECRET',
          minRequiredIntegrity: 'UNTRUSTED',
          categories: ['SENSITIVE_SOURCE'],
        },
        public_slack_post: {
          readConfidentiality: 'PUBLIC',
          readIntegrity: 'VERIFIED',
          maxSinkConfidentiality: 'INTERNAL',
          minRequiredIntegrity: 'UNTRUSTED',
          categories: ['EXTERNAL_SINK'],
        },
        prod_k8s_deploy: {
          readConfidentiality: 'INTERNAL',
          readIntegrity: 'SYSTEM',
          maxSinkConfidentiality: 'SECRET',
          minRequiredIntegrity: 'VERIFIED',
          categories: ['DESTRUCTIVE_SINK'],
        },
      },
    });

    const sessionId = 'sess-trifecta';

    // Step 1: Agent fetches untrusted web page -> integrity drops to UNTRUSTED
    expect(lattice.checkPreCallFlow(sessionId, 'web_fetch_untrusted').ok).toBe(true);
    const label1 = lattice.recordPostCallObservation(sessionId, 'web_fetch_untrusted');
    expect(label1).toEqual({ confidentiality: 'PUBLIC', integrity: 'UNTRUSTED' });
    expect(
      dag.recordHop({ sessionId, toolName: 'web_fetch_untrusted', labelApplied: label1 }).ok,
    ).toBe(true);
    clock.advanceMs(50);

    // Step 2: Biba Integrity Violation — tainted session tries to run prod_k8s_deploy (requires VERIFIED)
    const bibaCheck = lattice.checkPreCallFlow(sessionId, 'prod_k8s_deploy');
    expect(bibaCheck.ok).toBe(false);
    if (!bibaCheck.ok) {
      expect(bibaCheck.error.code).toBe(-32006);
      expect(bibaCheck.error.metadata?.violationType).toBe('INTEGRITY_NO_WRITE_UP');
    }

    const integrityBlame = dag.explainIntegrityTaintBlame(sessionId, 'UNTRUSTED');
    expect(integrityBlame.map((h) => h.toolName)).toEqual(['web_fetch_untrusted']);

    // Step 3: Agent reads SECRET payroll records -> confidentiality elevates to SECRET
    expect(lattice.checkPreCallFlow(sessionId, 'vault_read_payroll').ok).toBe(true);
    const label2 = lattice.recordPostCallObservation(sessionId, 'vault_read_payroll');
    expect(label2).toEqual({ confidentiality: 'SECRET', integrity: 'UNTRUSTED' });
    expect(
      dag.recordHop({ sessionId, toolName: 'vault_read_payroll', labelApplied: label2 }).ok,
    ).toBe(true);

    // Step 4: Bell-LaPadula Violation — session holding SECRET tries to post to INTERNAL Slack channel
    const blpCheck = lattice.checkPreCallFlow(sessionId, 'public_slack_post');
    expect(blpCheck.ok).toBe(false);
    if (!blpCheck.ok) {
      expect(blpCheck.error.metadata?.violationType).toBe('CONFIDENTIALITY_NO_WRITE_DOWN');
    }

    const secretBlame = dag.explainConfidentialityBlame(sessionId, 'SECRET');
    expect(secretBlame.map((h) => h.toolName)).toEqual(['vault_read_payroll']);
    expect(dag.exportSessionLineage(sessionId)).toHaveLength(2);
    expect(dag.getSessionFrontier(sessionId)).toHaveLength(1);
  });
});
