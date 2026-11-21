import { describe, expect, it } from 'vitest';
import { CusumAnomalyDetector } from '../../src/intelligence/cusum-detector.js';
import { MARKOV_START_STATE, MarkovCallGraph } from '../../src/intelligence/markov-graph.js';
import {
  computeInvocationSimHash64,
  hammingDistance64,
  SimHashLoopDetector,
} from '../../src/intelligence/simhash.js';
import { DEFAULT_SENTINEL_POLICY } from '../../src/types/policy.js';

describe('64-bit SimHash Loop Detector, Markov Call-Graph, and Welford/CUSUM', () => {
  it('blocks exact streaks, periodic A-B cycles, fuzzy SimHash loops, and error-retry spirals', () => {
    const h1 = computeInvocationSimHash64('web_search', {
      query: 'how to configure kubernetes ingress controller tls',
      page: 1,
    });
    const h2 = computeInvocationSimHash64('web_search', {
      query: 'how to configure kubernetes ingress controller tls',
      page: 2,
    });
    expect(hammingDistance64(h1, h2)).toBeLessThanOrEqual(6);

    const detector = new SimHashLoopDetector({
      ...DEFAULT_SENTINEL_POLICY.intelligence,
      maxIdenticalStreak: 3,
      simhashMaxHammingDistance: 6,
      simhashWindowSize: 16,
    });

    // 1. Exact canonical streak on 3rd identical call
    expect(detector.evaluateAndRecord('s-exact', 'ping', { host: 'a' }).ok).toBe(true);
    expect(detector.evaluateAndRecord('s-exact', 'ping', { host: 'a' }).ok).toBe(true);
    const thirdExact = detector.evaluateAndRecord('s-exact', 'ping', { host: 'a' });
    expect(thirdExact.ok).toBe(false);
    if (!thirdExact.ok) {
      expect(thirdExact.error.metadata?.tier).toBe('EXACT_CANONICAL_STREAK');
    }

    // 2. Periodic 2-step cycle: A -> B -> A -> B -> A -> B
    expect(detector.evaluateAndRecord('s-cycle', 'step_a', { v: 1 }).ok).toBe(true);
    expect(detector.evaluateAndRecord('s-cycle', 'step_b', { v: 2 }).ok).toBe(true);
    expect(detector.evaluateAndRecord('s-cycle', 'step_a', { v: 1 }).ok).toBe(true);
    expect(detector.evaluateAndRecord('s-cycle', 'step_b', { v: 2 }).ok).toBe(true);
    expect(detector.evaluateAndRecord('s-cycle', 'step_a', { v: 1 }).ok).toBe(true);
    const sixthCycle = detector.evaluateAndRecord('s-cycle', 'step_b', { v: 2 });
    expect(sixthCycle.ok).toBe(false);
    if (!sixthCycle.ok) {
      expect(sixthCycle.error.metadata?.tier).toBe('PERIODIC_CYCLE');
    }

    // 3. Error-retry spiral: 2 failed near-identical calls block the 3rd tweaked retry
    const firstTry = detector.evaluateAndRecord('s-err', 'sql_run', {
      sql: 'SELECT id, email, status FROM accounts WHERE org_id = 1001',
    });
    expect(firstTry.ok).toBe(true);
    if (firstTry.ok) {
      detector.markLastCallFailed('s-err', firstTry.value.canonicalDigestHex);
    }

    const secondTry = detector.evaluateAndRecord('s-err', 'sql_run', {
      sql: 'SELECT id, email, status FROM accounts WHERE org_id = 1002',
    });
    expect(secondTry.ok).toBe(true);
    if (secondTry.ok) {
      detector.markLastCallFailed('s-err', secondTry.value.canonicalDigestHex);
    }

    const thirdSpiral = detector.evaluateAndRecord('s-err', 'sql_run', {
      sql: 'SELECT id, email, status FROM accounts WHERE org_id = 1003',
    });
    expect(thirdSpiral.ok).toBe(false);
    if (!thirdSpiral.ok) {
      expect(thirdSpiral.error.metadata?.tier).toBe('ERROR_RETRY_SPIRAL');
    }
  });

  it('enforces forbidden Markov edges and detects anomalous transitions without poisoning', () => {
    const graph = new MarkovCallGraph(
      {
        ...DEFAULT_SENTINEL_POLICY.intelligence,
        markovEnabled: true,
        markovMinSamples: 10,
        markovAnomalyThreshold: 0.05,
      },
      {
        forbiddenEdges: [
          {
            fromPattern: 'web_*',
            toPattern: 'shell_*',
            reason: 'Direct web-to-shell execution forbidden',
          },
        ],
        seedTransitions: [
          { fromTool: MARKOV_START_STATE, toTool: 'auth_check', count: 20 },
          { fromTool: 'auth_check', toTool: 'db_read', count: 25 },
        ],
        enforceStatisticalBlock: true,
      },
    );

    expect(graph.evaluateAndAdvance('sess-1', 'auth_check').ok).toBe(true);

    // Unseen transition from 'auth_check' -> 'rare_admin_tool' has P = 0/26 < 0.05
    const rareRes = graph.evaluateAndAdvance('sess-1', 'rare_admin_tool');
    expect(rareRes.ok).toBe(false);

    // Deterministic forbidden transition check
    graph.resetSession('sess-2');
    const graphPermissive = new MarkovCallGraph(DEFAULT_SENTINEL_POLICY.intelligence, {
      forbiddenEdges: [{ fromPattern: 'web_*', toPattern: 'shell_*' }],
    });
    expect(graphPermissive.evaluateAndAdvance('sess-2', 'web_scrape').ok).toBe(true);
    expect(graphPermissive.evaluateAndAdvance('sess-2', 'shell_exec').ok).toBe(false);
  });

  it('catches both Welford Z-score spikes and Page CUSUM sustained drift drains', () => {
    const detector = new CusumAnomalyDetector({
      ...DEFAULT_SENTINEL_POLICY.intelligence,
      cusumEnabled: true,
      cusumDriftMicroUsd: 500,
      cusumThresholdMicroUsd: 3_500,
      zScoreThreshold: 3.0,
    });

    // Establish stable baseline around ~1,000 uUSD across 6 calls
    for (const sample of [980, 1020, 990, 1010, 1000, 1000]) {
      detector.recordActualSpend('sess-spike', sample);
      detector.recordActualSpend('sess-drift', sample);
    }

    // Sudden 2,800 uUSD spike (below CUSUM 3,500 ceiling, but >50 sigma above ~1,000 mean!)
    const spikeRes = detector.checkProjectedSpend('sess-spike', 2_800);
    expect(spikeRes.ok).toBe(false);
    if (!spikeRes.ok) {
      expect(spikeRes.error.metadata?.anomalyType).toBe('WELFORD_ZSCORE_SPIKE');
    }

    // Slow sustained drift using wider baseline variance so single calls stay under Z-score 10σ
    const driftDetector = new CusumAnomalyDetector({
      ...DEFAULT_SENTINEL_POLICY.intelligence,
      cusumEnabled: true,
      cusumDriftMicroUsd: 200,
      cusumThresholdMicroUsd: 2_500,
      zScoreThreshold: 10.0,
    });
    for (const sample of [800, 1200, 900, 1100, 1000, 1000]) {
      driftDetector.recordActualSpend('s-salami', sample);
    }
    // Repeated moderately elevated 2,000 uUSD calls accumulate CUSUM past 2,500 uUSD
    driftDetector.recordActualSpend('s-salami', 2_000);
    driftDetector.recordActualSpend('s-salami', 2_000);
    driftDetector.recordActualSpend('s-salami', 2_000);
    const driftBreach = driftDetector.checkProjectedSpend('s-salami', 2_000);
    expect(driftBreach.ok).toBe(false);
    if (!driftBreach.ok) {
      expect(driftBreach.error.metadata?.anomalyType).toBe('CUSUM_DRIFT_BREACH');
    }
  });
});
