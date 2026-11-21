#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import process from 'node:process';
import { mergeSentinelPolicy, SentinelKernel } from '../core/engine.js';
import { SplPolicyEngine } from '../dsl/vm.js';
import { CounterfactualPolicyReplayer } from '../forensics/counterfactual-replayer.js';
import { generateEd25519KeyPair } from '../forensics/ed25519-notary.js';
import { parseAuditJsonl, verifyJsonlAuditLog } from '../forensics/flight-recorder.js';
import {
  type MerkleInclusionProof,
  Rfc6962MerkleTree,
  verifyInclusionProof,
} from '../forensics/merkle-tree.js';
import { formatMicroUsdAsUsd } from '../ledger/cost-model.js';
import { StdioReverseProxy } from '../transports/stdio-proxy.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import { isJsonObject } from '../types/jsonrpc.js';
import { DEFAULT_SENTINEL_POLICY, type SentinelPolicy } from '../types/policy.js';
import { err, type Result } from '../types/result.js';
import { CLI_HELP_TEXT, parseCliArgs } from './arg-parser.js';

const PACKAGE_VERSION = '1.0.0';

function loadPolicyFile(filePath: string): Result<SentinelPolicy, SentinelError> {
  try {
    const rawText = readFileSync(filePath, 'utf8');
    const parsedJson: unknown = JSON.parse(rawText);
    return mergeSentinelPolicy(parsedJson);
  } catch (cause: unknown) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    return err(
      createSentinelError(
        'INVALID_PARAMS',
        `Failed to load policy file "${filePath}": ${detail}`,
        'cli-loader',
      ),
    );
  }
}

async function runCli(argv: readonly string[]): Promise<number> {
  const parsedRes = parseCliArgs(argv);
  if (!parsedRes.ok) {
    process.stderr.write(`[mcp-sentinel] Argument error: ${parsedRes.error.message}\n\n`);
    process.stderr.write(`${CLI_HELP_TEXT}\n`);
    return 2;
  }

  const cmd = parsedRes.value;

  switch (cmd.kind) {
    case 'help': {
      process.stdout.write(`${CLI_HELP_TEXT}\n`);
      return 0;
    }

    case 'version': {
      process.stdout.write(`mcp-sentinel v${PACKAGE_VERSION}\n`);
      return 0;
    }

    case 'keygen': {
      mkdirSync(cmd.outDir, { recursive: true });
      const kp = generateEd25519KeyPair();
      const privPath = join(cmd.outDir, `${cmd.prefix}.private.pem`);
      const pubPath = join(cmd.outDir, `${cmd.prefix}.public.pem`);
      writeFileSync(privPath, kp.privateKeyPem, { encoding: 'utf8', mode: 0o600 });
      writeFileSync(pubPath, kp.publicKeyPem, { encoding: 'utf8', mode: 0o644 });
      process.stdout.write(
        `${JSON.stringify(
          {
            status: 'generated',
            keyId: kp.keyId,
            privateKeyPath: privPath,
            publicKeyPath: pubPath,
          },
          null,
          2,
        )}\n`,
      );
      return 0;
    }

    case 'compile-policy': {
      const policyRes = loadPolicyFile(cmd.configPath);
      if (!policyRes.ok) {
        process.stderr.write(`[mcp-sentinel] ${policyRes.error.message}\n`);
        return 1;
      }
      const splRes = SplPolicyEngine.compile(policyRes.value.splRules, policyRes.value.maxVmGas);
      if (!splRes.ok) {
        process.stderr.write(`[mcp-sentinel] SPL compile error: ${splRes.error.message}\n`);
        return 1;
      }
      const kernelCheck = SentinelKernel.create(policyRes.value);
      if (!kernelCheck.ok) {
        process.stderr.write(
          `[mcp-sentinel] Policy validation failed: ${kernelCheck.error.message}\n`,
        );
        return 1;
      }
      process.stdout.write(
        `${JSON.stringify(
          {
            status: 'valid',
            mode: policyRes.value.mode,
            compiledSplRules: policyRes.value.splRules.length,
            maxVmGas: policyRes.value.maxVmGas,
            warnings: splRes.value.warnings,
          },
          null,
          2,
        )}\n`,
      );
      return 0;
    }

    case 'replay': {
      const jsonlContent = readFileSync(cmd.auditLogPath, 'utf8');
      const candRes = loadPolicyFile(cmd.candidateConfigPath);
      if (!candRes.ok) {
        process.stderr.write(`[mcp-sentinel] ${candRes.error.message}\n`);
        return 1;
      }

      let baselinePolicy: SentinelPolicy | undefined;
      if (cmd.baselineConfigPath !== undefined) {
        const baseRes = loadPolicyFile(cmd.baselineConfigPath);
        if (!baseRes.ok) {
          process.stderr.write(`[mcp-sentinel] ${baseRes.error.message}\n`);
          return 1;
        }
        baselinePolicy = baseRes.value;
      }

      const replayer = new CounterfactualPolicyReplayer();
      const reportRes = await replayer.replayJsonl({
        jsonlContent,
        candidatePolicy: candRes.value,
        ...(baselinePolicy !== undefined ? { baselinePolicy } : {}),
      });

      if (!reportRes.ok) {
        process.stderr.write(`[mcp-sentinel] Replay failed: ${reportRes.error.message}\n`);
        return 1;
      }

      const report = reportRes.value;
      process.stdout.write(
        `${JSON.stringify(
          {
            ...report,
            preventedSpendUsd: formatMicroUsdAsUsd(report.preventedSpendMicroUsd),
          },
          null,
          2,
        )}\n`,
      );
      return 0;
    }

    case 'prove-audit': {
      const jsonlContent = readFileSync(cmd.auditLogPath, 'utf8');
      const parsedLogRes = parseAuditJsonl(jsonlContent);
      if (!parsedLogRes.ok) {
        process.stderr.write(`[mcp-sentinel] ${parsedLogRes.error.message}\n`);
        return 1;
      }

      const tree = new Rfc6962MerkleTree();
      for (const rec of parsedLogRes.value) {
        const appendRes = tree.appendCanonicalJson({
          sequence: rec.sequence,
          timestampMs: rec.timestampMs,
          requestId: rec.requestId,
          traceparent: rec.traceparent,
          tenantId: rec.tenantId,
          sessionId: rec.sessionId,
          method: rec.method,
          mode: rec.mode,
          outcome: rec.outcome,
          stage: rec.stage,
          latencyMicros: rec.latencyMicros,
          estimatedMicroUsd: rec.estimatedMicroUsd,
          settledMicroUsd: rec.settledMicroUsd,
          confidentiality: rec.confidentiality,
          integrity: rec.integrity,
          ...(rec.toolName !== undefined ? { toolName: rec.toolName } : {}),
          ...(rec.sanitizedArgs !== undefined ? { sanitizedArgs: rec.sanitizedArgs } : {}),
          ...(rec.errorCode !== undefined ? { errorCode: rec.errorCode } : {}),
          ...(rec.errorName !== undefined ? { errorName: rec.errorName } : {}),
          ...(rec.reason !== undefined ? { reason: rec.reason } : {}),
        });
        if (!appendRes.ok) {
          process.stderr.write(`[mcp-sentinel] ${appendRes.error.message}\n`);
          return 1;
        }
      }

      const proofRes = tree.generateInclusionProof(cmd.leafIndex);
      if (!proofRes.ok) {
        process.stderr.write(`[mcp-sentinel] ${proofRes.error.message}\n`);
        return 1;
      }

      const serializedProof = JSON.stringify(proofRes.value, null, 2);
      if (cmd.outputPath !== undefined) {
        writeFileSync(cmd.outputPath, `${serializedProof}\n`, 'utf8');
      } else {
        process.stdout.write(`${serializedProof}\n`);
      }
      return 0;
    }

    case 'verify-audit': {
      const jsonlContent = readFileSync(cmd.auditLogPath, 'utf8');
      const pubKeyPem =
        cmd.publicKeyPath !== undefined ? readFileSync(cmd.publicKeyPath, 'utf8') : undefined;

      const verifyRes = verifyJsonlAuditLog(jsonlContent, pubKeyPem);
      if (!verifyRes.ok) {
        process.stderr.write(
          `[mcp-sentinel] AUDIT TAMPERING OR ERROR: ${verifyRes.error.message}\n`,
        );
        return 1;
      }

      let inclusionProofVerified: boolean | undefined;
      if (cmd.proofPath !== undefined) {
        const rawProof: unknown = JSON.parse(readFileSync(cmd.proofPath, 'utf8'));
        if (
          !isJsonObject(rawProof) ||
          typeof rawProof.leafIndex !== 'number' ||
          typeof rawProof.treeSize !== 'number' ||
          typeof rawProof.leafHashHex !== 'string' ||
          typeof rawProof.rootHashHex !== 'string' ||
          !Array.isArray(rawProof.auditPathHex)
        ) {
          process.stderr.write('[mcp-sentinel] Malformed Merkle inclusion proof JSON\n');
          return 1;
        }
        const proofValid = verifyInclusionProof(rawProof as unknown as MerkleInclusionProof);
        if (
          !proofValid ||
          rawProof.rootHashHex.toLowerCase() !== verifyRes.value.finalRootHashHex.toLowerCase()
        ) {
          process.stderr.write('[mcp-sentinel] Inclusion proof verification FAILED\n');
          return 1;
        }
        inclusionProofVerified = true;
      }

      process.stdout.write(
        `${JSON.stringify(
          {
            status: 'verified',
            ...verifyRes.value,
            ...(inclusionProofVerified !== undefined ? { inclusionProofVerified } : {}),
          },
          null,
          2,
        )}\n`,
      );
      return 0;
    }

    case 'proxy': {
      let basePolicy: SentinelPolicy = DEFAULT_SENTINEL_POLICY;
      if (cmd.configPath !== undefined) {
        const loaded = loadPolicyFile(cmd.configPath);
        if (!loaded.ok) {
          process.stderr.write(`[mcp-sentinel] ${loaded.error.message}\n`);
          return 1;
        }
        basePolicy = loaded.value;
      }

      const effectivePolicy: SentinelPolicy = {
        ...basePolicy,
        ...(cmd.mode !== undefined ? { mode: cmd.mode } : {}),
        forensics: {
          ...basePolicy.forensics,
          ...(cmd.auditLogPath !== undefined
            ? { enabled: true, logFilePath: cmd.auditLogPath }
            : {}),
        },
        telemetry: {
          ...basePolicy.telemetry,
          ...(cmd.metricsPort !== undefined ? { enabled: true, port: cmd.metricsPort } : {}),
        },
      };

      const kernelRes = SentinelKernel.create(effectivePolicy);
      if (!kernelRes.ok) {
        process.stderr.write(`[mcp-sentinel] Kernel boot error: ${kernelRes.error.message}\n`);
        return 1;
      }

      const proxy = new StdioReverseProxy({
        kernel: kernelRes.value,
        upstream: {
          command: cmd.command,
          args: cmd.commandArgs,
        },
        ...(cmd.upstreamTimeoutMs !== undefined
          ? { upstreamTimeoutMs: cmd.upstreamTimeoutMs }
          : {}),
      });

      const shutdown = (): void => {
        void proxy.stop().finally(() => {
          process.exit(0);
        });
      };

      process.once('SIGINT', shutdown);
      process.once('SIGTERM', shutdown);

      await proxy.start();
      return 0;
    }
  }
}

void runCli(process.argv.slice(2))
  .then((code) => {
    if (code !== 0) {
      process.exitCode = code;
    }
  })
  .catch((fatal: unknown) => {
    const message = fatal instanceof Error ? fatal.message : String(fatal);
    process.stderr.write(`[mcp-sentinel] Fatal CLI error: ${message}\n`);
    process.exitCode = 1;
  });
