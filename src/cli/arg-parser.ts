import { createSentinelError, type SentinelError } from '../types/errors.js';
import type { ExecutionMode } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';

export interface ProxyCommandArgs {
  readonly kind: 'proxy';
  readonly configPath?: string;
  readonly mode?: ExecutionMode;
  readonly auditLogPath?: string;
  readonly metricsPort?: number;
  readonly upstreamTimeoutMs?: number;
  readonly command: string;
  readonly commandArgs: readonly string[];
}

export interface CompilePolicyCommandArgs {
  readonly kind: 'compile-policy';
  readonly configPath: string;
}

export interface ReplayCommandArgs {
  readonly kind: 'replay';
  readonly auditLogPath: string;
  readonly candidateConfigPath: string;
  readonly baselineConfigPath?: string;
}

export interface ProveAuditCommandArgs {
  readonly kind: 'prove-audit';
  readonly auditLogPath: string;
  readonly leafIndex: number;
  readonly outputPath?: string;
}

export interface VerifyAuditCommandArgs {
  readonly kind: 'verify-audit';
  readonly auditLogPath: string;
  readonly publicKeyPath?: string;
  readonly proofPath?: string;
}

export interface KeygenCommandArgs {
  readonly kind: 'keygen';
  readonly outDir: string;
  readonly prefix: string;
}

export interface HelpOrVersionCommandArgs {
  readonly kind: 'help' | 'version';
}

export type ParsedCliCommand =
  | ProxyCommandArgs
  | CompilePolicyCommandArgs
  | ReplayCommandArgs
  | ProveAuditCommandArgs
  | VerifyAuditCommandArgs
  | KeygenCommandArgs
  | HelpOrVersionCommandArgs;

export const CLI_HELP_TEXT = `mcp-sentinel v1.0.0 — Zero-Trust Runtime Security Mesh & FinOps Firewall for MCP

Usage:
  mcp-sentinel [proxy] [options] -- <command> [args...]
  mcp-sentinel compile-policy --config <policy.json>
  mcp-sentinel replay <audit.jsonl> --config <candidate.json> [--baseline <base.json>]
  mcp-sentinel prove-audit <audit.jsonl> --index <leafIndex> [--output <proof.json>]
  mcp-sentinel verify-audit <audit.jsonl> [--public-key <pub.pem>] [--proof <proof.json>]
  mcp-sentinel keygen [--out-dir <dir>] [--prefix <name>]

Proxy Options:
  --config <path>          Path to Sentinel policy JSON file
  --mode <mode>            Override mode: ENFORCE | SHADOW | AUDIT_ONLY
  --audit-log <path>       Append RFC-6962 Merkle forensic records to JSONL file
  --metrics-port <port>    Enable Prometheus /metrics & live SSE server on 127.0.0.1:<port>
  --timeout-ms <ms>        Upstream MCP tool timeout in milliseconds (default: 30000)

Global Flags:
  -h, --help               Show this help message
  -v, --version            Print mcp-sentinel version
`;

function readFlagValue(
  argv: readonly string[],
  index: number,
  flagName: string,
): Result<string, SentinelError> {
  const val = argv[index + 1];
  if (val === undefined || val.startsWith('-')) {
    return err(
      createSentinelError('INVALID_PARAMS', `Missing value for CLI flag "${flagName}"`, 'cli-args'),
    );
  }
  return ok(val);
}

/**
 * Strict zero-dependency command-line parser supporting all 6 operational subcommands.
 */
export function parseCliArgs(rawArgv: readonly string[]): Result<ParsedCliCommand, SentinelError> {
  if (rawArgv.length === 0) {
    return ok({ kind: 'help' });
  }

  const first = rawArgv[0];
  if (first === '-h' || first === '--help' || first === 'help') {
    return ok({ kind: 'help' });
  }
  if (first === '-v' || first === '--version' || first === 'version') {
    return ok({ kind: 'version' });
  }

  if (first === 'compile-policy') {
    let configPath: string | undefined;
    for (let i = 1; i < rawArgv.length; i += 1) {
      const arg = rawArgv[i];
      if (arg === '--config' || arg === '-c') {
        const valRes = readFlagValue(rawArgv, i, arg);
        if (!valRes.ok) return valRes;
        configPath = valRes.value;
        i += 1;
        continue;
      }
      return err(
        createSentinelError(
          'INVALID_PARAMS',
          `Unknown option "${String(arg)}" for compile-policy`,
          'cli-args',
        ),
      );
    }
    if (configPath === undefined) {
      return err(
        createSentinelError(
          'INVALID_PARAMS',
          'compile-policy requires --config <policy.json>',
          'cli-args',
        ),
      );
    }
    return ok({ kind: 'compile-policy', configPath });
  }

  if (first === 'replay') {
    let auditLogPath: string | undefined;
    let candidateConfigPath: string | undefined;
    let baselineConfigPath: string | undefined;

    for (let i = 1; i < rawArgv.length; i += 1) {
      const arg = rawArgv[i];
      if (arg === undefined) continue;
      if (arg === '--config' || arg === '-c') {
        const valRes = readFlagValue(rawArgv, i, arg);
        if (!valRes.ok) return valRes;
        candidateConfigPath = valRes.value;
        i += 1;
        continue;
      }
      if (arg === '--baseline') {
        const valRes = readFlagValue(rawArgv, i, arg);
        if (!valRes.ok) return valRes;
        baselineConfigPath = valRes.value;
        i += 1;
        continue;
      }
      if (!arg.startsWith('-') && auditLogPath === undefined) {
        auditLogPath = arg;
        continue;
      }
      return err(
        createSentinelError('INVALID_PARAMS', `Unknown replay argument "${arg}"`, 'cli-args'),
      );
    }

    if (auditLogPath === undefined || candidateConfigPath === undefined) {
      return err(
        createSentinelError(
          'INVALID_PARAMS',
          'Usage: mcp-sentinel replay <audit.jsonl> --config <candidate.json> [--baseline <base.json>]',
          'cli-args',
        ),
      );
    }

    return ok({
      kind: 'replay',
      auditLogPath,
      candidateConfigPath,
      ...(baselineConfigPath !== undefined ? { baselineConfigPath } : {}),
    });
  }

  if (first === 'prove-audit') {
    let auditLogPath: string | undefined;
    let leafIndex: number | undefined;
    let outputPath: string | undefined;

    for (let i = 1; i < rawArgv.length; i += 1) {
      const arg = rawArgv[i];
      if (arg === undefined) continue;
      if (arg === '--index' || arg === '-i') {
        const valRes = readFlagValue(rawArgv, i, arg);
        if (!valRes.ok) return valRes;
        const parsedIdx = Number.parseInt(valRes.value, 10);
        if (!Number.isInteger(parsedIdx) || parsedIdx < 0) {
          return err(
            createSentinelError(
              'INVALID_PARAMS',
              `--index must be a non-negative integer, got "${valRes.value}"`,
              'cli-args',
            ),
          );
        }
        leafIndex = parsedIdx;
        i += 1;
        continue;
      }
      if (arg === '--output' || arg === '-o') {
        const valRes = readFlagValue(rawArgv, i, arg);
        if (!valRes.ok) return valRes;
        outputPath = valRes.value;
        i += 1;
        continue;
      }
      if (!arg.startsWith('-') && auditLogPath === undefined) {
        auditLogPath = arg;
        continue;
      }
      return err(
        createSentinelError('INVALID_PARAMS', `Unknown prove-audit argument "${arg}"`, 'cli-args'),
      );
    }

    if (auditLogPath === undefined || leafIndex === undefined) {
      return err(
        createSentinelError(
          'INVALID_PARAMS',
          'Usage: mcp-sentinel prove-audit <audit.jsonl> --index <leafIndex> [--output <proof.json>]',
          'cli-args',
        ),
      );
    }

    return ok({
      kind: 'prove-audit',
      auditLogPath,
      leafIndex,
      ...(outputPath !== undefined ? { outputPath } : {}),
    });
  }

  if (first === 'verify-audit') {
    let auditLogPath: string | undefined;
    let publicKeyPath: string | undefined;
    let proofPath: string | undefined;

    for (let i = 1; i < rawArgv.length; i += 1) {
      const arg = rawArgv[i];
      if (arg === undefined) continue;
      if (arg === '--public-key') {
        const valRes = readFlagValue(rawArgv, i, arg);
        if (!valRes.ok) return valRes;
        publicKeyPath = valRes.value;
        i += 1;
        continue;
      }
      if (arg === '--proof') {
        const valRes = readFlagValue(rawArgv, i, arg);
        if (!valRes.ok) return valRes;
        proofPath = valRes.value;
        i += 1;
        continue;
      }
      if (!arg.startsWith('-') && auditLogPath === undefined) {
        auditLogPath = arg;
        continue;
      }
      return err(
        createSentinelError('INVALID_PARAMS', `Unknown verify-audit argument "${arg}"`, 'cli-args'),
      );
    }

    if (auditLogPath === undefined) {
      return err(
        createSentinelError(
          'INVALID_PARAMS',
          'Usage: mcp-sentinel verify-audit <audit.jsonl> [--public-key <pub.pem>] [--proof <proof.json>]',
          'cli-args',
        ),
      );
    }

    return ok({
      kind: 'verify-audit',
      auditLogPath,
      ...(publicKeyPath !== undefined ? { publicKeyPath } : {}),
      ...(proofPath !== undefined ? { proofPath } : {}),
    });
  }

  if (first === 'keygen') {
    let outDir = '.';
    let prefix = 'sentinel-ed25519';

    for (let i = 1; i < rawArgv.length; i += 1) {
      const arg = rawArgv[i];
      if (arg === undefined) continue;
      if (arg === '--out-dir') {
        const valRes = readFlagValue(rawArgv, i, arg);
        if (!valRes.ok) return valRes;
        outDir = valRes.value;
        i += 1;
        continue;
      }
      if (arg === '--prefix') {
        const valRes = readFlagValue(rawArgv, i, arg);
        if (!valRes.ok) return valRes;
        prefix = valRes.value;
        i += 1;
        continue;
      }
      return err(
        createSentinelError('INVALID_PARAMS', `Unknown keygen argument "${arg}"`, 'cli-args'),
      );
    }

    return ok({ kind: 'keygen', outDir, prefix });
  }

  // Default / explicit `proxy` subcommand
  const startIdx = first === 'proxy' ? 1 : 0;
  const separatorIdx = rawArgv.indexOf('--', startIdx);
  if (separatorIdx === -1) {
    return err(
      createSentinelError(
        'INVALID_PARAMS',
        'Proxy mode requires "-- <command> [args...]" separator to specify upstream MCP server',
        'cli-args',
      ),
    );
  }

  const optionTokens = rawArgv.slice(startIdx, separatorIdx);
  const commandTokens = rawArgv.slice(separatorIdx + 1);
  const targetCommand = commandTokens[0];

  if (targetCommand === undefined || targetCommand.trim().length === 0) {
    return err(
      createSentinelError(
        'INVALID_PARAMS',
        'Missing upstream MCP server executable after "--"',
        'cli-args',
      ),
    );
  }

  let configPath: string | undefined;
  let mode: ExecutionMode | undefined;
  let auditLogPath: string | undefined;
  let metricsPort: number | undefined;
  let upstreamTimeoutMs: number | undefined;

  for (let i = 0; i < optionTokens.length; i += 1) {
    const opt = optionTokens[i];
    if (opt === undefined) continue;

    if (opt === '--config' || opt === '-c') {
      const valRes = readFlagValue(optionTokens, i, opt);
      if (!valRes.ok) return valRes;
      configPath = valRes.value;
      i += 1;
      continue;
    }

    if (opt === '--mode') {
      const valRes = readFlagValue(optionTokens, i, opt);
      if (!valRes.ok) return valRes;
      if (valRes.value !== 'ENFORCE' && valRes.value !== 'SHADOW' && valRes.value !== 'AUDIT_ONLY') {
        return err(
          createSentinelError(
            'INVALID_PARAMS',
            `Invalid --mode "${valRes.value}"; expected ENFORCE, SHADOW, or AUDIT_ONLY`,
            'cli-args',
          ),
        );
      }
      mode = valRes.value;
      i += 1;
      continue;
    }

    if (opt === '--audit-log') {
      const valRes = readFlagValue(optionTokens, i, opt);
      if (!valRes.ok) return valRes;
      auditLogPath = valRes.value;
      i += 1;
      continue;
    }

    if (opt === '--metrics-port') {
      const valRes = readFlagValue(optionTokens, i, opt);
      if (!valRes.ok) return valRes;
      const port = Number.parseInt(valRes.value, 10);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        return err(
          createSentinelError(
            'INVALID_PARAMS',
            `Invalid --metrics-port "${valRes.value}"; expected integer in 1..65535`,
            'cli-args',
          ),
        );
      }
      metricsPort = port;
      i += 1;
      continue;
    }

    if (opt === '--timeout-ms') {
      const valRes = readFlagValue(optionTokens, i, opt);
      if (!valRes.ok) return valRes;
      const timeout = Number.parseInt(valRes.value, 10);
      if (!Number.isInteger(timeout) || timeout < 100) {
        return err(
          createSentinelError(
            'INVALID_PARAMS',
            `Invalid --timeout-ms "${valRes.value}"; expected integer >= 100`,
            'cli-args',
          ),
        );
      }
      upstreamTimeoutMs = timeout;
      i += 1;
      continue;
    }

    return err(
      createSentinelError('INVALID_PARAMS', `Unknown proxy option "${opt}"`, 'cli-args'),
    );
  }

  return ok({
    kind: 'proxy',
    command: targetCommand,
    commandArgs: commandTokens.slice(1),
    ...(configPath !== undefined ? { configPath } : {}),
    ...(mode !== undefined ? { mode } : {}),
    ...(auditLogPath !== undefined ? { auditLogPath } : {}),
    ...(metricsPort !== undefined ? { metricsPort } : {}),
    ...(upstreamTimeoutMs !== undefined ? { upstreamTimeoutMs } : {}),
  });
}
