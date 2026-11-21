import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { constantTimeEqualHex } from '../core/canonical.js';
import type { Clock } from '../core/clock.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import { isJsonObject, type JsonObject } from '../types/jsonrpc.js';
import {
  type ConfidentialityLevel,
  type IntegrityLevel,
  isValidConfidentiality,
  isValidIntegrity,
} from '../types/lattice.js';
import type { ExecutionMode, ForensicsConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';
import {
  type SignedTreeHead,
  signMerkleTreeHead,
  verifySignedTreeHead,
} from './ed25519-notary.js';
import {
  type MerkleConsistencyProof,
  type MerkleInclusionProof,
  Rfc6962MerkleTree,
} from './merkle-tree.js';

export type AuditDecisionOutcome =
  | 'ALLOWED'
  | 'BLOCKED'
  | 'SHADOW_FLAGGED'
  | 'CACHE_HIT'
  | 'UPSTREAM_ERROR';

export interface AuditCorePayload {
  readonly sequence: number;
  readonly timestampMs: number;
  readonly requestId: string;
  readonly traceparent: string;
  readonly tenantId: string;
  readonly sessionId: string;
  readonly method: string;
  readonly toolName?: string;
  readonly mode: ExecutionMode;
  readonly outcome: AuditDecisionOutcome;
  readonly stage: string;
  readonly latencyMicros: number;
  readonly estimatedMicroUsd: number;
  readonly settledMicroUsd: number;
  readonly confidentiality: ConfidentialityLevel;
  readonly integrity: IntegrityLevel;
  readonly sanitizedArgs?: JsonObject;
  readonly errorCode?: number;
  readonly errorName?: string;
  readonly reason?: string;
}

export interface ForensicAuditRecord extends AuditCorePayload {
  readonly merkleLeafHashHex: string;
  readonly merkleRootHashHex: string;
  readonly signedTreeHead?: SignedTreeHead;
}

export type RecordAuditEventInput = Omit<AuditCorePayload, 'sequence' | 'timestampMs'>;

export type AuditRecordSubscriber = (record: ForensicAuditRecord) => void;

export interface AuditLogVerificationReport {
  readonly verifiedRecords: number;
  readonly finalRootHashHex: string;
  readonly verifiedSignatures: number;
}

const VALID_MODES: ReadonlySet<string> = new Set(['ENFORCE', 'SHADOW', 'AUDIT_ONLY']);
const VALID_OUTCOMES: ReadonlySet<string> = new Set([
  'ALLOWED',
  'BLOCKED',
  'SHADOW_FLAGGED',
  'CACHE_HIT',
  'UPSTREAM_ERROR',
]);

function extractCorePayloadFromRecord(raw: JsonObject): Result<AuditCorePayload, SentinelError> {
  if (
    typeof raw.sequence !== 'number' ||
    !Number.isInteger(raw.sequence) ||
    typeof raw.timestampMs !== 'number' ||
    typeof raw.requestId !== 'string' ||
    typeof raw.traceparent !== 'string' ||
    typeof raw.tenantId !== 'string' ||
    typeof raw.sessionId !== 'string' ||
    typeof raw.method !== 'string' ||
    typeof raw.mode !== 'string' ||
    !VALID_MODES.has(raw.mode) ||
    typeof raw.outcome !== 'string' ||
    !VALID_OUTCOMES.has(raw.outcome) ||
    typeof raw.stage !== 'string' ||
    typeof raw.latencyMicros !== 'number' ||
    typeof raw.estimatedMicroUsd !== 'number' ||
    typeof raw.settledMicroUsd !== 'number' ||
    typeof raw.confidentiality !== 'string' ||
    !isValidConfidentiality(raw.confidentiality) ||
    typeof raw.integrity !== 'string' ||
    !isValidIntegrity(raw.integrity)
  ) {
    return err(
      createSentinelError(
        'INVALID_PARAMS',
        `Malformed forensic audit record fields at sequence ${String(raw.sequence)}`,
        'flight-recorder',
      ),
    );
  }

  const base: AuditCorePayload = {
    sequence: raw.sequence,
    timestampMs: raw.timestampMs,
    requestId: raw.requestId,
    traceparent: raw.traceparent,
    tenantId: raw.tenantId,
    sessionId: raw.sessionId,
    method: raw.method,
    mode: raw.mode as ExecutionMode,
    outcome: raw.outcome as AuditDecisionOutcome,
    stage: raw.stage,
    latencyMicros: raw.latencyMicros,
    estimatedMicroUsd: raw.estimatedMicroUsd,
    settledMicroUsd: raw.settledMicroUsd,
    confidentiality: raw.confidentiality,
    integrity: raw.integrity,
  };

  return ok({
    ...base,
    ...(typeof raw.toolName === 'string' ? { toolName: raw.toolName } : {}),
    ...(isJsonObject(raw.sanitizedArgs) ? { sanitizedArgs: raw.sanitizedArgs } : {}),
    ...(typeof raw.errorCode === 'number' ? { errorCode: raw.errorCode } : {}),
    ...(typeof raw.errorName === 'string' ? { errorName: raw.errorName } : {}),
    ...(typeof raw.reason === 'string' ? { reason: raw.reason } : {}),
  });
}

/**
 * Parses raw `.jsonl` forensic audit content into strongly-typed `ForensicAuditRecord` items.
 */
export function parseAuditJsonl(
  jsonlContent: string,
): Result<readonly ForensicAuditRecord[], SentinelError> {
  const lines = jsonlContent
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  const records: ForensicAuditRecord[] = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (line === undefined) continue;

    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      return err(
        createSentinelError(
          'PARSE_ERROR',
          `Invalid JSON on line ${i + 1} of audit log`,
          'flight-recorder',
        ),
      );
    }

    if (
      !isJsonObject(parsed) ||
      typeof parsed.merkleLeafHashHex !== 'string' ||
      typeof parsed.merkleRootHashHex !== 'string'
    ) {
      return err(
        createSentinelError(
          'INVALID_PARAMS',
          `Missing Merkle hash envelopes on line ${i + 1} of audit log`,
          'flight-recorder',
        ),
      );
    }

    const coreRes = extractCorePayloadFromRecord(parsed);
    if (!coreRes.ok) {
      return coreRes;
    }

    let sth: SignedTreeHead | undefined;
    if (isJsonObject(parsed.signedTreeHead)) {
      const s = parsed.signedTreeHead;
      if (
        s.version === 'STH-v1' &&
        typeof s.treeSize === 'number' &&
        typeof s.timestampMs === 'number' &&
        typeof s.rootHashHex === 'string' &&
        typeof s.keyId === 'string' &&
        typeof s.signatureBase64 === 'string'
      ) {
        sth = {
          version: 'STH-v1',
          treeSize: s.treeSize,
          timestampMs: s.timestampMs,
          rootHashHex: s.rootHashHex,
          keyId: s.keyId,
          signatureBase64: s.signatureBase64,
        };
      } else {
        return err(
          createSentinelError(
            'INVALID_PARAMS',
            `Malformed signedTreeHead on line ${i + 1}`,
            'flight-recorder',
          ),
        );
      }
    }

    records.push({
      ...coreRes.value,
      merkleLeafHashHex: parsed.merkleLeafHashHex,
      merkleRootHashHex: parsed.merkleRootHashHex,
      ...(sth !== undefined ? { signedTreeHead: sth } : {}),
    });
  }

  return ok(records);
}

/**
 * Reconstructs the entire RFC-6962 Merkle Tree from a JSONL audit log and
 * cryptographically verifies every leaf digest, cumulative root hash, sequence
 * monotonicity, and optional Ed25519 Signed Tree Head signature.
 */
export function verifyJsonlAuditLog(
  jsonlContent: string,
  publicKeyPem?: string,
): Result<AuditLogVerificationReport, SentinelError> {
  const parsedRes = parseAuditJsonl(jsonlContent);
  if (!parsedRes.ok) {
    return parsedRes;
  }

  const records = parsedRes.value;
  const tree = new Rfc6962MerkleTree();
  let verifiedSignatures = 0;

  for (let idx = 0; idx < records.length; idx += 1) {
    const rec = records[idx];
    if (rec === undefined) continue;

    if (rec.sequence !== idx) {
      return err(
        createSentinelError(
          'SCHEMA_INTEGRITY_VIOLATION',
          `Audit sequence gap or reordering detected at index ${idx}: found sequence ${rec.sequence}`,
          'flight-recorder',
        ),
      );
    }

    const corePayload: AuditCorePayload = {
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
    };

    const appended = tree.appendCanonicalJson(corePayload);
    if (!appended.ok) {
      return appended;
    }

    if (!constantTimeEqualHex(appended.value.leafHashHex, rec.merkleLeafHashHex.toLowerCase())) {
      return err(
        createSentinelError(
          'SCHEMA_INTEGRITY_VIOLATION',
          `Tampered audit record detected at sequence ${idx}: leaf hash mismatch`,
          'flight-recorder',
          { sequence: idx },
        ),
      );
    }

    if (!constantTimeEqualHex(appended.value.rootHashHex, rec.merkleRootHashHex.toLowerCase())) {
      return err(
        createSentinelError(
          'SCHEMA_INTEGRITY_VIOLATION',
          `Tampered audit chain detected at sequence ${idx}: Merkle root mismatch`,
          'flight-recorder',
          { sequence: idx },
        ),
      );
    }

    if (publicKeyPem !== undefined) {
      if (rec.signedTreeHead === undefined) {
        return err(
          createSentinelError(
            'SCHEMA_INTEGRITY_VIOLATION',
            `Missing required Ed25519 SignedTreeHead at sequence ${idx}`,
            'flight-recorder',
          ),
        );
      }
      if (
        rec.signedTreeHead.treeSize !== idx + 1 ||
        !constantTimeEqualHex(
          rec.signedTreeHead.rootHashHex.toLowerCase(),
          appended.value.rootHashHex,
        )
      ) {
        return err(
          createSentinelError(
            'SCHEMA_INTEGRITY_VIOLATION',
            `SignedTreeHead metadata mismatch at sequence ${idx}`,
            'flight-recorder',
          ),
        );
      }
      const sigRes = verifySignedTreeHead(rec.signedTreeHead, publicKeyPem);
      if (!sigRes.ok) {
        return sigRes;
      }
      if (!sigRes.value) {
        return err(
          createSentinelError(
            'SCHEMA_INTEGRITY_VIOLATION',
            `Invalid Ed25519 SignedTreeHead signature at sequence ${idx}`,
            'flight-recorder',
          ),
        );
      }
      verifiedSignatures += 1;
    }
  }

  const finalRootRes = tree.rootHashHex();
  if (!finalRootRes.ok) {
    return finalRootRes;
  }

  return ok({
    verifiedRecords: records.length,
    finalRootHashHex: finalRootRes.value,
    verifiedSignatures,
  });
}

/**
 * Cryptographic Forensic Flight Recorder maintaining a live RFC-6962 Merkle Tree,
 * optional Ed25519 Signed Tree Heads, append-only JSONL persistence, and live SSE hooks.
 */
export class ForensicFlightRecorder {
  private readonly config: ForensicsConfig;
  private readonly clock: Clock;
  private readonly merkleTree = new Rfc6962MerkleTree();
  private readonly retainedRecords: ForensicAuditRecord[] = [];
  private readonly maxRetainedInMemory: number;
  private readonly subscribers = new Set<AuditRecordSubscriber>();
  private sequenceCounter = 0;
  private ensuredDirectory = false;

  public constructor(config: ForensicsConfig, clock: Clock, maxRetainedInMemory = 2_048) {
    this.config = config;
    this.clock = clock;
    this.maxRetainedInMemory = maxRetainedInMemory;
  }

  public subscribe(listener: AuditRecordSubscriber): () => void {
    this.subscribers.add(listener);
    return () => {
      this.subscribers.delete(listener);
    };
  }

  public record(input: RecordAuditEventInput): Result<ForensicAuditRecord, SentinelError> {
    const timestampMs = this.clock.nowMs();
    const sequence = this.sequenceCounter;

    const corePayload: AuditCorePayload = {
      sequence,
      timestampMs,
      ...input,
    };

    const appendRes = this.merkleTree.appendCanonicalJson(corePayload);
    if (!appendRes.ok) {
      return appendRes;
    }

    this.sequenceCounter += 1;

    let sth: SignedTreeHead | undefined;
    if (this.config.signTreeHeads && this.config.privateKeyPem !== undefined) {
      const signedRes = signMerkleTreeHead({
        treeSize: appendRes.value.treeSize,
        timestampMs,
        rootHashHex: appendRes.value.rootHashHex,
        privateKeyPem: this.config.privateKeyPem,
        ...(this.config.publicKeyPem !== undefined
          ? { publicKeyPem: this.config.publicKeyPem }
          : {}),
      });
      if (!signedRes.ok) {
        return signedRes;
      }
      sth = signedRes.value;
    }

    const fullRecord: ForensicAuditRecord = {
      ...corePayload,
      merkleLeafHashHex: appendRes.value.leafHashHex,
      merkleRootHashHex: appendRes.value.rootHashHex,
      ...(sth !== undefined ? { signedTreeHead: sth } : {}),
    };

    if (this.config.enabled) {
      if (this.retainedRecords.length >= this.maxRetainedInMemory) {
        this.retainedRecords.shift();
      }
      this.retainedRecords.push(fullRecord);

      if (this.config.logFilePath !== undefined && this.config.logFilePath.trim().length > 0) {
        try {
          if (!this.ensuredDirectory) {
            mkdirSync(dirname(this.config.logFilePath), { recursive: true });
            this.ensuredDirectory = true;
          }
          appendFileSync(this.config.logFilePath, `${JSON.stringify(fullRecord)}\n`, 'utf8');
        } catch (cause: unknown) {
          const detail = cause instanceof Error ? cause.message : String(cause);
          return err(
            createSentinelError(
              'INTERNAL_ERROR',
              `Failed to append forensic JSONL log "${this.config.logFilePath}": ${detail}`,
              'flight-recorder',
            ),
          );
        }
      }
    }

    for (const listener of this.subscribers) {
      listener(fullRecord);
    }

    return ok(fullRecord);
  }

  public getTreeSize(): number {
    return this.merkleTree.size;
  }

  public getCurrentRootHashHex(): Result<string, SentinelError> {
    return this.merkleTree.rootHashHex();
  }

  public getRecentRecords(): readonly ForensicAuditRecord[] {
    return [...this.retainedRecords];
  }

  public proveInclusion(
    leafIndex: number,
    atTreeSize?: number,
  ): Result<MerkleInclusionProof, SentinelError> {
    return this.merkleTree.generateInclusionProof(leafIndex, atTreeSize);
  }

  public proveConsistency(
    firstTreeSize: number,
    secondTreeSize?: number,
  ): Result<MerkleConsistencyProof, SentinelError> {
    return this.merkleTree.generateConsistencyProof(firstTreeSize, secondTreeSize);
  }
}
