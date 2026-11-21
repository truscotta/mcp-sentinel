import { Buffer } from 'node:buffer';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { hmacSha256Bytes, hmacSha256Hex } from '../core/canonical.js';
import type { Clock } from '../core/clock.js';
import { joinConfidentiality } from '../ifc/security-lattice.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import { isJsonObject, type JsonObject, type JsonValue } from '../types/jsonrpc.js';
import { CONFIDENTIALITY_RANK, type ConfidentialityLevel } from '../types/lattice.js';
import type { VaultConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';
import {
  type CompiledCustomVaultPattern,
  compileCustomVaultPatterns,
  type SensitiveEntityKind,
  scanSensitiveSpans,
} from './luhn-and-entropy.js';
import {
  extractSyntheticAliasesFromText,
  generateFormatPreservingAlias,
} from './synthetic-alias.js';

export interface InboundPseudonymizationReport {
  readonly sanitizedPayload: JsonValue;
  readonly pseudonymizedCount: number;
  readonly detectedKinds: readonly SensitiveEntityKind[];
  readonly highestConfidentiality: ConfidentialityLevel | null;
}

export interface OutboundDetokenizationReport {
  readonly detokenizedArgs: JsonObject;
  readonly restoredCount: number;
  readonly restoredAliases: readonly string[];
}

interface EncryptedVaultEntry {
  readonly alias: string;
  readonly plaintextHmacHex: string;
  readonly kind: SensitiveEntityKind;
  readonly originConfidentiality: ConfidentialityLevel;
  readonly iv: Buffer;
  readonly authTag: Buffer;
  readonly ciphertext: Buffer;
  expiresAtMs: number;
}

interface SessionVaultBucket {
  readonly sessionKey: Buffer;
  readonly byAlias: Map<string, EncryptedVaultEntry>;
  readonly aliasByPlaintextHmac: Map<string, string>;
}

/**
 * Bi-Directional AES-256-GCM Context Vault.
 *
 * 1. Inbound (`pseudonymizeInbound`): Encrypts sensitive PII and secrets into
 *    authenticated in-memory AES-256-GCM ciphertexts and hands format-preserving
 *    synthetic aliases to the untrusted LLM context window.
 * 2. Outbound (`detokenizeOutboundConditional`): Restores plaintext at the egress
 *    boundary ONLY if the destination tool's Bell-LaPadula `maxSinkConfidentiality`
 *    clearance dominates the vaulted entity's `originConfidentiality`.
 */
export class ReversibleContextVault {
  private readonly config: VaultConfig;
  private readonly clock: Clock;
  private readonly masterSecret: Buffer;
  private readonly customPatterns: readonly CompiledCustomVaultPattern[];
  private readonly sessions = new Map<string, SessionVaultBucket>();
  private readonly maxSessions: number;

  private constructor(
    config: VaultConfig,
    clock: Clock,
    customPatterns: readonly CompiledCustomVaultPattern[],
    maxSessions: number,
  ) {
    this.config = config;
    this.clock = clock;
    this.masterSecret = randomBytes(32);
    this.customPatterns = customPatterns;
    this.maxSessions = maxSessions;
  }

  public static create(
    config: VaultConfig,
    clock: Clock,
    maxSessions = 2_048,
  ): Result<ReversibleContextVault, SentinelError> {
    const compiled = compileCustomVaultPatterns(config.customPatterns);
    if (!compiled.ok) {
      return compiled;
    }
    return ok(new ReversibleContextVault(config, clock, compiled.value, maxSessions));
  }

  private bucketKey(tenantId: string, sessionId: string): string {
    return `${tenantId}:${sessionId}`;
  }

  private getOrCreateSessionBucket(tenantId: string, sessionId: string): SessionVaultBucket {
    const key = this.bucketKey(tenantId, sessionId);
    const existing = this.sessions.get(key);
    if (existing !== undefined) {
      this.sessions.delete(key);
      this.sessions.set(key, existing);
      return existing;
    }

    if (this.sessions.size >= this.maxSessions) {
      const oldestKey = this.sessions.keys().next().value;
      if (oldestKey !== undefined) {
        const evicted = this.sessions.get(oldestKey);
        if (evicted !== undefined) {
          this.zeroizeBucket(evicted);
        }
        this.sessions.delete(oldestKey);
      }
    }

    const derivedSessionKey = hmacSha256Bytes(this.masterSecret, `vault-aes-key:${key}`);
    const created: SessionVaultBucket = {
      sessionKey: derivedSessionKey,
      byAlias: new Map<string, EncryptedVaultEntry>(),
      aliasByPlaintextHmac: new Map<string, string>(),
    };
    this.sessions.set(key, created);
    return created;
  }

  private buildAadBuffer(
    tenantId: string,
    sessionId: string,
    alias: string,
    originConfidentiality: ConfidentialityLevel,
  ): Buffer {
    return Buffer.from(`${tenantId}|${sessionId}|${alias}|${originConfidentiality}`, 'utf8');
  }

  private storeOrReuseSecret(params: {
    readonly bucket: SessionVaultBucket;
    readonly tenantId: string;
    readonly sessionId: string;
    readonly rawValue: string;
    readonly kind: SensitiveEntityKind;
    readonly confidentiality: ConfidentialityLevel;
  }): string {
    const nowMs = this.clock.nowMs();
    const plaintextHmacHex = hmacSha256Hex(
      params.bucket.sessionKey,
      `pt:${params.kind}:${params.rawValue}`,
    );

    const existingAlias = params.bucket.aliasByPlaintextHmac.get(plaintextHmacHex);
    if (existingAlias !== undefined) {
      const existingEntry = params.bucket.byAlias.get(existingAlias);
      if (existingEntry !== undefined && nowMs < existingEntry.expiresAtMs) {
        existingEntry.expiresAtMs = nowMs + this.config.ttlMs;
        return existingAlias;
      }
    }

    let attempt = 0;
    let alias = generateFormatPreservingAlias({
      hmacSecret: params.bucket.sessionKey,
      tenantId: params.tenantId,
      sessionId: params.sessionId,
      kind: params.kind,
      rawPlaintext: params.rawValue,
      collisionAttempt: attempt,
    });

    while (params.bucket.byAlias.has(alias)) {
      attempt += 1;
      alias = generateFormatPreservingAlias({
        hmacSecret: params.bucket.sessionKey,
        tenantId: params.tenantId,
        sessionId: params.sessionId,
        kind: params.kind,
        rawPlaintext: params.rawValue,
        collisionAttempt: attempt,
      });
    }

    const iv = randomBytes(12);
    const aad = this.buildAadBuffer(
      params.tenantId,
      params.sessionId,
      alias,
      params.confidentiality,
    );
    const cipher = createCipheriv('aes-256-gcm', params.bucket.sessionKey, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(params.rawValue, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const entry: EncryptedVaultEntry = {
      alias,
      plaintextHmacHex,
      kind: params.kind,
      originConfidentiality: params.confidentiality,
      iv,
      authTag,
      ciphertext,
      expiresAtMs: nowMs + this.config.ttlMs,
    };

    params.bucket.byAlias.set(alias, entry);
    params.bucket.aliasByPlaintextHmac.set(plaintextHmacHex, alias);
    return alias;
  }

  private decryptEntry(
    bucket: SessionVaultBucket,
    tenantId: string,
    sessionId: string,
    entry: EncryptedVaultEntry,
  ): Result<string, SentinelError> {
    if (this.clock.nowMs() >= entry.expiresAtMs) {
      bucket.byAlias.delete(entry.alias);
      bucket.aliasByPlaintextHmac.delete(entry.plaintextHmacHex);
      entry.ciphertext.fill(0);
      return err(
        createSentinelError(
          'VAULT_INTEGRITY_ERROR',
          `Vault entry for synthetic alias "${entry.alias}" has expired`,
          'context-vault',
          { alias: entry.alias },
        ),
      );
    }

    try {
      const aad = this.buildAadBuffer(tenantId, sessionId, entry.alias, entry.originConfidentiality);
      const decipher = createDecipheriv('aes-256-gcm', bucket.sessionKey, entry.iv);
      decipher.setAAD(aad);
      decipher.setAuthTag(entry.authTag);
      const decrypted = Buffer.concat([decipher.update(entry.ciphertext), decipher.final()]);
      return ok(decrypted.toString('utf8'));
    } catch {
      return err(
        createSentinelError(
          'VAULT_INTEGRITY_ERROR',
          `AES-256-GCM authentication tag verification failed for alias "${entry.alias}"`,
          'context-vault',
          { alias: entry.alias },
        ),
      );
    }
  }

  /**
   * Scans an upstream MCP response (or outbound LLM prompt/arguments prior to audit logging)
   * and replaces sensitive entities with AES-256-GCM backed synthetic aliases.
   */
  public pseudonymizeInbound(params: {
    readonly tenantId: string;
    readonly sessionId: string;
    readonly payload: JsonValue;
    readonly minimumOriginConfidentiality?: ConfidentialityLevel;
  }): InboundPseudonymizationReport {
    if (!this.config.enabled) {
      return {
        sanitizedPayload: params.payload,
        pseudonymizedCount: 0,
        detectedKinds: [],
        highestConfidentiality: null,
      };
    }

    const bucket = this.getOrCreateSessionBucket(params.tenantId, params.sessionId);
    let pseudonymizedCount = 0;
    const kindsSet = new Set<SensitiveEntityKind>();
    let highestConfidentiality: ConfidentialityLevel | null = null;

    const transformText = (text: string): string => {
      const spans = scanSensitiveSpans(text, this.config, this.customPatterns);
      if (spans.length === 0) {
        return text;
      }

      let cursor = 0;
      let rebuilt = '';

      for (const span of spans) {
        const effectiveConf =
          params.minimumOriginConfidentiality !== undefined
            ? joinConfidentiality(span.confidentiality, params.minimumOriginConfidentiality)
            : span.confidentiality;

        const alias = this.storeOrReuseSecret({
          bucket,
          tenantId: params.tenantId,
          sessionId: params.sessionId,
          rawValue: span.value,
          kind: span.kind,
          confidentiality: effectiveConf,
        });

        rebuilt += `${text.slice(cursor, span.start)}${alias}`;
        cursor = span.end;
        pseudonymizedCount += 1;
        kindsSet.add(span.kind);
        highestConfidentiality =
          highestConfidentiality === null
            ? effectiveConf
            : joinConfidentiality(highestConfidentiality, effectiveConf);
      }

      rebuilt += text.slice(cursor);
      return rebuilt;
    };

    const walk = (node: JsonValue, depth: number): JsonValue => {
      if (depth > 32 || node === null || typeof node === 'number' || typeof node === 'boolean') {
        return node;
      }
      if (typeof node === 'string') {
        return transformText(node);
      }
      if (Array.isArray(node)) {
        return node.map((item) => walk(item, depth + 1));
      }
      if (isJsonObject(node)) {
        const outObj: Record<string, JsonValue | undefined> = {};
        for (const [k, v] of Object.entries(node)) {
          outObj[k] = v === undefined ? undefined : walk(v, depth + 1);
        }
        return outObj as JsonObject;
      }
      return node;
    };

    const sanitizedPayload = walk(params.payload, 0);

    return {
      sanitizedPayload,
      pseudonymizedCount,
      detectedKinds: Array.from(kindsSet),
      highestConfidentiality,
    };
  }

  /**
   * Detokenizes synthetic aliases inside outbound tool call arguments ONLY if
   * `targetMaxSinkConfidentiality` satisfies Bell-LaPadula clearance for every
   * referenced secret; rejects expired, cross-session, or unauthorized aliases.
   */
  public detokenizeOutboundConditional(params: {
    readonly tenantId: string;
    readonly sessionId: string;
    readonly toolName: string;
    readonly args: JsonObject;
    readonly targetMaxSinkConfidentiality: ConfidentialityLevel;
  }): Result<OutboundDetokenizationReport, SentinelError> {
    if (!this.config.enabled) {
      return ok({
        detokenizedArgs: params.args,
        restoredCount: 0,
        restoredAliases: [],
      });
    }

    const bucket = this.sessions.get(this.bucketKey(params.tenantId, params.sessionId));
    const restoredAliases = new Set<string>();
    let restoredCount = 0;

    const detokenizeString = (text: string): Result<string, SentinelError> => {
      const candidateAliases = extractSyntheticAliasesFromText(text);
      if (candidateAliases.length === 0) {
        return ok(text);
      }

      let working = text;

      for (const rawCandidate of candidateAliases) {
        // Match case-insensitively for email aliases while looking up canonical stored alias
        const canonicalAlias = rawCandidate.endsWith('@sentinel.vault')
          ? rawCandidate.toLowerCase()
          : rawCandidate;
        const entry = bucket?.byAlias.get(canonicalAlias);

        if (entry === undefined || bucket === undefined) {
          return err(
            createSentinelError(
              'VAULT_INTEGRITY_ERROR',
              `Outbound call to "${params.toolName}" referenced unknown, expired, or cross-session vault alias "${rawCandidate}"`,
              'context-vault',
              { toolName: params.toolName, alias: rawCandidate },
            ),
          );
        }

        const originRank = CONFIDENTIALITY_RANK[entry.originConfidentiality];
        const sinkRank = CONFIDENTIALITY_RANK[params.targetMaxSinkConfidentiality];
        if (originRank > sinkRank) {
          return err(
            createSentinelError(
              'LATTICE_VIOLATION',
              `Vault blocked detokenization of ${entry.kind} alias "${entry.alias}" (${entry.originConfidentiality}) into lower-clearance tool "${params.toolName}" (max ${params.targetMaxSinkConfidentiality})`,
              'context-vault',
              {
                toolName: params.toolName,
                alias: entry.alias,
                entityKind: entry.kind,
                originConfidentiality: entry.originConfidentiality,
                maxSinkConfidentiality: params.targetMaxSinkConfidentiality,
              },
            ),
          );
        }

        const plaintextRes = this.decryptEntry(bucket, params.tenantId, params.sessionId, entry);
        if (!plaintextRes.ok) {
          return plaintextRes;
        }

        working = working.split(rawCandidate).join(plaintextRes.value);
        restoredAliases.add(entry.alias);
        restoredCount += 1;
      }

      return ok(working);
    };

    const walk = (node: JsonValue, depth: number): Result<JsonValue, SentinelError> => {
      if (depth > 32 || node === null || typeof node === 'number' || typeof node === 'boolean') {
        return ok(node);
      }
      if (typeof node === 'string') {
        return detokenizeString(node);
      }
      if (Array.isArray(node)) {
        const nextArr: JsonValue[] = [];
        for (const item of node) {
          const itemRes = walk(item, depth + 1);
          if (!itemRes.ok) return itemRes;
          nextArr.push(itemRes.value);
        }
        return ok(nextArr);
      }
      if (isJsonObject(node)) {
        const nextObj: Record<string, JsonValue | undefined> = {};
        for (const [k, v] of Object.entries(node)) {
          if (v === undefined) {
            nextObj[k] = undefined;
            continue;
          }
          const valRes = walk(v, depth + 1);
          if (!valRes.ok) return valRes;
          nextObj[k] = valRes.value;
        }
        return ok(nextObj as JsonObject);
      }
      return ok(node);
    };

    const transformed = walk(params.args, 0);
    if (!transformed.ok) {
      return transformed;
    }

    return ok({
      detokenizedArgs: transformed.value as JsonObject,
      restoredCount,
      restoredAliases: Array.from(restoredAliases),
    });
  }

  private zeroizeBucket(bucket: SessionVaultBucket): void {
    for (const entry of bucket.byAlias.values()) {
      entry.ciphertext.fill(0);
      entry.authTag.fill(0);
      entry.iv.fill(0);
    }
    bucket.byAlias.clear();
    bucket.aliasByPlaintextHmac.clear();
    bucket.sessionKey.fill(0);
  }

  public destroySession(tenantId: string, sessionId: string): void {
    const key = this.bucketKey(tenantId, sessionId);
    const bucket = this.sessions.get(key);
    if (bucket !== undefined) {
      this.zeroizeBucket(bucket);
      this.sessions.delete(key);
    }
  }
}
