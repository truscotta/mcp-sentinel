import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { constantTimeEqualHex, hmacSha256Bytes, hmacSha256Hex } from '../core/canonical.js';
import type { Clock } from '../core/clock.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import { isJsonObject, type JsonObject } from '../types/jsonrpc.js';
import {
  CONFIDENTIALITY_RANK,
  type ConfidentialityLevel,
  isValidConfidentiality,
} from '../types/lattice.js';
import { err, ok, type Result } from '../types/result.js';

const MACAROON_PREFIX = 'msmac_v1.';
const KEY_DERIVATION_DOMAIN = 'mcp-sentinel-macaroon-kdf-v1';

export interface Macaroon {
  readonly version: 1;
  readonly location: string;
  readonly identifier: string;
  readonly caveats: readonly string[];
  readonly signature: string;
}

export interface MintMacaroonOptions {
  readonly location?: string;
  readonly identifier?: string;
  readonly caveats?: readonly string[];
}

export interface MacaroonVerificationContext {
  readonly method: string;
  readonly toolName?: string;
  readonly tenantId: string;
  readonly sessionId: string;
  readonly args?: JsonObject;
  readonly estimatedCallMicroUsd: number;
  readonly sessionSpentMicroUsd: number;
  readonly sessionConfidentiality: ConfidentialityLevel;
}

export interface VerifiedMacaroonSummary {
  readonly identifier: string;
  readonly location: string;
  readonly caveatCount: number;
}

function deriveRootKeyBytes(rootSecret: string | Uint8Array): Buffer {
  return hmacSha256Bytes(KEY_DERIVATION_DOMAIN, rootSecret);
}

function computeChainedSignatureHex(
  rootSecret: string | Uint8Array,
  identifier: string,
  caveats: readonly string[],
): string {
  let sigBytes = hmacSha256Bytes(deriveRootKeyBytes(rootSecret), identifier);
  for (const caveat of caveats) {
    sigBytes = hmacSha256Bytes(sigBytes, caveat);
  }
  return sigBytes.toString('hex');
}

function wildcardMatch(pattern: string, candidate: string): boolean {
  if (pattern === '*') {
    return true;
  }
  if (pattern.endsWith('*') && !pattern.slice(0, -1).includes('*')) {
    return candidate.startsWith(pattern.slice(0, -1));
  }
  if (pattern.startsWith('*') && !pattern.slice(1).includes('*')) {
    return candidate.endsWith(pattern.slice(1));
  }
  return pattern === candidate;
}

/**
 * Strongly-typed builders for standard first-party MCP attenuation caveats.
 */
export const MacaroonCaveats = {
  expiresAtMs(epochMs: number): string {
    return `expires < ${Math.floor(epochMs)}`;
  },
  bindTenant(tenantId: string): string {
    return `tenant = ${tenantId.trim()}`;
  },
  bindSession(sessionId: string): string {
    return `session = ${sessionId.trim()}`;
  },
  allowTools(patterns: readonly string[]): string {
    return `tools in ${patterns.map((p) => p.trim()).join(',')}`;
  },
  denyTools(patterns: readonly string[]): string {
    return `tools deny ${patterns.map((p) => p.trim()).join(',')}`;
  },
  allowMethods(methods: readonly string[]): string {
    return `methods in ${methods.map((m) => m.trim()).join(',')}`;
  },
  maxCallMicroUsd(limitMicroUsd: number): string {
    return `max_call_micro_usd <= ${Math.floor(limitMicroUsd)}`;
  },
  maxSessionMicroUsd(limitMicroUsd: number): string {
    return `max_session_micro_usd <= ${Math.floor(limitMicroUsd)}`;
  },
  requireArgPrefix(argKey: string, prefix: string): string {
    return `arg_prefix ${argKey.trim()} = ${prefix}`;
  },
  maxConfidentiality(level: ConfidentialityLevel): string {
    return `max_confidentiality <= ${level}`;
  },
} as const;

/**
 * Mints a root HMAC-SHA256 capability Macaroon.
 */
export function mintMacaroon(
  rootSecret: string | Uint8Array,
  options?: MintMacaroonOptions,
): Result<Macaroon, SentinelError> {
  if (
    (typeof rootSecret === 'string' && rootSecret.length < 16) ||
    (rootSecret instanceof Uint8Array && rootSecret.byteLength < 16)
  ) {
    return err(
      createSentinelError(
        'CAPABILITY_DENIED',
        'Macaroon root secret must be at least 16 bytes/characters',
        'macaroon-mint',
      ),
    );
  }

  const location = options?.location?.trim() || 'mcp-sentinel';
  const identifier = options?.identifier?.trim() || `cap_${randomBytes(12).toString('hex')}`;
  const caveats = [...(options?.caveats ?? [])];
  const signature = computeChainedSignatureHex(rootSecret, identifier, caveats);

  return ok({
    version: 1,
    location,
    identifier,
    caveats,
    signature,
  });
}

/**
 * Public, offline caveat attenuation: any holder of a Macaroon can append
 * stricter first-party caveats (e.g., narrowing directory scope or budget for
 * a sub-agent) WITHOUT possessing the root secret key.
 */
export function attenuateMacaroon(
  parent: Macaroon,
  additionalCaveats: readonly string[],
): Result<Macaroon, SentinelError> {
  if (!/^[0-9a-f]{64}$/i.test(parent.signature)) {
    return err(
      createSentinelError(
        'CAPABILITY_DENIED',
        'Cannot attenuate Macaroon with malformed hexadecimal signature',
        'macaroon-attenuate',
      ),
    );
  }

  let currentSigHex = parent.signature.toLowerCase();
  const nextCaveats = [...parent.caveats];

  for (const rawCaveat of additionalCaveats) {
    const caveat = rawCaveat.trim();
    if (caveat.length === 0) {
      return err(
        createSentinelError(
          'CAPABILITY_DENIED',
          'Macaroon caveat string must not be empty',
          'macaroon-attenuate',
        ),
      );
    }
    const keyBytes = Buffer.from(currentSigHex, 'hex');
    currentSigHex = hmacSha256Hex(keyBytes, caveat);
    nextCaveats.push(caveat);
  }

  return ok({
    version: 1,
    location: parent.location,
    identifier: parent.identifier,
    caveats: nextCaveats,
    signature: currentSigHex,
  });
}

export function serializeMacaroon(macaroon: Macaroon): string {
  const json = JSON.stringify({
    v: macaroon.version,
    l: macaroon.location,
    i: macaroon.identifier,
    c: macaroon.caveats,
    s: macaroon.signature,
  });
  return `${MACAROON_PREFIX}${Buffer.from(json, 'utf8').toString('base64url')}`;
}

export function deserializeMacaroon(token: string): Result<Macaroon, SentinelError> {
  const trimmed = token.trim();
  if (!trimmed.startsWith(MACAROON_PREFIX)) {
    return err(
      createSentinelError(
        'CAPABILITY_DENIED',
        `Malformed capability token prefix; expected "${MACAROON_PREFIX}"`,
        'macaroon-deserialize',
      ),
    );
  }

  const encoded = trimmed.slice(MACAROON_PREFIX.length);
  if (encoded.length === 0 || encoded.length > 8_192) {
    return err(
      createSentinelError(
        'CAPABILITY_DENIED',
        'Serialized Macaroon payload size is out of bounds',
        'macaroon-deserialize',
      ),
    );
  }

  let parsed: unknown;
  try {
    const decodedJson = Buffer.from(encoded, 'base64url').toString('utf8');
    parsed = JSON.parse(decodedJson);
  } catch {
    return err(
      createSentinelError(
        'CAPABILITY_DENIED',
        'Failed to decode Base64url JSON Macaroon envelope',
        'macaroon-deserialize',
      ),
    );
  }

  if (!isJsonObject(parsed)) {
    return err(
      createSentinelError(
        'CAPABILITY_DENIED',
        'Macaroon payload must be a JSON object',
        'macaroon-deserialize',
      ),
    );
  }

  if (
    parsed.v !== 1 ||
    typeof parsed.l !== 'string' ||
    typeof parsed.i !== 'string' ||
    parsed.i.length === 0 ||
    !Array.isArray(parsed.c) ||
    !parsed.c.every((item) => typeof item === 'string') ||
    typeof parsed.s !== 'string' ||
    !/^[0-9a-f]{64}$/i.test(parsed.s)
  ) {
    return err(
      createSentinelError(
        'CAPABILITY_DENIED',
        'Invalid Macaroon structure or signature format',
        'macaroon-deserialize',
      ),
    );
  }

  return ok({
    version: 1,
    location: parsed.l,
    identifier: parsed.i,
    caveats: parsed.c as readonly string[],
    signature: parsed.s.toLowerCase(),
  });
}

function evaluateSingleCaveat(
  caveat: string,
  ctx: MacaroonVerificationContext,
  clock: Clock,
): Result<void, SentinelError> {
  if (caveat.startsWith('expires < ')) {
    const limitMs = Number(caveat.slice('expires < '.length).trim());
    if (!Number.isFinite(limitMs) || clock.nowMs() >= limitMs) {
      return err(
        createSentinelError(
          'CAPABILITY_DENIED',
          `Capability token expired (caveat: "${caveat}")`,
          'macaroon-verify',
          { caveat },
        ),
      );
    }
    return ok(undefined);
  }

  if (caveat.startsWith('tenant = ')) {
    const expectedTenant = caveat.slice('tenant = '.length).trim();
    if (ctx.tenantId !== expectedTenant) {
      return err(
        createSentinelError(
          'CAPABILITY_DENIED',
          `Capability token tenant mismatch: expected "${expectedTenant}"`,
          'macaroon-verify',
          { caveat },
        ),
      );
    }
    return ok(undefined);
  }

  if (caveat.startsWith('session = ')) {
    const expectedSession = caveat.slice('session = '.length).trim();
    if (ctx.sessionId !== expectedSession) {
      return err(
        createSentinelError(
          'CAPABILITY_DENIED',
          'Capability token is bound to a different session',
          'macaroon-verify',
          { caveat },
        ),
      );
    }
    return ok(undefined);
  }

  if (caveat.startsWith('methods in ')) {
    const allowedMethods = caveat
      .slice('methods in '.length)
      .split(',')
      .map((m) => m.trim())
      .filter((m) => m.length > 0);
    if (!allowedMethods.some((pattern) => wildcardMatch(pattern, ctx.method))) {
      return err(
        createSentinelError(
          'CAPABILITY_DENIED',
          `Method "${ctx.method}" is not permitted by capability caveat "${caveat}"`,
          'macaroon-verify',
          { caveat },
        ),
      );
    }
    return ok(undefined);
  }

  if (caveat.startsWith('tools in ')) {
    if (ctx.toolName !== undefined) {
      const patterns = caveat
        .slice('tools in '.length)
        .split(',')
        .map((p) => p.trim())
        .filter((p) => p.length > 0);
      const toolName = ctx.toolName;
      if (!patterns.some((pattern) => wildcardMatch(pattern, toolName))) {
        return err(
          createSentinelError(
            'CAPABILITY_DENIED',
            `Tool "${toolName}" is not in allowed capability scope`,
            'macaroon-verify',
            { caveat, toolName },
          ),
        );
      }
    }
    return ok(undefined);
  }

  if (caveat.startsWith('tools deny ')) {
    if (ctx.toolName !== undefined) {
      const patterns = caveat
        .slice('tools deny '.length)
        .split(',')
        .map((p) => p.trim())
        .filter((p) => p.length > 0);
      const toolName = ctx.toolName;
      if (patterns.some((pattern) => wildcardMatch(pattern, toolName))) {
        return err(
          createSentinelError(
            'CAPABILITY_DENIED',
            `Tool "${toolName}" is explicitly denied by capability caveat`,
            'macaroon-verify',
            { caveat, toolName },
          ),
        );
      }
    }
    return ok(undefined);
  }

  if (caveat.startsWith('max_call_micro_usd <= ')) {
    const ceiling = Number(caveat.slice('max_call_micro_usd <= '.length).trim());
    if (!Number.isFinite(ceiling) || ctx.estimatedCallMicroUsd > ceiling) {
      return err(
        createSentinelError(
          'CAPABILITY_DENIED',
          `Estimated call cost (${ctx.estimatedCallMicroUsd} uUSD) exceeds capability limit (${ceiling} uUSD)`,
          'macaroon-verify',
          { caveat },
        ),
      );
    }
    return ok(undefined);
  }

  if (caveat.startsWith('max_session_micro_usd <= ')) {
    const ceiling = Number(caveat.slice('max_session_micro_usd <= '.length).trim());
    const projected = ctx.sessionSpentMicroUsd + ctx.estimatedCallMicroUsd;
    if (!Number.isFinite(ceiling) || projected > ceiling) {
      return err(
        createSentinelError(
          'CAPABILITY_DENIED',
          `Projected session spend (${projected} uUSD) exceeds capability budget (${ceiling} uUSD)`,
          'macaroon-verify',
          { caveat },
        ),
      );
    }
    return ok(undefined);
  }

  if (caveat.startsWith('arg_prefix ')) {
    const rest = caveat.slice('arg_prefix '.length);
    const eqIdx = rest.indexOf('=');
    if (eqIdx === -1) {
      return err(
        createSentinelError(
          'CAPABILITY_DENIED',
          `Malformed arg_prefix caveat "${caveat}"`,
          'macaroon-verify',
          { caveat },
        ),
      );
    }
    const argKey = rest.slice(0, eqIdx).trim();
    const expectedPrefix = rest.slice(eqIdx + 1).trimStart();
    if (ctx.toolName !== undefined) {
      const actualVal = ctx.args?.[argKey];
      if (typeof actualVal !== 'string' || !actualVal.startsWith(expectedPrefix)) {
        return err(
          createSentinelError(
            'CAPABILITY_DENIED',
            `Argument "${argKey}" violates required prefix constraint "${expectedPrefix}"`,
            'macaroon-verify',
            { caveat, argKey },
          ),
        );
      }
    }
    return ok(undefined);
  }

  if (caveat.startsWith('max_confidentiality <= ')) {
    const rawLevel = caveat.slice('max_confidentiality <= '.length).trim();
    if (!isValidConfidentiality(rawLevel)) {
      return err(
        createSentinelError(
          'CAPABILITY_DENIED',
          `Invalid confidentiality level in caveat "${caveat}"`,
          'macaroon-verify',
          { caveat },
        ),
      );
    }
    if (CONFIDENTIALITY_RANK[ctx.sessionConfidentiality] > CONFIDENTIALITY_RANK[rawLevel]) {
      return err(
        createSentinelError(
          'CAPABILITY_DENIED',
          `Session confidentiality (${ctx.sessionConfidentiality}) exceeds capability clearance (${rawLevel})`,
          'macaroon-verify',
          { caveat },
        ),
      );
    }
    return ok(undefined);
  }

  // Fail closed on unrecognized caveats (fundamental Macaroon security invariant)
  return err(
    createSentinelError(
      'CAPABILITY_DENIED',
      `Unrecognized capability caveat predicate: "${caveat}"`,
      'macaroon-verify',
      { caveat },
    ),
  );
}

/**
 * Verifies the cryptographic HMAC-SHA256 chain in constant time and evaluates
 * all first-party attenuation caveats against the active execution context.
 */
export function verifyMacaroon(
  rootSecret: string | Uint8Array,
  macaroonOrToken: Macaroon | string,
  ctx: MacaroonVerificationContext,
  clock: Clock,
): Result<VerifiedMacaroonSummary, SentinelError> {
  const macaroonResult =
    typeof macaroonOrToken === 'string'
      ? deserializeMacaroon(macaroonOrToken)
      : ok(macaroonOrToken);
  if (!macaroonResult.ok) {
    return macaroonResult;
  }

  const macaroon = macaroonResult.value;
  const expectedSigHex = computeChainedSignatureHex(
    rootSecret,
    macaroon.identifier,
    macaroon.caveats,
  );

  if (!constantTimeEqualHex(expectedSigHex, macaroon.signature)) {
    return err(
      createSentinelError(
        'CAPABILITY_DENIED',
        'Capability Macaroon HMAC signature verification failed',
        'macaroon-verify',
      ),
    );
  }

  for (const caveat of macaroon.caveats) {
    const check = evaluateSingleCaveat(caveat, ctx, clock);
    if (!check.ok) {
      return check;
    }
  }

  return ok({
    identifier: macaroon.identifier,
    location: macaroon.location,
    caveatCount: macaroon.caveats.length,
  });
}
