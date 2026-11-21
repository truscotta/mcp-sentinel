import { Buffer } from 'node:buffer';
import { createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { canonicalizeJson, sha256Hex } from '../core/canonical.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import { err, ok, type Result } from '../types/result.js';

const STH_SIGNING_DOMAIN = 'mcp-sentinel-sth-v1\n';

export interface Ed25519KeyPairPem {
  readonly keyId: string;
  readonly publicKeyPem: string;
  readonly privateKeyPem: string;
}

export interface SignedTreeHead {
  readonly version: 'STH-v1';
  readonly treeSize: number;
  readonly timestampMs: number;
  readonly rootHashHex: string;
  readonly keyId: string;
  readonly signatureBase64: string;
}

export function deriveEd25519KeyId(publicKeyPem: string): string {
  const normalized = publicKeyPem.replace(/\r\n/g, '\n').trim();
  return `ed25519_${sha256Hex(normalized).slice(0, 16)}`;
}

/**
 * Generates an RFC-8032 Ed25519 asymmetric keypair in standard SPKI / PKCS#8 PEM format
 * for signing Merkle Audit Tree Heads.
 */
export function generateEd25519KeyPair(): Ed25519KeyPairPem {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  return {
    keyId: deriveEd25519KeyId(publicKey),
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
  };
}

function buildSthSigningBuffer(
  treeSize: number,
  timestampMs: number,
  rootHashHex: string,
): Result<Buffer, SentinelError> {
  if (!Number.isInteger(treeSize) || treeSize < 0) {
    return err(
      createSentinelError('INVALID_PARAMS', 'STH treeSize must be a non-negative integer', 'sth'),
    );
  }
  if (!Number.isFinite(timestampMs) || timestampMs < 0) {
    return err(
      createSentinelError('INVALID_PARAMS', 'STH timestampMs must be non-negative', 'sth'),
    );
  }
  if (!/^[0-9a-fA-F]{64}$/.test(rootHashHex)) {
    return err(
      createSentinelError('INVALID_PARAMS', 'STH rootHashHex must be a 64-char SHA-256 hex', 'sth'),
    );
  }

  const canonicalRes = canonicalizeJson({
    rootHashHex: rootHashHex.toLowerCase(),
    timestampMs: Math.floor(timestampMs),
    treeSize,
    version: 'STH-v1',
  });
  if (!canonicalRes.ok) {
    return canonicalRes;
  }

  return ok(Buffer.from(`${STH_SIGNING_DOMAIN}${canonicalRes.value}`, 'utf8'));
}

/**
 * Produces an Ed25519 detached cryptographic signature over a Merkle Tree Head.
 */
export function signMerkleTreeHead(params: {
  readonly treeSize: number;
  readonly timestampMs: number;
  readonly rootHashHex: string;
  readonly privateKeyPem: string;
  readonly publicKeyPem?: string;
}): Result<SignedTreeHead, SentinelError> {
  const payloadRes = buildSthSigningBuffer(
    params.treeSize,
    params.timestampMs,
    params.rootHashHex,
  );
  if (!payloadRes.ok) {
    return payloadRes;
  }

  try {
    const derivedPublicPem =
      params.publicKeyPem ??
      createPublicKey(params.privateKeyPem).export({ type: 'spki', format: 'pem' }).toString();
    const keyId = deriveEd25519KeyId(derivedPublicPem);
    const sigBytes = sign(null, payloadRes.value, params.privateKeyPem);

    return ok({
      version: 'STH-v1',
      treeSize: params.treeSize,
      timestampMs: Math.floor(params.timestampMs),
      rootHashHex: params.rootHashHex.toLowerCase(),
      keyId,
      signatureBase64: sigBytes.toString('base64'),
    });
  } catch (cause: unknown) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    return err(
      createSentinelError(
        'INTERNAL_ERROR',
        `Failed to sign Merkle Tree Head with Ed25519 key: ${detail}`,
        'ed25519-notary',
      ),
    );
  }
}

/**
 * Verifies an Ed25519 `SignedTreeHead` against a trusted SPKI public key PEM.
 */
export function verifySignedTreeHead(
  sth: SignedTreeHead,
  publicKeyPem: string,
): Result<boolean, SentinelError> {
  if (sth.version !== 'STH-v1') {
    return ok(false);
  }

  const expectedKeyId = deriveEd25519KeyId(publicKeyPem);
  if (sth.keyId !== expectedKeyId) {
    return ok(false);
  }

  const payloadRes = buildSthSigningBuffer(sth.treeSize, sth.timestampMs, sth.rootHashHex);
  if (!payloadRes.ok) {
    return payloadRes;
  }

  try {
    const signatureBytes = Buffer.from(sth.signatureBase64, 'base64');
    if (signatureBytes.byteLength !== 64) {
      return ok(false);
    }
    const isValid = verify(null, payloadRes.value, publicKeyPem, signatureBytes);
    return ok(isValid);
  } catch (cause: unknown) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    return err(
      createSentinelError(
        'INVALID_PARAMS',
        `Ed25519 public key verification error: ${detail}`,
        'ed25519-notary',
      ),
    );
  }
}
