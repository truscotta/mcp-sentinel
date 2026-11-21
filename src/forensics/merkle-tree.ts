import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalizeJson, constantTimeEqualHex, sha256Hex } from '../core/canonical.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import { err, ok, type Result } from '../types/result.js';

const LEAF_DOMAIN_PREFIX = Buffer.from([0x00]);
const NODE_DOMAIN_PREFIX = Buffer.from([0x01]);
const EMPTY_TREE_ROOT_HEX = sha256Hex('');

export interface MerkleAppendReceipt {
  readonly leafIndex: number;
  readonly treeSize: number;
  readonly leafHashHex: string;
  readonly rootHashHex: string;
}

export interface MerkleInclusionProof {
  readonly leafIndex: number;
  readonly treeSize: number;
  readonly leafHashHex: string;
  readonly auditPathHex: readonly string[];
  readonly rootHashHex: string;
}

export interface MerkleConsistencyProof {
  readonly firstTreeSize: number;
  readonly secondTreeSize: number;
  readonly firstRootHex: string;
  readonly secondRootHex: string;
  readonly proofHashesHex: readonly string[];
}

/**
 * Computes the largest power of two strictly less than `n` (`k < n <= 2k`),
 * matching RFC-6962 §2.1 binary Merkle tree split boundaries.
 */
export function largestPowerOfTwoLessThan(n: number): number {
  if (!Number.isInteger(n) || n <= 1) {
    throw new RangeError('largestPowerOfTwoLessThan requires an integer n >= 2');
  }
  let k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

/**
 * RFC-6962 §2.1 domain-separated leaf hash: `SHA-256(0x00 || leafBytes)`.
 */
export function hashMerkleLeafBytes(data: string | Uint8Array): Buffer {
  const payload = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return createHash('sha256').update(LEAF_DOMAIN_PREFIX).update(payload).digest();
}

export function hashMerkleLeafHex(data: string | Uint8Array): string {
  return hashMerkleLeafBytes(data).toString('hex');
}

/**
 * RFC-6962 §2.1 domain-separated interior node hash: `SHA-256(0x01 || left || right)`.
 */
export function hashMerkleNodeBytes(left: Uint8Array, right: Uint8Array): Buffer {
  return createHash('sha256').update(NODE_DOMAIN_PREFIX).update(left).update(right).digest();
}

function isHexSha256(candidate: string): boolean {
  return candidate.length === 64 && /^[0-9a-fA-F]{64}$/.test(candidate);
}

function reconstructInclusionRoot(
  m: number,
  n: number,
  leafHash: Buffer,
  auditPath: readonly Buffer[],
): Buffer | null {
  if (n === 1 && m === 0) {
    return auditPath.length === 0 ? leafHash : null;
  }
  if (auditPath.length === 0 || m < 0 || m >= n) {
    return null;
  }

  const k = largestPowerOfTwoLessThan(n);
  const sibling = auditPath[auditPath.length - 1];
  if (sibling === undefined) {
    return null;
  }
  const innerPath = auditPath.slice(0, -1);

  if (m < k) {
    const leftSubtree = reconstructInclusionRoot(m, k, leafHash, innerPath);
    if (leftSubtree === null) {
      return null;
    }
    return hashMerkleNodeBytes(leftSubtree, sibling);
  }

  const rightSubtree = reconstructInclusionRoot(m - k, n - k, leafHash, innerPath);
  if (rightSubtree === null) {
    return null;
  }
  return hashMerkleNodeBytes(sibling, rightSubtree);
}

/**
 * Offline O(log2 N) cryptographic verifier for RFC-6962 Merkle Inclusion Proofs.
 */
export function verifyInclusionProof(proof: MerkleInclusionProof): boolean {
  if (
    !Number.isInteger(proof.treeSize) ||
    proof.treeSize <= 0 ||
    !Number.isInteger(proof.leafIndex) ||
    proof.leafIndex < 0 ||
    proof.leafIndex >= proof.treeSize
  ) {
    return false;
  }

  if (!isHexSha256(proof.leafHashHex) || !isHexSha256(proof.rootHashHex)) {
    return false;
  }

  const pathBuffers: Buffer[] = [];
  for (const hex of proof.auditPathHex) {
    if (!isHexSha256(hex)) {
      return false;
    }
    pathBuffers.push(Buffer.from(hex, 'hex'));
  }

  const leafBytes = Buffer.from(proof.leafHashHex, 'hex');
  const computedRoot = reconstructInclusionRoot(
    proof.leafIndex,
    proof.treeSize,
    leafBytes,
    pathBuffers,
  );

  if (computedRoot === null) {
    return false;
  }

  return constantTimeEqualHex(computedRoot.toString('hex'), proof.rootHashHex.toLowerCase());
}

function reconstructConsistencySubroots(
  m: number,
  n: number,
  isCompleteSubtree: boolean,
  firstRoot: Buffer,
  proofNodes: readonly Buffer[],
): readonly [Buffer, Buffer] | null {
  if (m === n) {
    if (isCompleteSubtree) {
      return proofNodes.length === 0 ? [firstRoot, firstRoot] : null;
    }
    const single = proofNodes[0];
    if (proofNodes.length !== 1 || single === undefined) {
      return null;
    }
    return [single, single];
  }

  if (m <= 0 || m > n || proofNodes.length === 0) {
    return null;
  }

  const k = largestPowerOfTwoLessThan(n);
  const sibling = proofNodes[proofNodes.length - 1];
  if (sibling === undefined) {
    return null;
  }
  const innerNodes = proofNodes.slice(0, -1);

  if (m <= k) {
    const sub = reconstructConsistencySubroots(m, k, isCompleteSubtree, firstRoot, innerNodes);
    if (sub === null) {
      return null;
    }
    const [oldLeft, newLeft] = sub;
    return [oldLeft, hashMerkleNodeBytes(newLeft, sibling)];
  }

  const sub = reconstructConsistencySubroots(m - k, n - k, false, firstRoot, innerNodes);
  if (sub === null) {
    return null;
  }
  const [oldRight, newRight] = sub;
  return [hashMerkleNodeBytes(sibling, oldRight), hashMerkleNodeBytes(sibling, newRight)];
}

/**
 * Offline O(log2 N) cryptographic verifier for RFC-6962 Consistency Proofs,
 * proving that an append-only audit log was never truncated, reordered, or rewritten.
 */
export function verifyConsistencyProof(proof: MerkleConsistencyProof): boolean {
  if (
    !Number.isInteger(proof.firstTreeSize) ||
    !Number.isInteger(proof.secondTreeSize) ||
    proof.firstTreeSize < 0 ||
    proof.secondTreeSize < proof.firstTreeSize
  ) {
    return false;
  }

  if (!isHexSha256(proof.firstRootHex) || !isHexSha256(proof.secondRootHex)) {
    return false;
  }

  if (proof.firstTreeSize === 0) {
    return (
      proof.proofHashesHex.length === 0 &&
      constantTimeEqualHex(proof.firstRootHex.toLowerCase(), EMPTY_TREE_ROOT_HEX)
    );
  }

  if (proof.firstTreeSize === proof.secondTreeSize) {
    return (
      proof.proofHashesHex.length === 0 &&
      constantTimeEqualHex(proof.firstRootHex.toLowerCase(), proof.secondRootHex.toLowerCase())
    );
  }

  const nodeBuffers: Buffer[] = [];
  for (const hex of proof.proofHashesHex) {
    if (!isHexSha256(hex)) {
      return false;
    }
    nodeBuffers.push(Buffer.from(hex, 'hex'));
  }

  const firstRootBuf = Buffer.from(proof.firstRootHex, 'hex');
  const roots = reconstructConsistencySubroots(
    proof.firstTreeSize,
    proof.secondTreeSize,
    true,
    firstRootBuf,
    nodeBuffers,
  );

  if (roots === null) {
    return false;
  }

  const [reconstructedOld, reconstructedNew] = roots;
  return (
    constantTimeEqualHex(reconstructedOld.toString('hex'), proof.firstRootHex.toLowerCase()) &&
    constantTimeEqualHex(reconstructedNew.toString('hex'), proof.secondRootHex.toLowerCase())
  );
}

/**
 * Append-only RFC-6962 Binary Merkle Transparency Tree with memoized power-of-two
 * subtree hashes for fast root calculation, selective Zero-Knowledge Inclusion Proofs,
 * and append-only Consistency Proofs.
 */
export class Rfc6962MerkleTree {
  private readonly leafHashes: Buffer[] = [];
  private readonly subtreeMemo = new Map<string, Buffer>();

  public get size(): number {
    return this.leafHashes.length;
  }

  public appendRawLeaf(data: string | Uint8Array): MerkleAppendReceipt {
    const leafBuf = hashMerkleLeafBytes(data);
    const leafIndex = this.leafHashes.length;
    this.leafHashes.push(leafBuf);
    const treeSize = this.leafHashes.length;
    const rootBuf = this.computeSubtreeHash(0, treeSize);

    return {
      leafIndex,
      treeSize,
      leafHashHex: leafBuf.toString('hex'),
      rootHashHex: rootBuf.toString('hex'),
    };
  }

  public appendCanonicalJson(payload: unknown): Result<MerkleAppendReceipt, SentinelError> {
    const canonical = canonicalizeJson(payload);
    if (!canonical.ok) {
      return canonical;
    }
    return ok(this.appendRawLeaf(canonical.value));
  }

  public rootHashHex(atTreeSize?: number): Result<string, SentinelError> {
    const targetSize = atTreeSize ?? this.leafHashes.length;
    if (!Number.isInteger(targetSize) || targetSize < 0 || targetSize > this.leafHashes.length) {
      return err(
        createSentinelError(
          'INVALID_PARAMS',
          `Requested Merkle tree size ${String(targetSize)} is out of bounds [0..${this.leafHashes.length}]`,
          'merkle-tree',
        ),
      );
    }
    if (targetSize === 0) {
      return ok(EMPTY_TREE_ROOT_HEX);
    }
    return ok(this.computeSubtreeHash(0, targetSize).toString('hex'));
  }

  public getLeafHashHex(leafIndex: number): Result<string, SentinelError> {
    const leaf = this.leafHashes[leafIndex];
    if (!Number.isInteger(leafIndex) || leafIndex < 0 || leaf === undefined) {
      return err(
        createSentinelError(
          'INVALID_PARAMS',
          `Merkle leaf index ${String(leafIndex)} is out of bounds`,
          'merkle-tree',
        ),
      );
    }
    return ok(leaf.toString('hex'));
  }

  public generateInclusionProof(
    leafIndex: number,
    atTreeSize?: number,
  ): Result<MerkleInclusionProof, SentinelError> {
    const treeSize = atTreeSize ?? this.leafHashes.length;
    if (
      !Number.isInteger(treeSize) ||
      treeSize <= 0 ||
      treeSize > this.leafHashes.length ||
      !Number.isInteger(leafIndex) ||
      leafIndex < 0 ||
      leafIndex >= treeSize
    ) {
      return err(
        createSentinelError(
          'INVALID_PARAMS',
          `Invalid inclusion proof coordinates (leafIndex=${String(leafIndex)}, treeSize=${String(treeSize)})`,
          'merkle-tree',
        ),
      );
    }

    const leafBuf = this.leafHashes[leafIndex];
    if (leafBuf === undefined) {
      return err(
        createSentinelError('INTERNAL_ERROR', 'Missing Merkle leaf buffer', 'merkle-tree'),
      );
    }

    const pathBuffers = this.buildAuditPath(leafIndex, 0, treeSize);
    const rootBuf = this.computeSubtreeHash(0, treeSize);

    return ok({
      leafIndex,
      treeSize,
      leafHashHex: leafBuf.toString('hex'),
      auditPathHex: pathBuffers.map((b) => b.toString('hex')),
      rootHashHex: rootBuf.toString('hex'),
    });
  }

  public generateConsistencyProof(
    firstTreeSize: number,
    secondTreeSize?: number,
  ): Result<MerkleConsistencyProof, SentinelError> {
    const targetSecond = secondTreeSize ?? this.leafHashes.length;
    if (
      !Number.isInteger(firstTreeSize) ||
      !Number.isInteger(targetSecond) ||
      firstTreeSize < 0 ||
      targetSecond < firstTreeSize ||
      targetSecond > this.leafHashes.length
    ) {
      return err(
        createSentinelError(
          'INVALID_PARAMS',
          `Invalid consistency proof bounds (first=${String(firstTreeSize)}, second=${String(targetSecond)})`,
          'merkle-tree',
        ),
      );
    }

    const firstRootRes = this.rootHashHex(firstTreeSize);
    if (!firstRootRes.ok) return firstRootRes;
    const secondRootRes = this.rootHashHex(targetSecond);
    if (!secondRootRes.ok) return secondRootRes;

    if (firstTreeSize === 0 || firstTreeSize === targetSecond) {
      return ok({
        firstTreeSize,
        secondTreeSize: targetSecond,
        firstRootHex: firstRootRes.value,
        secondRootHex: secondRootRes.value,
        proofHashesHex: [],
      });
    }

    const subproof = this.buildConsistencySubproof(firstTreeSize, 0, targetSecond, true);

    return ok({
      firstTreeSize,
      secondTreeSize: targetSecond,
      firstRootHex: firstRootRes.value,
      secondRootHex: secondRootRes.value,
      proofHashesHex: subproof.map((b) => b.toString('hex')),
    });
  }

  private computeSubtreeHash(start: number, count: number): Buffer {
    if (count === 1) {
      const leaf = this.leafHashes[start];
      if (leaf === undefined) {
        throw new RangeError(`Missing Merkle leaf at index ${start}`);
      }
      return leaf;
    }

    const isPowerOfTwo = (count & (count - 1)) === 0;
    const memoKey = `${start}:${count}`;
    if (isPowerOfTwo) {
      const cached = this.subtreeMemo.get(memoKey);
      if (cached !== undefined) {
        return cached;
      }
    }

    const k = largestPowerOfTwoLessThan(count);
    const left = this.computeSubtreeHash(start, k);
    const right = this.computeSubtreeHash(start + k, count - k);
    const combined = hashMerkleNodeBytes(left, right);

    if (isPowerOfTwo) {
      this.subtreeMemo.set(memoKey, combined);
    }

    return combined;
  }

  private buildAuditPath(m: number, start: number, count: number): Buffer[] {
    if (count === 1) {
      return [];
    }
    const k = largestPowerOfTwoLessThan(count);
    if (m < k) {
      const inner = this.buildAuditPath(m, start, k);
      inner.push(this.computeSubtreeHash(start + k, count - k));
      return inner;
    }
    const inner = this.buildAuditPath(m - k, start + k, count - k);
    inner.push(this.computeSubtreeHash(start, k));
    return inner;
  }

  private buildConsistencySubproof(
    m: number,
    start: number,
    count: number,
    isCompleteSubtree: boolean,
  ): Buffer[] {
    if (m === count) {
      return isCompleteSubtree ? [] : [this.computeSubtreeHash(start, count)];
    }
    const k = largestPowerOfTwoLessThan(count);
    if (m <= k) {
      const inner = this.buildConsistencySubproof(m, start, k, isCompleteSubtree);
      inner.push(this.computeSubtreeHash(start + k, count - k));
      return inner;
    }
    const inner = this.buildConsistencySubproof(m - k, start + k, count - k, false);
    inner.push(this.computeSubtreeHash(start, k));
    return inner;
  }
}
