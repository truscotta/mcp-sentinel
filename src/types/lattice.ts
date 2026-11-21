/**
 * Dual Security Lattice primitives combining Bell-LaPadula Confidentiality
 * ("no read up / no write down") with Biba Integrity ("no read down / no write up").
 */
export type ConfidentialityLevel = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'SECRET';

export type IntegrityLevel = 'UNTRUSTED' | 'SANITIZED' | 'VERIFIED' | 'SYSTEM';

export type ToolCategory =
  | 'UNTRUSTED_SOURCE'
  | 'SENSITIVE_SOURCE'
  | 'EXTERNAL_SINK'
  | 'DESTRUCTIVE_SINK'
  | 'INTERNAL_COMPUTE';

export interface SecurityLabel {
  readonly confidentiality: ConfidentialityLevel;
  readonly integrity: IntegrityLevel;
}

export interface ToolSecurityClassification {
  /** Confidentiality introduced into session state after reading from this tool. */
  readonly readConfidentiality?: ConfidentialityLevel;
  /** Integrity floor applied to session state after consuming output from this tool. */
  readonly readIntegrity?: IntegrityLevel;
  /** Maximum session confidentiality permitted to flow into this tool's arguments. */
  readonly maxSinkConfidentiality?: ConfidentialityLevel;
  /** Minimum session integrity required before invoking this tool. */
  readonly minRequiredIntegrity?: IntegrityLevel;
  /** Semantic categories used for provenance diagnostics and policy predicates. */
  readonly categories?: readonly ToolCategory[];
}

export interface ProvenanceHop {
  readonly hopId: string;
  readonly parentHopIds: readonly string[];
  readonly toolName: string;
  readonly timestampMs: number;
  readonly labelApplied: SecurityLabel;
  readonly digestHex: string;
}

export const CONFIDENTIALITY_RANK: Readonly<Record<ConfidentialityLevel, 0 | 1 | 2 | 3>> = {
  PUBLIC: 0,
  INTERNAL: 1,
  CONFIDENTIAL: 2,
  SECRET: 3,
};

export const INTEGRITY_RANK: Readonly<Record<IntegrityLevel, 0 | 1 | 2 | 3>> = {
  UNTRUSTED: 0,
  SANITIZED: 1,
  VERIFIED: 2,
  SYSTEM: 3,
};

export const RANK_TO_CONFIDENTIALITY: readonly [
  ConfidentialityLevel,
  ConfidentialityLevel,
  ConfidentialityLevel,
  ConfidentialityLevel,
] = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET'];

export const RANK_TO_INTEGRITY: readonly [
  IntegrityLevel,
  IntegrityLevel,
  IntegrityLevel,
  IntegrityLevel,
] = ['UNTRUSTED', 'SANITIZED', 'VERIFIED', 'SYSTEM'];

export const DEFAULT_SESSION_LABEL: SecurityLabel = {
  confidentiality: 'PUBLIC',
  integrity: 'VERIFIED',
};

export const DEFAULT_TOOL_CLASSIFICATION: Required<ToolSecurityClassification> = {
  readConfidentiality: 'INTERNAL',
  readIntegrity: 'VERIFIED',
  maxSinkConfidentiality: 'CONFIDENTIAL',
  minRequiredIntegrity: 'UNTRUSTED',
  categories: ['INTERNAL_COMPUTE'],
};

export function isValidConfidentiality(value: string): value is ConfidentialityLevel {
  return (
    value === 'PUBLIC' ||
    value === 'INTERNAL' ||
    value === 'CONFIDENTIAL' ||
    value === 'SECRET'
  );
}

export function isValidIntegrity(value: string): value is IntegrityLevel {
  return (
    value === 'UNTRUSTED' ||
    value === 'SANITIZED' ||
    value === 'VERIFIED' ||
    value === 'SYSTEM'
  );
}
