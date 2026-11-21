import type { McpToolInputSchema } from './jsonrpc.js';
import type { SecurityLabel, ToolSecurityClassification } from './lattice.js';

export type ExecutionMode = 'ENFORCE' | 'SHADOW' | 'AUDIT_ONLY';

export type PolicyDecisionAction = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL';

export interface SplRuleConfig {
  readonly id: string;
  readonly description?: string;
  readonly priority: number;
  readonly effect: PolicyDecisionAction;
  readonly expression: string;
}

export interface PayloadFirewallConfig {
  readonly maxPayloadBytes: number;
  readonly maxDepth: number;
  readonly blockSsrf: boolean;
  readonly blockPathTraversal: boolean;
  readonly blockedPatterns: readonly string[];
  readonly allowedTools?: readonly string[];
  readonly deniedTools?: readonly string[];
}

export interface RateLimitRuleConfig {
  readonly capacity: number;
  readonly refillPerSecond: number;
}

export interface RateLimiterConfig {
  readonly enabled: boolean;
  readonly tenant?: RateLimitRuleConfig;
  readonly session?: RateLimitRuleConfig;
  readonly perTool?: Readonly<Record<string, RateLimitRuleConfig>>;
  readonly defaultTool?: RateLimitRuleConfig;
}

export interface CircuitBreakerConfig {
  readonly enabled: boolean;
  readonly failureThreshold: number;
  readonly recoveryTimeoutMs: number;
  readonly halfOpenSuccessThreshold: number;
}

export interface IdempotencyConfig {
  readonly enabled: boolean;
  readonly ttlMs: number;
  readonly maxEntries: number;
  readonly coalesceInFlight: boolean;
  readonly bypassTools?: readonly string[];
}

export interface SchemaLockConfig {
  readonly enabled: boolean;
  readonly pinOnFirstSeen: boolean;
  readonly stripPoisonPatterns: boolean;
  readonly expectedToolHashes?: Readonly<Record<string, string>>;
}

export interface HoneyToolSpec {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: McpToolInputSchema;
}

export interface DeceptionConfig {
  readonly enabled: boolean;
  readonly honeyTools: readonly HoneyToolSpec[];
  readonly canaryTokens: readonly string[];
  readonly injectWatermarks: boolean;
}

export interface LatticeIfcConfig {
  readonly enabled: boolean;
  readonly initialLabel?: SecurityLabel;
  readonly toolClassifications: Readonly<Record<string, ToolSecurityClassification>>;
  readonly defaultClassification?: ToolSecurityClassification;
}

export interface IntelligenceConfig {
  readonly simhashEnabled: boolean;
  readonly simhashWindowSize: number;
  readonly simhashMaxHammingDistance: number;
  readonly maxIdenticalStreak: number;
  readonly markovEnabled: boolean;
  readonly markovMinSamples: number;
  readonly markovAnomalyThreshold: number;
  readonly cusumEnabled: boolean;
  readonly cusumDriftMicroUsd: number;
  readonly cusumThresholdMicroUsd: number;
  readonly zScoreThreshold: number;
}

export interface VaultConfig {
  readonly enabled: boolean;
  readonly ttlMs: number;
  readonly entropyThresholdBits: number;
  readonly minSecretLength: number;
  readonly detectEmail: boolean;
  readonly detectCreditCard: boolean;
  readonly detectSsn: boolean;
  readonly detectPhone: boolean;
  readonly detectApiKeys: boolean;
  readonly customPatterns?: Readonly<Record<string, string>>;
}

export interface ToolPricingSpec {
  readonly baseMicroUsd: number;
  readonly inputByteMicroUsd?: number;
  readonly outputByteMicroUsd?: number;
}

export interface BudgetLedgerConfig {
  readonly enabled: boolean;
  readonly maxGlobalMicroUsd?: number;
  readonly maxTenantMicroUsd?: number;
  readonly maxSessionMicroUsd: number;
  readonly maxPerToolMicroUsd?: Readonly<Record<string, number>>;
  readonly defaultToolPricing: ToolPricingSpec;
  readonly toolPricing?: Readonly<Record<string, ToolPricingSpec>>;
}

export interface HitlApprovalConfig {
  readonly enabled: boolean;
  readonly webhookUrl?: string;
  readonly hmacSecret?: string;
  readonly timeoutMs: number;
  readonly highCostThresholdMicroUsd?: number;
  readonly approvalRequiredTools?: readonly string[];
}

export interface ForensicsConfig {
  readonly enabled: boolean;
  readonly logFilePath?: string;
  readonly signTreeHeads: boolean;
  readonly privateKeyPem?: string;
  readonly publicKeyPem?: string;
}

export interface TelemetryConfig {
  readonly enabled: boolean;
  readonly host: string;
  readonly port: number;
}

export interface MacaroonVerificationConfig {
  readonly enabled: boolean;
  readonly rootKeyHex?: string;
  readonly metadataField: string;
}

export interface InjectionShieldConfig {
  readonly enabled: boolean;
  readonly sanitizeInboundText: boolean;
  readonly blockOnCriticalInjection: boolean;
}

export interface SentinelPolicy {
  readonly version: '1.0';
  readonly mode: ExecutionMode;
  readonly maxVmGas: number;
  readonly splRules: readonly SplRuleConfig[];
  readonly firewall: PayloadFirewallConfig;
  readonly rateLimiter: RateLimiterConfig;
  readonly circuitBreaker: CircuitBreakerConfig;
  readonly idempotency: IdempotencyConfig;
  readonly schemaLock: SchemaLockConfig;
  readonly injectionShield: InjectionShieldConfig;
  readonly deception: DeceptionConfig;
  readonly lattice: LatticeIfcConfig;
  readonly intelligence: IntelligenceConfig;
  readonly vault: VaultConfig;
  readonly ledger: BudgetLedgerConfig;
  readonly hitl: HitlApprovalConfig;
  readonly forensics: ForensicsConfig;
  readonly telemetry: TelemetryConfig;
  readonly macaroons: MacaroonVerificationConfig;
}

export const DEFAULT_SENTINEL_POLICY: SentinelPolicy = {
  version: '1.0',
  mode: 'ENFORCE',
  maxVmGas: 2_000,
  splRules: [],
  firewall: {
    maxPayloadBytes: 262_144,
    maxDepth: 24,
    blockSsrf: true,
    blockPathTraversal: true,
    blockedPatterns: ['(?i)\\bDROP\\s+TABLE\\b', '(?i)\\brm\\s+-rf\\s+/'],
  },
  rateLimiter: {
    enabled: true,
    session: { capacity: 60, refillPerSecond: 10 },
    defaultTool: { capacity: 20, refillPerSecond: 5 },
  },
  circuitBreaker: {
    enabled: true,
    failureThreshold: 5,
    recoveryTimeoutMs: 30_000,
    halfOpenSuccessThreshold: 2,
  },
  idempotency: {
    enabled: true,
    ttlMs: 60_000,
    maxEntries: 1_024,
    coalesceInFlight: true,
  },
  schemaLock: {
    enabled: true,
    pinOnFirstSeen: true,
    stripPoisonPatterns: true,
  },
  injectionShield: {
    enabled: true,
    sanitizeInboundText: true,
    blockOnCriticalInjection: false,
  },
  deception: {
    enabled: true,
    honeyTools: [
      {
        name: 'admin_export_master_credentials',
        description:
          'Internal administrative utility to export raw master vault keys and database root credentials.',
        inputSchema: {
          type: 'object',
          properties: {
            format: { type: 'string' },
          },
          additionalProperties: false,
        },
      },
    ],
    canaryTokens: ['CANARY-SENTINEL-ROOT-9F8E7D6C'],
    injectWatermarks: true,
  },
  lattice: {
    enabled: true,
    toolClassifications: {},
  },
  intelligence: {
    simhashEnabled: true,
    simhashWindowSize: 16,
    simhashMaxHammingDistance: 4,
    maxIdenticalStreak: 3,
    markovEnabled: true,
    markovMinSamples: 10,
    markovAnomalyThreshold: 0.01,
    cusumEnabled: true,
    cusumDriftMicroUsd: 50_000,
    cusumThresholdMicroUsd: 500_000,
    zScoreThreshold: 3.5,
  },
  vault: {
    enabled: true,
    ttlMs: 900_000,
    entropyThresholdBits: 4.35,
    minSecretLength: 24,
    detectEmail: true,
    detectCreditCard: true,
    detectSsn: true,
    detectPhone: true,
    detectApiKeys: true,
  },
  ledger: {
    enabled: true,
    maxGlobalMicroUsd: 50_000_000,
    maxTenantMicroUsd: 10_000_000,
    maxSessionMicroUsd: 2_000_000,
    defaultToolPricing: {
      baseMicroUsd: 1_000,
      inputByteMicroUsd: 1,
      outputByteMicroUsd: 1,
    },
  },
  hitl: {
    enabled: false,
    timeoutMs: 15_000,
  },
  forensics: {
    enabled: true,
    signTreeHeads: false,
  },
  telemetry: {
    enabled: false,
    host: '127.0.0.1',
    port: 9464,
  },
  macaroons: {
    enabled: false,
    metadataField: 'capabilityToken',
  },
};

export function createDefaultPolicy(overrides?: Partial<SentinelPolicy>): SentinelPolicy {
  if (!overrides) {
    return DEFAULT_SENTINEL_POLICY;
  }
  return {
    ...DEFAULT_SENTINEL_POLICY,
    ...overrides,
  };
}
