export {
  attenuateMacaroon,
  deserializeMacaroon,
  type Macaroon,
  MacaroonCaveats,
  type MacaroonVerificationContext,
  type MintMacaroonOptions,
  mintMacaroon,
  serializeMacaroon,
  type VerifiedMacaroonSummary,
  verifyMacaroon,
} from './capabilities/macaroon.js';
export { CLI_HELP_TEXT, type ParsedCliCommand, parseCliArgs } from './cli/arg-parser.js';
export {
  canonicalHashHex,
  canonicalizeJson,
  constantTimeEqualHex,
  fnv1a64,
  hmacSha256Bytes,
  hmacSha256Hex,
  sha256Bytes,
  sha256Hex,
} from './core/canonical.js';
export { type Clock, SystemClock, VirtualClock } from './core/clock.js';
export {
  type CreateExecutionContextInput,
  createChildTraceContext,
  createExecutionContext,
  type ExecutionContext,
  formatTraceparent,
  parseTraceparent,
  type W3CTraceContext,
} from './core/context.js';
export {
  mergeSentinelPolicy,
  SentinelKernel,
  type SentinelKernelOptions,
  type UpstreamMcpHandler,
} from './core/engine.js';
export { type HoneyTrapTriggerReport, MirageDeceptionEngine } from './deception/mirage-tools.js';
export { type CanaryDetectionMatch, EpistemicWatermarkEngine } from './deception/watermark.js';
export {
  type AnalyzedSplRule,
  analyzePolicyRules,
  canonicalizeAstCondition,
  compileSafeRegex,
  inferAndValidateAst,
  type StaticAnalysisReport,
  type StaticDiagnostic,
} from './dsl/analyzer.js';
export { type SplToken, type SplTokenKind, tokenizeSpl } from './dsl/lexer.js';
export { parseSplExpression, parseSplTokens, type SplAstNode } from './dsl/parser.js';
export {
  type CompiledSplProgram,
  compileAstToBytecode,
  executeBytecodeProgram,
  type SplEvaluationInput,
  type SplInstruction,
  type SplOpCode,
  SplPolicyEngine,
  type SplPolicyVerdict,
} from './dsl/vm.js';
export {
  CounterfactualPolicyReplayer,
  type DifferentialReplayReport,
  type ReplayDivergenceItem,
} from './forensics/counterfactual-replayer.js';
export {
  deriveEd25519KeyId,
  type Ed25519KeyPairPem,
  generateEd25519KeyPair,
  type SignedTreeHead,
  signMerkleTreeHead,
  verifySignedTreeHead,
} from './forensics/ed25519-notary.js';
export {
  type AuditCorePayload,
  type AuditDecisionOutcome,
  type AuditLogVerificationReport,
  type ForensicAuditRecord,
  ForensicFlightRecorder,
  parseAuditJsonl,
  verifyJsonlAuditLog,
} from './forensics/flight-recorder.js';
export {
  hashMerkleLeafBytes,
  hashMerkleLeafHex,
  hashMerkleNodeBytes,
  largestPowerOfTwoLessThan,
  type MerkleAppendReceipt,
  type MerkleConsistencyProof,
  type MerkleInclusionProof,
  Rfc6962MerkleTree,
  verifyConsistencyProof,
  verifyInclusionProof,
} from './forensics/merkle-tree.js';
export {
  CircuitBreakerRegistry,
  type CircuitSnapshot,
  type CircuitState,
} from './guards/circuit-breaker.js';
export {
  type CoalescedExecutionOutcome,
  type CoalescedExecutionSource,
  IdempotencyCoalescer,
  type IdempotencyKeyInput,
} from './guards/idempotency-coalescer.js';
export {
  type FirewallInspectionReport,
  PayloadFirewall,
} from './guards/payload-firewall.js';
export {
  HierarchicalRateLimiter,
  type RateLimitDecision,
  type RateLimitTier,
} from './guards/rate-limiter.js';
export {
  HitlApprovalGate,
  type HitlApprovalResult,
  type HitlWebhookRequestEnvelope,
  type HitlWebhookTransport,
  type HitlWebhookWireResponse,
} from './hitl/approval-gate.js';
export { ProvenanceDag, type RecordProvenanceHopInput } from './ifc/provenance-dag.js';
export {
  combineSessionWithObservation,
  joinConfidentiality,
  joinIntegrity,
  matchToolGlob,
  meetConfidentiality,
  meetIntegrity,
  type ResolvedToolClassification,
  SecurityLatticeEngine,
  type SessionFlowVerdict,
  verifyLatticeFlow,
} from './ifc/security-lattice.js';
export {
  CusumAnomalyDetector,
  type SpendAnomalySnapshot,
} from './intelligence/cusum-detector.js';
export {
  type ForbiddenTransitionRule,
  MARKOV_START_STATE,
  MarkovCallGraph,
  type MarkovTransitionVerdict,
  type SeedTransitionEntry,
} from './intelligence/markov-graph.js';
export {
  computeInvocationSimHash64,
  formatSimHashHex,
  hammingDistance64,
  type LoopDetectionTier,
  type SimHashCallVerdict,
  SimHashLoopDetector,
} from './intelligence/simhash.js';
export {
  type ActualCallCostBreakdown,
  calculateActualCallMicroUsd,
  estimatePreCallMicroUsd,
  formatMicroUsdAsUsd,
  MICRO_USD_PER_DOLLAR,
  type PreCallCostEstimate,
  resolveToolPricing,
} from './ledger/cost-model.js';
export {
  type BudgetReservation,
  type BudgetTierName,
  type CommitReceipt,
  type LedgerExposureSnapshot,
  MicroUsdLedger,
  type RollbackReceipt,
} from './ledger/micro-ledger.js';
export {
  type InboundScanOutcome,
  type InjectionFinding,
  type InjectionSeverity,
  InjectionShield,
} from './security/injection-shield.js';
export {
  KillSwitch,
  type LockdownRecord,
  type LockdownScope,
  type TriggerLockdownInput,
} from './security/kill-switch.js';
export {
  computeToolSchemaHash,
  SchemaLockGuard,
  type SchemaVerificationOutcome,
  sanitizeToolDescription,
} from './security/schema-lock.js';
export { ObservabilityServer } from './telemetry/observability-server.js';
export {
  createSentinelMiddleware,
  type LocalToolHandler,
  SentinelProtectedRegistry,
} from './transports/sdk-middleware.js';
export {
  StdioReverseProxy,
  type StdioReverseProxyOptions,
  type StdioUpstreamSpawnSpec,
  type StdioUpstreamStreamsSpec,
} from './transports/stdio-proxy.js';
export {
  createSentinelError,
  SENTINEL_ERROR_CODES,
  type SentinelError,
  type SentinelErrorCode,
  type SentinelErrorName,
  toJsonRpcErrorObject,
} from './types/errors.js';
export type {
  JsonArray,
  JsonObject,
  JsonPrimitive,
  JsonRpcErrorObject,
  JsonRpcErrorResponse,
  JsonRpcId,
  JsonRpcMessage,
  JsonRpcNotification,
  JsonRpcRequest,
  JsonRpcResponse,
  JsonRpcSuccessResponse,
  JsonValue,
  McpContentBlock,
  McpResourceContent,
  McpTextContent,
  McpToolCallParams,
  McpToolCallResult,
  McpToolDefinition,
  McpToolInputSchema,
  McpToolsListResult,
} from './types/jsonrpc.js';
export {
  createJsonRpcErrorResponse,
  createJsonRpcSuccessResponse,
  isJsonObject,
  isJsonRpcId,
  isJsonRpcRequest,
  isJsonRpcResponse,
  isJsonValue,
  isToolsCallParams,
} from './types/jsonrpc.js';
export {
  CONFIDENTIALITY_RANK,
  type ConfidentialityLevel,
  DEFAULT_SESSION_LABEL,
  DEFAULT_TOOL_CLASSIFICATION,
  INTEGRITY_RANK,
  type IntegrityLevel,
  isValidConfidentiality,
  isValidIntegrity,
  type ProvenanceHop,
  type SecurityLabel,
  type ToolCategory,
  type ToolSecurityClassification,
} from './types/lattice.js';
export {
  type BudgetLedgerConfig,
  type CircuitBreakerConfig,
  createDefaultPolicy,
  DEFAULT_SENTINEL_POLICY,
  type DeceptionConfig,
  type ExecutionMode,
  type ForensicsConfig,
  type HitlApprovalConfig,
  type HoneyToolSpec,
  type IdempotencyConfig,
  type InjectionShieldConfig,
  type IntelligenceConfig,
  type LatticeIfcConfig,
  type MacaroonVerificationConfig,
  type PayloadFirewallConfig,
  type PolicyDecisionAction,
  type RateLimiterConfig,
  type RateLimitRuleConfig,
  type SchemaLockConfig,
  type SentinelPolicy,
  type SplRuleConfig,
  type TelemetryConfig,
  type ToolPricingSpec,
  type VaultConfig,
} from './types/policy.js';
export {
  andThen,
  collectResults,
   type Err,
  err,
  isErr,
  isOk,
  mapErr,
  mapResult,
  type Ok,
  ok,
  type Result,
  tryAsync,
  trySync,
  unwrapOr,
} from './types/result.js';
export {
  type InboundPseudonymizationReport,
  type OutboundDetokenizationReport,
  ReversibleContextVault,
} from './vault/context-vault.js';
export {
  computeLuhnCheckDigit,
  isLikelyUnstructuredSecret,
  isSyntheticVaultToken,
  passesLuhnCheck,
  type SensitiveEntityKind,
  type SensitiveSpanMatch,
  scanSensitiveSpans,
  shannonEntropyBits,
} from './vault/luhn-and-entropy.js';
export {
  extractSyntheticAliasesFromText,
  generateFormatPreservingAlias,
} from './vault/synthetic-alias.js';
