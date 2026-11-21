import { Buffer } from 'node:buffer';
import { matchToolGlob } from '../ifc/security-lattice.js';
import type { JsonObject, JsonValue } from '../types/jsonrpc.js';
import type { BudgetLedgerConfig, ToolPricingSpec } from '../types/policy.js';

export const MICRO_USD_PER_DOLLAR = 1_000_000;

export interface PreCallCostEstimate {
  readonly estimatedMicroUsd: number;
  readonly inputBytes: number;
  readonly pricingApplied: ToolPricingSpec;
}

export interface ActualCallCostBreakdown {
  readonly actualMicroUsd: number;
  readonly inputBytes: number;
  readonly outputBytes: number;
  readonly pricingApplied: ToolPricingSpec;
}

function clampSafeNonNegativeInteger(value: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    return 0;
  }
  const ceiled = Math.ceil(value);
  return Math.min(ceiled, Number.MAX_SAFE_INTEGER);
}

/**
 * Formats integer Micro-USD as a fixed 6-decimal USD string (`"1.250000"`)
 * using exact integer division with zero IEEE-754 floating-point drift.
 */
export function formatMicroUsdAsUsd(microUsd: number): string {
  const safe = Math.trunc(microUsd);
  const sign = safe < 0 ? '-' : '';
  const abs = BigInt(Math.abs(safe));
  const whole = abs / 1_000_000n;
  const frac = (abs % 1_000_000n).toString().padStart(6, '0');
  return `${sign}${whole.toString()}.${frac}`;
}

export function resolveToolPricing(
  toolName: string,
  config: BudgetLedgerConfig,
): ToolPricingSpec {
  if (config.toolPricing !== undefined) {
    const exact = config.toolPricing[toolName];
    if (exact !== undefined) {
      return exact;
    }
    for (const [pattern, spec] of Object.entries(config.toolPricing)) {
      if ((pattern.includes('*') || pattern.includes('?')) && matchToolGlob(pattern, toolName)) {
        return spec;
      }
    }
  }
  return config.defaultToolPricing;
}

/**
 * Computes conservative integer Micro-USD reservation cost prior to upstream execution.
 * Includes a minimum 256-byte projected output buffer when `outputByteMicroUsd > 0`
 * so concurrent calls cannot slip past budget ceilings before responses arrive.
 */
export function estimatePreCallMicroUsd(
  toolName: string,
  args: JsonObject,
  config: BudgetLedgerConfig,
): PreCallCostEstimate {
  const pricing = resolveToolPricing(toolName, config);
  const inputBytes = Buffer.byteLength(JSON.stringify(args), 'utf8');

  const base = clampSafeNonNegativeInteger(pricing.baseMicroUsd);
  const inRate = pricing.inputByteMicroUsd ?? 0;
  const outRate = pricing.outputByteMicroUsd ?? 0;

  const inputComponent = clampSafeNonNegativeInteger(inputBytes * inRate);
  const projectedOutputBuffer = outRate > 0 ? clampSafeNonNegativeInteger(256 * outRate) : 0;

  const estimatedMicroUsd = clampSafeNonNegativeInteger(
    base + inputComponent + projectedOutputBuffer,
  );

  return {
    estimatedMicroUsd,
    inputBytes,
    pricingApplied: pricing,
  };
}

/**
 * Computes exact integer Micro-USD settlement cost from actual input and output byte sizes.
 */
export function calculateActualCallMicroUsd(
  toolName: string,
  args: JsonObject,
  responsePayload: JsonValue,
  config: BudgetLedgerConfig,
): ActualCallCostBreakdown {
  const pricing = resolveToolPricing(toolName, config);
  const inputBytes = Buffer.byteLength(JSON.stringify(args), 'utf8');
  const outputBytes = Buffer.byteLength(JSON.stringify(responsePayload), 'utf8');

  const base = clampSafeNonNegativeInteger(pricing.baseMicroUsd);
  const inputComponent = clampSafeNonNegativeInteger(
    inputBytes * (pricing.inputByteMicroUsd ?? 0),
  );
  const outputComponent = clampSafeNonNegativeInteger(
    outputBytes * (pricing.outputByteMicroUsd ?? 0),
  );

  const actualMicroUsd = clampSafeNonNegativeInteger(base + inputComponent + outputComponent);

  return {
    actualMicroUsd,
    inputBytes,
    outputBytes,
    pricingApplied: pricing,
  };
}
