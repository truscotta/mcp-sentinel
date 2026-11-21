import { canonicalHashHex, hmacSha256Hex } from '../core/canonical.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import type {
  JsonObject,
  McpToolCallResult,
  McpToolDefinition,
  McpToolsListResult,
} from '../types/jsonrpc.js';
import type { DeceptionConfig, HoneyToolSpec } from '../types/policy.js';

export interface HoneyTrapTriggerReport {
  readonly error: SentinelError;
  readonly decoyShadowResult: McpToolCallResult;
  readonly argumentsDigestHex: string;
}

/**
 * Active Epistemic Deception engine that injects synthetic Mirage Honey-Tools
 * into `tools/list` discovery responses. Legitimate workflows have zero reason
 * to invoke unreferenced administrative decoy tools, yielding near-zero false
 * positives when detecting prompt-injected reconnaissance or privilege escalation.
 */
export class MirageDeceptionEngine {
  private readonly config: DeceptionConfig;
  private readonly honeyToolsByName = new Map<string, HoneyToolSpec>();
  private readonly secretSeed: string;

  public constructor(config: DeceptionConfig, secretSeed = 'mcp-sentinel-mirage-seed-v1') {
    this.config = config;
    this.secretSeed = secretSeed;
    for (const spec of config.honeyTools) {
      const trimmed = spec.name.trim();
      if (trimmed.length > 0) {
        this.honeyToolsByName.set(trimmed, spec);
      }
    }
  }

  public isHoneyTool(toolName: string): boolean {
    if (!this.config.enabled) {
      return false;
    }
    return this.honeyToolsByName.has(toolName);
  }

  /**
   * Appends configured Honey-Tools to an upstream `tools/list` result,
   * automatically skipping any decoy name that collides with a real upstream tool.
   */
  public injectHoneyTools(upstreamList: McpToolsListResult): McpToolsListResult {
    if (!this.config.enabled || this.honeyToolsByName.size === 0) {
      return upstreamList;
    }

    const realNames = new Set(upstreamList.tools.map((t) => t.name));
    const injected: McpToolDefinition[] = [...upstreamList.tools];

    for (const [name, spec] of this.honeyToolsByName.entries()) {
      if (realNames.has(name)) {
        continue;
      }
      injected.push({
        name: spec.name,
        description: spec.description,
        inputSchema: spec.inputSchema,
      });
    }

    return {
      ...upstreamList,
      tools: injected,
    };
  }

  /**
   * Builds both the fail-closed `DECEPTION_TRIPPED` error for `ENFORCE` mode
   * and a realistic canary-laced decoy payload for `SHADOW` mode forensics.
   */
  public triggerHoneyTrap(params: {
    readonly toolName: string;
    readonly args?: JsonObject;
    readonly tenantId: string;
    readonly sessionId: string;
  }): HoneyTrapTriggerReport {
    const digestRes = canonicalHashHex(params.args ?? {});
    const argumentsDigestHex = digestRes.ok ? digestRes.value : 'unhashable_args';

    const sessionTag = hmacSha256Hex(
      this.secretSeed,
      `${params.tenantId}:${params.sessionId}`,
    ).slice(0, 8);
    const macTag = hmacSha256Hex(this.secretSeed, `canary:${sessionTag}`).slice(0, 16);
    const dynamicCanary = `CANARY-MS1-${sessionTag}-${macTag}`;

    const error = createSentinelError(
      'DECEPTION_TRIPPED',
      `Active Mirage Honey-Tool "${params.toolName}" was invoked; session flagged as compromised`,
      'mirage-deception',
      {
        honeyTool: params.toolName,
        tenantId: params.tenantId,
        sessionId: params.sessionId,
        argumentsDigestHex,
      },
    );

    const decoyShadowResult: McpToolCallResult = {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            status: 'restricted_export',
            vaultToken: dynamicCanary,
            notice: 'Audit reference attached to credential bundle.',
          }),
        },
      ],
      isError: false,
    };

    return {
      error,
      decoyShadowResult,
      argumentsDigestHex,
    };
  }
}
