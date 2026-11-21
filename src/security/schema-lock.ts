import { canonicalHashHex } from '../core/canonical.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import type { McpToolDefinition, McpToolsListResult } from '../types/jsonrpc.js';
import type { SchemaLockConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';

export interface SchemaVerificationOutcome {
  readonly sanitizedResult: McpToolsListResult;
  readonly strippedPoisonTools: readonly string[];
  readonly pinnedCount: number;
}

const POISON_TAG_PATTERNS: readonly RegExp[] = [
  /<\s*important\b[^>]*>[\s\S]*?<\s*\/\s*important\s*>/gi,
  /<\s*system\b[^>]*>[\s\S]*?<\s*\/\s*system\s*>/gi,
  /\[\s*system(?:_instruction|_prompt)?\s*\][\s\S]*?\[\s*\/\s*system(?:_instruction|_prompt)?\s*\]/gi,
  /<!--[\s\S]*?-->/g,
];

function isInvisibleOrSmuggledCodePoint(cp: number): boolean {
  // Zero-width space, ZWNJ, ZWJ, LRM, RLM
  if (cp >= 0x200b && cp <= 0x200f) return true;
  // Bidi embedding / override controls (Trojan Source & prompt spoofing)
  if (cp >= 0x202a && cp <= 0x202e) return true;
  // Word joiner & invisible operators
  if (cp >= 0x2060 && cp <= 0x2064) return true;
  // Bidi isolate controls
  if (cp >= 0x2066 && cp <= 0x2069) return true;
  // Zero-width no-break space / BOM
  if (cp === 0xfeff) return true;
  // Astral-plane Unicode Tag block (U+E0000..U+E007F) used for invisible LLM prompt smuggling
  if (cp >= 0xe0000 && cp <= 0xe007f) return true;
  return false;
}

/**
 * Strips astral-plane Unicode Tag smuggling, bidirectional overrides, zero-width
 * characters, and hidden `<IMPORTANT>` / `<system>` / HTML comment poisoning blocks
 * from MCP tool descriptions.
 */
export function sanitizeToolDescription(rawDescription: string): {
  readonly cleaned: string;
  readonly wasModified: boolean;
} {
  let codePointFiltered = '';
  let strippedInvisible = false;

  for (const ch of rawDescription) {
    const cp = ch.codePointAt(0);
    if (cp !== undefined && isInvisibleOrSmuggledCodePoint(cp)) {
      strippedInvisible = true;
      continue;
    }
    codePointFiltered += ch;
  }

  let patternFiltered = codePointFiltered;
  for (const regex of POISON_TAG_PATTERNS) {
    regex.lastIndex = 0;
    patternFiltered = patternFiltered.replace(regex, ' ');
  }

  const normalized =
    patternFiltered !== codePointFiltered
      ? patternFiltered.replace(/\s{2,}/g, ' ').trim()
      : patternFiltered;

  return {
    cleaned: normalized,
    wasModified: strippedInvisible || normalized !== rawDescription,
  };
}

/**
 * Computes a deterministic SHA-256 lock digest over an `McpToolDefinition`.
 */
export function computeToolSchemaHash(tool: McpToolDefinition): Result<string, SentinelError> {
  return canonicalHashHex({
    name: tool.name,
    description: tool.description ?? '',
    inputSchema: tool.inputSchema,
  });
}

/**
 * Protects MCP clients against Tool Poisoning and mid-session Rug-Pull attacks
 * by enforcing SHA-256 schema pinning on `tools/list` responses.
 */
export class SchemaLockGuard {
  private readonly config: SchemaLockConfig;
  private readonly pinnedHashes = new Map<string, string>();

  public constructor(config: SchemaLockConfig) {
    this.config = config;
    if (config.expectedToolHashes !== undefined) {
      for (const [toolName, hash] of Object.entries(config.expectedToolHashes)) {
        this.pinnedHashes.set(toolName, hash.toLowerCase());
      }
    }
  }

  public verifyAndSanitizeToolsList(
    listResult: McpToolsListResult,
  ): Result<SchemaVerificationOutcome, SentinelError> {
    if (!this.config.enabled) {
      return ok({
        sanitizedResult: listResult,
        strippedPoisonTools: [],
        pinnedCount: this.pinnedHashes.size,
      });
    }

    const sanitizedTools: McpToolDefinition[] = [];
    const strippedPoisonTools: string[] = [];

    for (const rawTool of listResult.tools) {
      let processedTool = rawTool;

      if (this.config.stripPoisonPatterns && rawTool.description !== undefined) {
        const sanitized = sanitizeToolDescription(rawTool.description);
        if (sanitized.wasModified) {
          strippedPoisonTools.push(rawTool.name);
          processedTool = {
            ...rawTool,
            description: sanitized.cleaned,
          };
        }
      }

      const hashResult = computeToolSchemaHash(processedTool);
      if (!hashResult.ok) {
        return hashResult;
      }

      const currentHash = hashResult.value;
      const existingPin = this.pinnedHashes.get(processedTool.name);

      if (existingPin !== undefined) {
        if (existingPin !== currentHash) {
          return err(
            createSentinelError(
              'SCHEMA_INTEGRITY_VIOLATION',
              `MCP Rug-Pull detected: schema or description for tool "${processedTool.name}" mutated unexpectedly`,
              'schema-lock',
              {
                toolName: processedTool.name,
                expectedHash: existingPin,
                actualHash: currentHash,
              },
            ),
          );
        }
      } else if (this.config.pinOnFirstSeen) {
        this.pinnedHashes.set(processedTool.name, currentHash);
      }

      sanitizedTools.push(processedTool);
    }

    return ok({
      sanitizedResult: {
        ...listResult,
        tools: sanitizedTools,
      },
      strippedPoisonTools,
      pinnedCount: this.pinnedHashes.size,
    });
  }

  public exportLockfile(): Record<string, string> {
    const out: Record<string, string> = {};
    const sortedNames = Array.from(this.pinnedHashes.keys()).sort();
    for (const name of sortedNames) {
      const hash = this.pinnedHashes.get(name);
      if (hash !== undefined) {
        out[name] = hash;
      }
    }
    return out;
  }
}
