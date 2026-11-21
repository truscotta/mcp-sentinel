import { createSentinelError, type SentinelError } from '../types/errors.js';
import { isJsonObject, type JsonObject, type JsonValue } from '../types/jsonrpc.js';
import type { InjectionShieldConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';

export type InjectionSeverity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface InjectionFinding {
  readonly ruleId: string;
  readonly severity: Exclude<InjectionSeverity, 'NONE'>;
  readonly description: string;
}

export interface InboundScanOutcome {
  readonly sanitizedPayload: JsonValue;
  readonly findings: readonly InjectionFinding[];
  readonly highestSeverity: InjectionSeverity;
  readonly wasModified: boolean;
}

interface SignatureSpec {
  readonly id: string;
  readonly severity: Exclude<InjectionSeverity, 'NONE'>;
  readonly description: string;
  readonly detectRegex: RegExp;
  readonly neutralize: (input: string) => string;
}

const SEVERITY_RANK: Readonly<Record<InjectionSeverity, number>> = {
  NONE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const INBOUND_SIGNATURES: readonly SignatureSpec[] = [
  {
    id: 'ROLE_DELIMITER_SPOOF',
    severity: 'CRITICAL',
    description: 'ChatML / Llama / Claude system role delimiter spoofing inside tool output',
    detectRegex: /<\|im_start\|>\s*system|<\|system\|>|<<SYS>>|\[INST\]|\n\s*System\s*:/i,
    neutralize: (input) =>
      input.replace(
        /<\|im_start\|>\s*system|<\|system\|>|<<SYS>>|\[INST\]|\n\s*System\s*:/gi,
        '[NEUTRALIZED_ROLE_MARKER]',
      ),
  },
  {
    id: 'INSTRUCTION_OVERRIDE_DIRECTIVE',
    severity: 'CRITICAL',
    description: 'Explicit directive attempting to override prior system or user instructions',
    detectRegex:
      /\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|guardrails|directives)\b/i,
    neutralize: (input) =>
      input.replace(
        /\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|guardrails|directives)\b/gi,
        '[NEUTRALIZED_OVERRIDE_DIRECTIVE]',
      ),
  },
  {
    id: 'MARKDOWN_EXFILTRATION_BEACON',
    severity: 'HIGH',
    description:
      'Markdown image beacon with query string designed for zero-click data exfiltration',
    detectRegex: /!\[[^\]]*\]\(https?:\/\/[^)\s]+\?[^)\s]+=/i,
    neutralize: (input) =>
      input.replace(
        /!\[([^\]]*)\]\((https?:\/\/[^)\s]+\?[^)\s]+=[^)\s]*)\)/gi,
        '[STRIPPED_EXFIL_IMAGE:$1]',
      ),
  },
  {
    id: 'SYNTHETIC_TOOL_CALL_INJECTION',
    severity: 'HIGH',
    description: 'Embedded XML/JSON tool invocation tags attempting to hijack agent tool selection',
    detectRegex: /<\s*(?:tool_call|function_calls|invoke)\b[^>]*>/i,
    neutralize: (input) =>
      input.replace(/<\s*(\/?\s*(?:tool_call|function_calls|invoke)\b[^>]*)>/gi, '[$1]'),
  },
];

function stripSmuggledUnicodeFromOutput(text: string): {
  readonly cleaned: string;
  readonly hadSmuggledChars: boolean;
} {
  let out = '';
  let hadSmuggledChars = false;

  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (
      cp !== undefined &&
      ((cp >= 0xe0000 && cp <= 0xe007f) ||
        (cp >= 0x202a && cp <= 0x202e) ||
        (cp >= 0x2066 && cp <= 0x2069))
    ) {
      hadSmuggledChars = true;
      continue;
    }
    out += ch;
  }

  return { cleaned: out, hadSmuggledChars };
}

/**
 * Inbound Indirect Prompt Injection Shield.
 * Scans untrusted MCP `tools/call` and `resources/read` outputs before they
 * enter the host LLM's context window, neutralizing or blocking jailbreaks,
 * role-delimiter spoofing, Unicode tag smuggling, and Markdown exfil beacons.
 */
export class InjectionShield {
  private readonly config: InjectionShieldConfig;

  public constructor(config: InjectionShieldConfig) {
    this.config = config;
  }

  public inspectAndSanitize(payload: JsonValue): Result<InboundScanOutcome, SentinelError> {
    if (!this.config.enabled) {
      return ok({
        sanitizedPayload: payload,
        findings: [],
        highestSeverity: 'NONE',
        wasModified: false,
      });
    }

    const findingsMap = new Map<string, InjectionFinding>();
    let wasModified = false;

    const recordFinding = (finding: InjectionFinding): void => {
      if (!findingsMap.has(finding.ruleId)) {
        findingsMap.set(finding.ruleId, finding);
      }
    };

    const transformString = (text: string): string => {
      let working = text;

      const unicodeScan = stripSmuggledUnicodeFromOutput(working);
      if (unicodeScan.hadSmuggledChars) {
        recordFinding({
          ruleId: 'UNICODE_TAG_OR_BIDI_SMUGGLING',
          severity: 'HIGH',
          description: 'Invisible astral Unicode tags or bidirectional override controls in output',
        });
        if (this.config.sanitizeInboundText) {
          working = unicodeScan.cleaned;
          wasModified = true;
        }
      }

      for (const sig of INBOUND_SIGNATURES) {
        if (sig.detectRegex.test(working)) {
          recordFinding({
            ruleId: sig.id,
            severity: sig.severity,
            description: sig.description,
          });
          if (this.config.sanitizeInboundText) {
            const next = sig.neutralize(working);
            if (next !== working) {
              working = next;
              wasModified = true;
            }
          }
        }
      }

      return working;
    };

    const walk = (node: JsonValue, depth: number): JsonValue => {
      if (depth > 32 || node === null || typeof node === 'number' || typeof node === 'boolean') {
        return node;
      }

      if (typeof node === 'string') {
        return transformString(node);
      }

      if (Array.isArray(node)) {
        return node.map((item) => walk(item, depth + 1));
      }

      if (isJsonObject(node)) {
        const nextObj: Record<string, JsonValue | undefined> = {};
        for (const [key, val] of Object.entries(node)) {
          nextObj[key] = val === undefined ? undefined : walk(val, depth + 1);
        }
        return nextObj as JsonObject;
      }

      return node;
    };

    const sanitizedPayload = walk(payload, 0);
    const findings = Array.from(findingsMap.values());

    let highestSeverity: InjectionSeverity = 'NONE';
    for (const finding of findings) {
      if (SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highestSeverity]) {
        highestSeverity = finding.severity;
      }
    }

    if (this.config.blockOnCriticalInjection && highestSeverity === 'CRITICAL') {
      return err(
        createSentinelError(
          'POLICY_VIOLATION',
          `Critical indirect prompt injection blocked in upstream response (${findings.map((f) => f.ruleId).join(', ')})`,
          'injection-shield',
          {
            highestSeverity,
            ruleIds: findings.map((f) => f.ruleId),
          },
        ),
      );
    }

    return ok({
      sanitizedPayload,
      findings,
      highestSeverity,
      wasModified,
    });
  }
}
