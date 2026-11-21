import { createSentinelError, type SentinelError } from '../types/errors.js';
import type { PolicyDecisionAction, SplRuleConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';
import { parseSplExpression, type SplAstNode } from './parser.js';

export type SplValueType = 'BOOLEAN' | 'NUMBER' | 'STRING' | 'ARRAY' | 'NULL' | 'DYNAMIC';

export interface BuiltinSignature {
  readonly minArgs: number;
  readonly maxArgs: number;
  readonly returnType: SplValueType;
}

export interface StaticDiagnostic {
  readonly severity: 'ERROR' | 'WARNING';
  readonly code:
    | 'DUPLICATE_RULE_ID'
    | 'CONTRADICTORY_RULES'
    | 'SHADOWED_RULE'
    | 'UNREACHABLE_AFTER_TAUTOLOGY';
  readonly ruleId: string;
  readonly conflictingRuleId?: string;
  readonly message: string;
}

export interface AnalyzedSplRule {
  readonly id: string;
  readonly description?: string;
  readonly priority: number;
  readonly effect: PolicyDecisionAction;
  readonly expression: string;
  readonly ast: SplAstNode;
  readonly canonicalCondition: string;
}

export interface StaticAnalysisReport {
  readonly rules: readonly AnalyzedSplRule[];
  readonly warnings: readonly StaticDiagnostic[];
}

export const SPL_ROOT_NAMESPACES: ReadonlySet<string> = new Set([
  'tool',
  'args',
  'session',
  'cost',
  'tenant',
  'method',
]);

const FORBIDDEN_PROPERTIES: ReadonlySet<string> = new Set([
  '__proto__',
  'prototype',
  'constructor',
]);

export const SPL_BUILTIN_SIGNATURES: Readonly<Record<string, BuiltinSignature>> = {
  entropy: { minArgs: 1, maxArgs: 1, returnType: 'NUMBER' },
  len: { minArgs: 1, maxArgs: 1, returnType: 'NUMBER' },
  size: { minArgs: 1, maxArgs: 1, returnType: 'NUMBER' },
  'args.size': { minArgs: 0, maxArgs: 0, returnType: 'NUMBER' },
  lower: { minArgs: 1, maxArgs: 1, returnType: 'STRING' },
  upper: { minArgs: 1, maxArgs: 1, returnType: 'STRING' },
  contains: { minArgs: 2, maxArgs: 2, returnType: 'BOOLEAN' },
  starts_with: { minArgs: 2, maxArgs: 2, returnType: 'BOOLEAN' },
  ends_with: { minArgs: 2, maxArgs: 2, returnType: 'BOOLEAN' },
  exists: { minArgs: 1, maxArgs: 1, returnType: 'BOOLEAN' },
  'taint.has': { minArgs: 1, maxArgs: 1, returnType: 'BOOLEAN' },
  has_category: { minArgs: 1, maxArgs: 1, returnType: 'BOOLEAN' },
  'cost.session_usd': { minArgs: 0, maxArgs: 0, returnType: 'NUMBER' },
  'cost.estimated_usd': { minArgs: 0, maxArgs: 0, returnType: 'NUMBER' },
};

/**
 * Compiles a regular expression after structurally rejecting nested catastrophic
 * backtracking quantifiers (ReDoS protection) and translating leading `(?i)`.
 */
export function compileSafeRegex(rawPattern: string): Result<RegExp, SentinelError> {
  if (rawPattern.length > 512) {
    return err(
      createSentinelError(
        'POLICY_VIOLATION',
        'Regular expression exceeds 512-character safety ceiling',
        'spl-analyzer',
      ),
    );
  }

  let flags = '';
  let pattern = rawPattern;
  if (pattern.startsWith('(?i)')) {
    flags = 'i';
    pattern = pattern.slice(4);
  }

  if (hasNestedQuantifierReDoS(pattern)) {
    return err(
      createSentinelError(
        'POLICY_VIOLATION',
        `Rejected potentially catastrophic ReDoS regular expression: "${rawPattern}"`,
        'spl-analyzer',
      ),
    );
  }

  try {
    return ok(new RegExp(pattern, flags));
  } catch (cause: unknown) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    return err(
      createSentinelError(
        'POLICY_VIOLATION',
        `Invalid regular expression "${rawPattern}": ${detail}`,
        'spl-analyzer',
      ),
    );
  }
}

function isQuantifierChar(ch: string | undefined): boolean {
  return ch === '+' || ch === '*' || ch === '{';
}

function hasNestedQuantifierReDoS(pattern: string): boolean {
  const groupHasInnerQuantifier: boolean[] = [];
  let inCharClass = false;

  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i];
    if (ch === undefined) {
      break;
    }

    if (ch === '\\') {
      i += 1;
      continue;
    }

    if (inCharClass) {
      if (ch === ']') {
        inCharClass = false;
      }
      continue;
    }

    if (ch === '[') {
      inCharClass = true;
      continue;
    }

    if (ch === '(') {
      groupHasInnerQuantifier.push(false);
      continue;
    }

    if (ch === ')') {
      const innerQuantified = groupHasInnerQuantifier.pop() ?? false;
      const nextChar = pattern[i + 1];
      if (innerQuantified && isQuantifierChar(nextChar)) {
        return true;
      }
      if (innerQuantified && groupHasInnerQuantifier.length > 0) {
        groupHasInnerQuantifier[groupHasInnerQuantifier.length - 1] = true;
      }
      continue;
    }

    if (isQuantifierChar(ch) && groupHasInnerQuantifier.length > 0) {
      groupHasInnerQuantifier[groupHasInnerQuantifier.length - 1] = true;
    }
  }

  return false;
}

export function inferAndValidateAst(node: SplAstNode): Result<SplValueType, SentinelError> {
  switch (node.kind) {
    case 'Literal': {
      if (node.value === null) return ok('NULL');
      if (typeof node.value === 'boolean') return ok('BOOLEAN');
      if (typeof node.value === 'number') return ok('NUMBER');
      return ok('STRING');
    }

    case 'ArrayLiteral': {
      for (const elem of node.elements) {
        const checked = inferAndValidateAst(elem);
        if (!checked.ok) {
          return checked;
        }
      }
      return ok('ARRAY');
    }

    case 'Identifier': {
      if (!SPL_ROOT_NAMESPACES.has(node.name)) {
        return err(
          createSentinelError(
            'POLICY_VIOLATION',
            `Unknown root identifier "${node.name}" at offset ${node.offset}; valid roots are: ${Array.from(SPL_ROOT_NAMESPACES).join(', ')}`,
            'spl-analyzer',
          ),
        );
      }
      return ok(node.name === 'method' || node.name === 'tenant' ? 'STRING' : 'DYNAMIC');
    }

    case 'Member': {
      if (FORBIDDEN_PROPERTIES.has(node.property)) {
        return err(
          createSentinelError(
            'POLICY_VIOLATION',
            `Forbidden prototype property access "${node.property}" at offset ${node.offset}`,
            'spl-analyzer',
          ),
        );
      }
      const parentCheck = inferAndValidateAst(node.object);
      if (!parentCheck.ok) {
        return parentCheck;
      }
      return ok('DYNAMIC');
    }

    case 'Unary': {
      const inner = inferAndValidateAst(node.operand);
      if (!inner.ok) {
        return inner;
      }
      if (node.operator === 'NEG') {
        if (inner.value !== 'NUMBER' && inner.value !== 'DYNAMIC') {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Unary "-" expects NUMBER operand but got ${inner.value} at offset ${node.offset}`,
              'spl-analyzer',
            ),
          );
        }
        return ok('NUMBER');
      }
      return ok('BOOLEAN');
    }

    case 'Binary': {
      const leftType = inferAndValidateAst(node.left);
      if (!leftType.ok) {
        return leftType;
      }
      const rightType = inferAndValidateAst(node.right);
      if (!rightType.ok) {
        return rightType;
      }

      if (node.operator === 'OR' || node.operator === 'AND') {
        return ok('BOOLEAN');
      }

      if (node.operator === 'EQ' || node.operator === 'NEQ') {
        return ok('BOOLEAN');
      }

      if (node.operator === 'MATCHES') {
        if (node.right.kind !== 'Literal' || typeof node.right.value !== 'string') {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Operator "matches" requires a static string regex literal on the right-hand side at offset ${node.offset}`,
              'spl-analyzer',
            ),
          );
        }
        if (leftType.value !== 'STRING' && leftType.value !== 'DYNAMIC') {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Operator "matches" expects STRING left operand but got ${leftType.value} at offset ${node.offset}`,
              'spl-analyzer',
            ),
          );
        }
        const regexCheck = compileSafeRegex(node.right.value);
        if (!regexCheck.ok) {
          return regexCheck;
        }
        return ok('BOOLEAN');
      }

      if (node.operator === 'IN') {
        if (
          rightType.value !== 'ARRAY' &&
          rightType.value !== 'STRING' &&
          rightType.value !== 'DYNAMIC'
        ) {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Operator "in" requires ARRAY or STRING right operand, got ${rightType.value} at offset ${node.offset}`,
              'spl-analyzer',
            ),
          );
        }
        return ok('BOOLEAN');
      }

      if (
        node.operator === 'LT' ||
        node.operator === 'LTE' ||
        node.operator === 'GT' ||
        node.operator === 'GTE'
      ) {
        const compatibleLeft =
          leftType.value === 'NUMBER' || leftType.value === 'STRING' || leftType.value === 'DYNAMIC';
        const compatibleRight =
          rightType.value === 'NUMBER' ||
          rightType.value === 'STRING' ||
          rightType.value === 'DYNAMIC';
        if (
          !compatibleLeft ||
          !compatibleRight ||
          (leftType.value !== 'DYNAMIC' &&
            rightType.value !== 'DYNAMIC' &&
            leftType.value !== rightType.value)
        ) {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Incompatible relational comparison between ${leftType.value} and ${rightType.value} at offset ${node.offset}`,
              'spl-analyzer',
            ),
          );
        }
        return ok('BOOLEAN');
      }

      // Arithmetic operators (+, -, *, /, %)
      if (
        (leftType.value !== 'NUMBER' && leftType.value !== 'DYNAMIC') ||
        (rightType.value !== 'NUMBER' && rightType.value !== 'DYNAMIC')
      ) {
        return err(
          createSentinelError(
            'POLICY_VIOLATION',
            `Arithmetic operator "${node.operator}" requires numeric operands, got ${leftType.value} and ${rightType.value} at offset ${node.offset}`,
            'spl-analyzer',
          ),
        );
      }
      return ok('NUMBER');
    }

    case 'Call': {
      const signature = SPL_BUILTIN_SIGNATURES[node.callee];
      if (signature === undefined) {
        return err(
          createSentinelError(
            'POLICY_VIOLATION',
            `Unknown SPL built-in function "${node.callee}()" at offset ${node.offset}`,
            'spl-analyzer',
          ),
        );
      }
      if (node.args.length < signature.minArgs || node.args.length > signature.maxArgs) {
        return err(
          createSentinelError(
            'POLICY_VIOLATION',
            `Function "${node.callee}()" expects ${signature.minArgs} argument(s) but received ${node.args.length} at offset ${node.offset}`,
            'spl-analyzer',
          ),
        );
      }
      for (const arg of node.args) {
        const argCheck = inferAndValidateAst(arg);
        if (!argCheck.ok) {
          return argCheck;
        }
      }
      return ok(signature.returnType);
    }
  }
}

/**
 * Produces a normalized structural signature for an AST, sorting commutative
 * `AND`, `OR`, `EQ`, and `NEQ` operands so semantically identical expressions
 * (`a and b` vs `b and a`) resolve to the exact same canonical condition string.
 */
export function canonicalizeAstCondition(node: SplAstNode): string {
  switch (node.kind) {
    case 'Literal':
      return `lit(${JSON.stringify(node.value)})`;
    case 'ArrayLiteral':
      return `arr([${node.elements.map(canonicalizeAstCondition).join(',')}])`;
    case 'Identifier':
      return `id(${node.name})`;
    case 'Member':
      return `mem(${canonicalizeAstCondition(node.object)}.${node.property})`;
    case 'Unary':
      return `un(${node.operator},${canonicalizeAstCondition(node.operand)})`;
    case 'Call':
      return `call(${node.callee},[${node.args.map(canonicalizeAstCondition).join(',')}])`;
    case 'Binary': {
      const leftSig = canonicalizeAstCondition(node.left);
      const rightSig = canonicalizeAstCondition(node.right);
      if (
        node.operator === 'AND' ||
        node.operator === 'OR' ||
        node.operator === 'EQ' ||
        node.operator === 'NEQ'
      ) {
        const ordered = leftSig <= rightSig ? [leftSig, rightSig] : [rightSig, leftSig];
        return `bin(${node.operator},${ordered[0]},${ordered[1]})`;
      }
      return `bin(${node.operator},${leftSig},${rightSig})`;
    }
  }
}

const ACTION_PRECEDENCE: Readonly<Record<PolicyDecisionAction, number>> = {
  DENY: 3,
  REQUIRE_APPROVAL: 2,
  ALLOW: 1,
};

/**
 * Validates and statically analyzes a set of SPL policy rules:
 * 1. Parses and type-checks every expression.
 * 2. Fails closed on duplicate rule IDs or equal-priority contradictory rules.
 * 3. Emits warnings for shadowed rules or rules unreachable behind unconditional `true`.
 */
export function analyzePolicyRules(
  rules: readonly SplRuleConfig[],
): Result<StaticAnalysisReport, SentinelError> {
  const seenIds = new Set<string>();
  const analyzed: AnalyzedSplRule[] = [];

  for (const rule of rules) {
    const trimmedId = rule.id.trim();
    if (trimmedId.length === 0) {
      return err(
        createSentinelError('POLICY_VIOLATION', 'SPL rule id must not be empty', 'spl-analyzer'),
      );
    }
    if (seenIds.has(trimmedId)) {
      return err(
        createSentinelError(
          'POLICY_VIOLATION',
          `Duplicate SPL rule id "${trimmedId}" detected during static analysis`,
          'spl-analyzer',
          { ruleId: trimmedId },
        ),
      );
    }
    seenIds.add(trimmedId);

    const parsed = parseSplExpression(rule.expression);
    if (!parsed.ok) {
      return err(
        createSentinelError(
          'POLICY_VIOLATION',
          `Rule "${trimmedId}" parse error: ${parsed.error.message}`,
          'spl-analyzer',
          { ruleId: trimmedId },
        ),
      );
    }

    const inferred = inferAndValidateAst(parsed.value);
    if (!inferred.ok) {
      return err(
        createSentinelError(
          'POLICY_VIOLATION',
          `Rule "${trimmedId}" type error: ${inferred.error.message}`,
          'spl-analyzer',
          { ruleId: trimmedId },
        ),
      );
    }

    if (inferred.value !== 'BOOLEAN' && inferred.value !== 'DYNAMIC') {
      return err(
        createSentinelError(
          'POLICY_VIOLATION',
          `Rule "${trimmedId}" root expression must evaluate to BOOLEAN, got ${inferred.value}`,
          'spl-analyzer',
          { ruleId: trimmedId },
        ),
      );
    }

    const entry: AnalyzedSplRule = {
      id: trimmedId,
      priority: rule.priority,
      effect: rule.effect,
      expression: rule.expression,
      ast: parsed.value,
      canonicalCondition: canonicalizeAstCondition(parsed.value),
      ...(rule.description !== undefined ? { description: rule.description } : {}),
    };
    analyzed.push(entry);
  }

  // Deterministic ordering: highest priority first; ties broken by strictest effect, then ID.
  analyzed.sort((a, b) => {
    if (b.priority !== a.priority) {
      return b.priority - a.priority;
    }
    const effectDiff = ACTION_PRECEDENCE[b.effect] - ACTION_PRECEDENCE[a.effect];
    if (effectDiff !== 0) {
      return effectDiff;
    }
    return a.id.localeCompare(b.id);
  });

  const warnings: StaticDiagnostic[] = [];
  let unconditionalCatchAllRuleId: string | undefined;

  for (let i = 0; i < analyzed.length; i += 1) {
    const currentRule = analyzed[i];
    if (currentRule === undefined) {
      continue;
    }

    if (unconditionalCatchAllRuleId !== undefined) {
      warnings.push({
        severity: 'WARNING',
        code: 'UNREACHABLE_AFTER_TAUTOLOGY',
        ruleId: currentRule.id,
        conflictingRuleId: unconditionalCatchAllRuleId,
        message: `Rule "${currentRule.id}" is unreachable after higher-priority unconditional rule "${unconditionalCatchAllRuleId}"`,
      });
    }

    if (currentRule.canonicalCondition === 'lit(true)' && unconditionalCatchAllRuleId === undefined) {
      unconditionalCatchAllRuleId = currentRule.id;
    }

    for (let j = 0; j < i; j += 1) {
      const earlierRule = analyzed[j];
      if (earlierRule === undefined) {
        continue;
      }

      if (earlierRule.canonicalCondition === currentRule.canonicalCondition) {
        if (
          earlierRule.priority === currentRule.priority &&
          earlierRule.effect !== currentRule.effect
        ) {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Contradictory SPL rules "${earlierRule.id}" (${earlierRule.effect}) and "${currentRule.id}" (${currentRule.effect}) share identical condition and priority ${currentRule.priority}`,
              'spl-analyzer',
              {
                ruleId: currentRule.id,
                conflictingRuleId: earlierRule.id,
              },
            ),
          );
        }

        warnings.push({
          severity: 'WARNING',
          code: 'SHADOWED_RULE',
          ruleId: currentRule.id,
          conflictingRuleId: earlierRule.id,
          message: `Rule "${currentRule.id}" is shadowed by higher-precedence rule "${earlierRule.id}"`,
        });
      }
    }
  }

  return ok({
    rules: analyzed,
    warnings,
  });
}
