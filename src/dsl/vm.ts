import { Buffer } from 'node:buffer';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import { isJsonObject, type JsonObject, type JsonValue } from '../types/jsonrpc.js';
import type { ConfidentialityLevel, IntegrityLevel, ToolCategory } from '../types/lattice.js';
import type { PolicyDecisionAction, SplRuleConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';
import {
  type AnalyzedSplRule,
  analyzePolicyRules,
  compileSafeRegex,
  type StaticDiagnostic,
} from './analyzer.js';
import type { SplAstNode } from './parser.js';

export type SplOpCode =
  | 'PUSH_CONST'
  | 'LOAD_ROOT'
  | 'GET_PROP'
  | 'MAKE_ARRAY'
  | 'UNARY_NOT'
  | 'UNARY_NEG'
  | 'BINARY_EQ'
  | 'BINARY_NEQ'
  | 'BINARY_LT'
  | 'BINARY_LTE'
  | 'BINARY_GT'
  | 'BINARY_GTE'
  | 'BINARY_ADD'
  | 'BINARY_SUB'
  | 'BINARY_MUL'
  | 'BINARY_DIV'
  | 'BINARY_MOD'
  | 'BINARY_IN'
  | 'BINARY_MATCHES'
  | 'JUMP_IF_FALSE_SHORT'
  | 'JUMP_IF_TRUE_SHORT'
  | 'CALL_BUILTIN'
  | 'TO_BOOL'
  | 'HALT';

export interface SplInstruction {
  readonly op: SplOpCode;
  readonly arg?: number;
  readonly arg2?: number;
}

export interface CompiledSplProgram {
  readonly instructions: readonly SplInstruction[];
  readonly constants: readonly JsonValue[];
  readonly regexPool: readonly RegExp[];
}

export interface SplEvaluationInput {
  readonly method: string;
  readonly toolName: string;
  readonly args: JsonObject;
  readonly tenantId: string;
  readonly sessionId: string;
  readonly confidentiality: ConfidentialityLevel;
  readonly integrity: IntegrityLevel;
  readonly taintLabels: readonly string[];
  readonly toolCategories: readonly ToolCategory[];
  readonly sessionSpentMicroUsd: number;
  readonly estimatedCallMicroUsd: number;
  readonly payloadBytes: number;
}

export interface SplPolicyVerdict {
  readonly action: PolicyDecisionAction;
  readonly matchedRuleId?: string;
  readonly description?: string;
  readonly totalGasUsed: number;
  readonly evaluatedRuleCount: number;
}

const BUILTIN_NAMES = [
  'entropy',
  'len',
  'size',
  'args.size',
  'lower',
  'upper',
  'contains',
  'starts_with',
  'ends_with',
  'exists',
  'taint.has',
  'has_category',
  'cost.session_usd',
  'cost.estimated_usd',
] as const;

type BuiltinName = (typeof BUILTIN_NAMES)[number];

const UNDEFINED_SENTINEL: unique symbol = Symbol('spl.undefined');

type VmValue = JsonValue | typeof UNDEFINED_SENTINEL;

function computeShannonEntropy(text: string): number {
  if (text.length === 0) {
    return 0;
  }
  const counts = new Map<string, number>();
  for (const ch of text) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  const len = text.length;
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isTruthy(val: VmValue): boolean {
  if (val === UNDEFINED_SENTINEL || val === null || val === false) {
    return false;
  }
  if (val === 0 || val === '') {
    return false;
  }
  return true;
}

function valuesEqual(a: VmValue, b: VmValue): boolean {
  if (a === UNDEFINED_SENTINEL) {
    return b === UNDEFINED_SENTINEL || b === null;
  }
  if (b === UNDEFINED_SENTINEL) {
    return a === null;
  }
  return a === b;
}

function instructionGasCost(op: SplOpCode): number {
  switch (op) {
    case 'BINARY_MATCHES':
      return 15;
    case 'CALL_BUILTIN':
      return 8;
    case 'BINARY_IN':
    case 'MAKE_ARRAY':
      return 4;
    default:
      return 1;
  }
}

/**
 * Compiles a validated `SplAstNode` into flat stack bytecode instructions
 * with short-circuit jump targets and pre-compiled regular expressions.
 */
export function compileAstToBytecode(root: SplAstNode): Result<CompiledSplProgram, SentinelError> {
  const instructions: SplInstruction[] = [];
  const constants: JsonValue[] = [];
  const regexPool: RegExp[] = [];

  const addConstant = (val: JsonValue): number => {
    const existingIdx = constants.findIndex((item) => item === val);
    if (existingIdx !== -1) {
      return existingIdx;
    }
    constants.push(val);
    return constants.length - 1;
  };

  const emit = (node: SplAstNode): Result<void, SentinelError> => {
    switch (node.kind) {
      case 'Literal': {
        const idx = addConstant(node.value);
        instructions.push({ op: 'PUSH_CONST', arg: idx });
        return ok(undefined);
      }

      case 'ArrayLiteral': {
        for (const elem of node.elements) {
          const r = emit(elem);
          if (!r.ok) return r;
        }
        instructions.push({ op: 'MAKE_ARRAY', arg: node.elements.length });
        return ok(undefined);
      }

      case 'Identifier': {
        const idx = addConstant(node.name);
        instructions.push({ op: 'LOAD_ROOT', arg: idx });
        return ok(undefined);
      }

      case 'Member': {
        const parentRes = emit(node.object);
        if (!parentRes.ok) return parentRes;
        const propIdx = addConstant(node.property);
        instructions.push({ op: 'GET_PROP', arg: propIdx });
        return ok(undefined);
      }

      case 'Unary': {
        const opRes = emit(node.operand);
        if (!opRes.ok) return opRes;
        instructions.push({ op: node.operator === 'NOT' ? 'UNARY_NOT' : 'UNARY_NEG' });
        return ok(undefined);
      }

      case 'Binary': {
        if (node.operator === 'AND') {
          const lhsRes = emit(node.left);
          if (!lhsRes.ok) return lhsRes;
          const jumpIndex = instructions.length;
          instructions.push({ op: 'JUMP_IF_FALSE_SHORT', arg: 0 });
          const rhsRes = emit(node.right);
          if (!rhsRes.ok) return rhsRes;
          instructions.push({ op: 'TO_BOOL' });
          instructions[jumpIndex] = { op: 'JUMP_IF_FALSE_SHORT', arg: instructions.length };
          return ok(undefined);
        }

        if (node.operator === 'OR') {
          const lhsRes = emit(node.left);
          if (!lhsRes.ok) return lhsRes;
          const jumpIndex = instructions.length;
          instructions.push({ op: 'JUMP_IF_TRUE_SHORT', arg: 0 });
          const rhsRes = emit(node.right);
          if (!rhsRes.ok) return rhsRes;
          instructions.push({ op: 'TO_BOOL' });
          instructions[jumpIndex] = { op: 'JUMP_IF_TRUE_SHORT', arg: instructions.length };
          return ok(undefined);
        }

        if (node.operator === 'MATCHES') {
          const lhsRes = emit(node.left);
          if (!lhsRes.ok) return lhsRes;
          if (node.right.kind !== 'Literal' || typeof node.right.value !== 'string') {
            return err(
              createSentinelError(
                'POLICY_VIOLATION',
                'Right-hand side of "matches" must be a string literal',
                'spl-compiler',
              ),
            );
          }
          const compiledRegex = compileSafeRegex(node.right.value);
          if (!compiledRegex.ok) return compiledRegex;
          regexPool.push(compiledRegex.value);
          instructions.push({ op: 'BINARY_MATCHES', arg: regexPool.length - 1 });
          return ok(undefined);
        }

        const lhsRes = emit(node.left);
        if (!lhsRes.ok) return lhsRes;
        const rhsRes = emit(node.right);
        if (!rhsRes.ok) return rhsRes;

        const opMap: Readonly<
          Record<Exclude<typeof node.operator, 'AND' | 'OR' | 'MATCHES'>, SplOpCode>
        > = {
          EQ: 'BINARY_EQ',
          NEQ: 'BINARY_NEQ',
          LT: 'BINARY_LT',
          LTE: 'BINARY_LTE',
          GT: 'BINARY_GT',
          GTE: 'BINARY_GTE',
          IN: 'BINARY_IN',
          ADD: 'BINARY_ADD',
          SUB: 'BINARY_SUB',
          MUL: 'BINARY_MUL',
          DIV: 'BINARY_DIV',
          MOD: 'BINARY_MOD',
        };
        instructions.push({ op: opMap[node.operator] });
        return ok(undefined);
      }

      case 'Call': {
        const builtinIdx = BUILTIN_NAMES.indexOf(node.callee as BuiltinName);
        if (builtinIdx === -1) {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Unsupported built-in function "${node.callee}"`,
              'spl-compiler',
            ),
          );
        }
        for (const arg of node.args) {
          const argRes = emit(arg);
          if (!argRes.ok) return argRes;
        }
        instructions.push({
          op: 'CALL_BUILTIN',
          arg: builtinIdx,
          arg2: node.args.length,
        });
        return ok(undefined);
      }
    }
  };

  const emitted = emit(root);
  if (!emitted.ok) {
    return emitted;
  }

  instructions.push({ op: 'HALT' });

  return ok({
    instructions,
    constants,
    regexPool,
  });
}

/**
 * Non-recursive, deterministic Stack Bytecode Virtual Machine with strict gas metering.
 */
export function executeBytecodeProgram(
  program: CompiledSplProgram,
  context: SplEvaluationInput,
  maxGas: number,
): Result<{ readonly result: boolean; readonly gasUsed: number }, SentinelError> {
  const stack: VmValue[] = [];
  let ip = 0;
  let gasUsed = 0;

  const popValue = (): Result<VmValue, SentinelError> => {
    if (stack.length === 0) {
      return err(
        createSentinelError('INTERNAL_ERROR', 'SPL VM stack underflow', 'spl-vm'),
      );
    }
    const val = stack.pop();
    return ok(val === undefined ? UNDEFINED_SENTINEL : val);
  };

  while (ip < program.instructions.length) {
    const instr = program.instructions[ip];
    if (instr === undefined) {
      break;
    }

    gasUsed += instructionGasCost(instr.op);
    if (gasUsed > maxGas) {
      return err(
        createSentinelError(
          'POLICY_VIOLATION',
          `SPL VM execution exceeded gas budget (${gasUsed} > ${maxGas})`,
          'spl-vm',
          { gasUsed, maxGas },
        ),
      );
    }

    switch (instr.op) {
      case 'PUSH_CONST': {
        const c = instr.arg !== undefined ? program.constants[instr.arg] : undefined;
        stack.push(c === undefined ? UNDEFINED_SENTINEL : c);
        ip += 1;
        break;
      }

      case 'LOAD_ROOT': {
        const name = instr.arg !== undefined ? program.constants[instr.arg] : undefined;
        switch (name) {
          case 'tool':
            stack.push({
              name: context.toolName,
              categories: context.toolCategories,
            });
            break;
          case 'args':
            stack.push(context.args);
            break;
          case 'session':
            stack.push({
              id: context.sessionId,
              confidentiality: context.confidentiality,
              integrity: context.integrity,
              taint: context.taintLabels,
            });
            break;
          case 'cost':
            stack.push({
              session_micro_usd: context.sessionSpentMicroUsd,
              estimated_micro_usd: context.estimatedCallMicroUsd,
              session_usd: context.sessionSpentMicroUsd / 1_000_000,
              estimated_usd: context.estimatedCallMicroUsd / 1_000_000,
            });
            break;
          case 'tenant':
            stack.push(context.tenantId);
            break;
          case 'method':
            stack.push(context.method);
            break;
          default:
            stack.push(UNDEFINED_SENTINEL);
            break;
        }
        ip += 1;
        break;
      }

      case 'GET_PROP': {
        const propName = instr.arg !== undefined ? program.constants[instr.arg] : undefined;
        const targetRes = popValue();
        if (!targetRes.ok) return targetRes;
        const target = targetRes.value;

        if (
          typeof propName !== 'string' ||
          propName === '__proto__' ||
          propName === 'prototype' ||
          propName === 'constructor' ||
          target === UNDEFINED_SENTINEL ||
          !isJsonObject(target)
        ) {
          stack.push(UNDEFINED_SENTINEL);
        } else if (Object.prototype.hasOwnProperty.call(target, propName)) {
          const propVal = target[propName];
          stack.push(propVal === undefined ? UNDEFINED_SENTINEL : propVal);
        } else {
          stack.push(UNDEFINED_SENTINEL);
        }
        ip += 1;
        break;
      }

      case 'MAKE_ARRAY': {
        const count = instr.arg ?? 0;
        const arr: JsonValue[] = [];
        for (let i = 0; i < count; i += 1) {
          const popped = popValue();
          if (!popped.ok) return popped;
          arr.unshift(popped.value === UNDEFINED_SENTINEL ? null : popped.value);
        }
        stack.push(arr);
        ip += 1;
        break;
      }

      case 'UNARY_NOT': {
        const val = popValue();
        if (!val.ok) return val;
        stack.push(!isTruthy(val.value));
        ip += 1;
        break;
      }

      case 'UNARY_NEG': {
        const val = popValue();
        if (!val.ok) return val;
        if (typeof val.value !== 'number') {
          return err(
            createSentinelError('POLICY_VIOLATION', 'SPL runtime unary "-" on non-number', 'spl-vm'),
          );
        }
        stack.push(-val.value);
        ip += 1;
        break;
      }

      case 'TO_BOOL': {
        const val = popValue();
        if (!val.ok) return val;
        stack.push(isTruthy(val.value));
        ip += 1;
        break;
      }

      case 'JUMP_IF_FALSE_SHORT': {
        const top = popValue();
        if (!top.ok) return top;
        if (!isTruthy(top.value)) {
          stack.push(false);
          ip = instr.arg ?? ip + 1;
        } else {
          ip += 1;
        }
        break;
      }

      case 'JUMP_IF_TRUE_SHORT': {
        const top = popValue();
        if (!top.ok) return top;
        if (isTruthy(top.value)) {
          stack.push(true);
          ip = instr.arg ?? ip + 1;
        } else {
          ip += 1;
        }
        break;
      }

      case 'BINARY_EQ':
      case 'BINARY_NEQ': {
        const right = popValue();
        if (!right.ok) return right;
        const left = popValue();
        if (!left.ok) return left;
        const eq = valuesEqual(left.value, right.value);
        stack.push(instr.op === 'BINARY_EQ' ? eq : !eq);
        ip += 1;
        break;
      }

      case 'BINARY_LT':
      case 'BINARY_LTE':
      case 'BINARY_GT':
      case 'BINARY_GTE': {
        const right = popValue();
        if (!right.ok) return right;
        const left = popValue();
        if (!left.ok) return left;

        let cmpResult = false;
        if (typeof left.value === 'number' && typeof right.value === 'number') {
          if (instr.op === 'BINARY_LT') cmpResult = left.value < right.value;
          else if (instr.op === 'BINARY_LTE') cmpResult = left.value <= right.value;
          else if (instr.op === 'BINARY_GT') cmpResult = left.value > right.value;
          else cmpResult = left.value >= right.value;
        } else if (typeof left.value === 'string' && typeof right.value === 'string') {
          if (instr.op === 'BINARY_LT') cmpResult = left.value < right.value;
          else if (instr.op === 'BINARY_LTE') cmpResult = left.value <= right.value;
          else if (instr.op === 'BINARY_GT') cmpResult = left.value > right.value;
          else cmpResult = left.value >= right.value;
        }
        stack.push(cmpResult);
        ip += 1;
        break;
      }

      case 'BINARY_ADD':
      case 'BINARY_SUB':
      case 'BINARY_MUL':
      case 'BINARY_DIV':
      case 'BINARY_MOD': {
        const right = popValue();
        if (!right.ok) return right;
        const left = popValue();
        if (!left.ok) return left;
        if (typeof left.value !== 'number' || typeof right.value !== 'number') {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `SPL arithmetic operator ${instr.op} received non-numeric value at runtime`,
              'spl-vm',
            ),
          );
        }
        if ((instr.op === 'BINARY_DIV' || instr.op === 'BINARY_MOD') && right.value === 0) {
          return err(
            createSentinelError('POLICY_VIOLATION', 'SPL division by zero', 'spl-vm'),
          );
        }
        let computed = 0;
        if (instr.op === 'BINARY_ADD') computed = left.value + right.value;
        else if (instr.op === 'BINARY_SUB') computed = left.value - right.value;
        else if (instr.op === 'BINARY_MUL') computed = left.value * right.value;
        else if (instr.op === 'BINARY_DIV') computed = left.value / right.value;
        else computed = left.value % right.value;
        stack.push(computed);
        ip += 1;
        break;
      }

      case 'BINARY_IN': {
        const right = popValue();
        if (!right.ok) return right;
        const left = popValue();
        if (!left.ok) return left;
        if (Array.isArray(right.value)) {
          stack.push(right.value.some((item) => valuesEqual(left.value, item)));
        } else if (typeof right.value === 'string' && typeof left.value === 'string') {
          stack.push(right.value.includes(left.value));
        } else {
          stack.push(false);
        }
        ip += 1;
        break;
      }

      case 'BINARY_MATCHES': {
        const left = popValue();
        if (!left.ok) return left;
        const regex = instr.arg !== undefined ? program.regexPool[instr.arg] : undefined;
        if (regex === undefined || typeof left.value !== 'string') {
          stack.push(false);
        } else {
          // Charge extra proportional gas for scanning long strings
          gasUsed += Math.ceil(left.value.length / 256);
          if (gasUsed > maxGas) {
            return err(
              createSentinelError(
                'POLICY_VIOLATION',
                `SPL regex scan exceeded gas budget (${gasUsed} > ${maxGas})`,
                'spl-vm',
              ),
            );
          }
          stack.push(regex.test(left.value));
        }
        ip += 1;
        break;
      }

      case 'CALL_BUILTIN': {
        const fnName = instr.arg !== undefined ? BUILTIN_NAMES[instr.arg] : undefined;
        const argCount = instr.arg2 ?? 0;
        const fnArgs: VmValue[] = [];
        for (let i = 0; i < argCount; i += 1) {
          const popped = popValue();
          if (!popped.ok) return popped;
          fnArgs.unshift(popped.value);
        }

        const arg0 = fnArgs[0];
        const arg1 = fnArgs[1];

        switch (fnName) {
          case 'entropy': {
            const str = typeof arg0 === 'string' ? arg0 : '';
            gasUsed += Math.ceil(str.length / 128);
            stack.push(computeShannonEntropy(str));
            break;
          }
          case 'len':
          case 'size': {
            if (typeof arg0 === 'string') stack.push(Buffer.byteLength(arg0, 'utf8'));
            else if (Array.isArray(arg0)) stack.push(arg0.length);
            else if (arg0 !== undefined && arg0 !== UNDEFINED_SENTINEL && isJsonObject(arg0)) {
              stack.push(Object.keys(arg0).length);
            } else {
              stack.push(0);
            }
            break;
          }
          case 'args.size':
            stack.push(context.payloadBytes);
            break;
          case 'lower':
            stack.push(typeof arg0 === 'string' ? arg0.toLowerCase() : '');
            break;
          case 'upper':
            stack.push(typeof arg0 === 'string' ? arg0.toUpperCase() : '');
            break;
          case 'contains':
            stack.push(
              typeof arg0 === 'string' && typeof arg1 === 'string' ? arg0.includes(arg1) : false,
            );
            break;
          case 'starts_with':
            stack.push(
              typeof arg0 === 'string' && typeof arg1 === 'string' ? arg0.startsWith(arg1) : false,
            );
            break;
          case 'ends_with':
            stack.push(
              typeof arg0 === 'string' && typeof arg1 === 'string' ? arg0.endsWith(arg1) : false,
            );
            break;
          case 'exists':
            stack.push(arg0 !== undefined && arg0 !== UNDEFINED_SENTINEL && arg0 !== null);
            break;
          case 'taint.has':
            stack.push(
              typeof arg0 === 'string'
                ? context.taintLabels.includes(arg0) ||
                    context.confidentiality === arg0 ||
                    context.integrity === arg0
                : false,
            );
            break;
          case 'has_category':
            stack.push(
              typeof arg0 === 'string'
                ? context.toolCategories.includes(arg0 as ToolCategory)
                : false,
            );
            break;
          case 'cost.session_usd':
            stack.push(context.sessionSpentMicroUsd / 1_000_000);
            break;
          case 'cost.estimated_usd':
            stack.push(context.estimatedCallMicroUsd / 1_000_000);
            break;
          default:
            return err(
              createSentinelError(
                'INTERNAL_ERROR',
                `Unimplemented SPL builtin index ${String(instr.arg)}`,
                'spl-vm',
              ),
            );
        }
        ip += 1;
        break;
      }

      case 'HALT': {
        const finalVal = popValue();
        if (!finalVal.ok) return finalVal;
        return ok({
          result: isTruthy(finalVal.value),
          gasUsed,
        });
      }
    }
  }

  return err(
    createSentinelError('INTERNAL_ERROR', 'SPL VM terminated without HALT opcode', 'spl-vm'),
  );
}

interface CompiledRuleEntry {
  readonly meta: AnalyzedSplRule;
  readonly program: CompiledSplProgram;
}

/**
 * Pre-compiled SPL policy engine that statically validates rules once at boot
 * and executes bytecode rules deterministically on every request.
 */
export class SplPolicyEngine {
  private readonly compiledRules: readonly CompiledRuleEntry[];
  public readonly warnings: readonly StaticDiagnostic[];
  private readonly maxGasPerRule: number;

  private constructor(
    compiledRules: readonly CompiledRuleEntry[],
    warnings: readonly StaticDiagnostic[],
    maxGasPerRule: number,
  ) {
    this.compiledRules = compiledRules;
    this.warnings = warnings;
    this.maxGasPerRule = maxGasPerRule;
  }

  public static compile(
    rules: readonly SplRuleConfig[],
    maxGasPerRule = 2_000,
  ): Result<SplPolicyEngine, SentinelError> {
    const analysis = analyzePolicyRules(rules);
    if (!analysis.ok) {
      return analysis;
    }

    const entries: CompiledRuleEntry[] = [];
    for (const rule of analysis.value.rules) {
      const bytecode = compileAstToBytecode(rule.ast);
      if (!bytecode.ok) {
        return bytecode;
      }
      entries.push({
        meta: rule,
        program: bytecode.value,
      });
    }

    return ok(new SplPolicyEngine(entries, analysis.value.warnings, maxGasPerRule));
  }

  public evaluate(input: SplEvaluationInput): Result<SplPolicyVerdict, SentinelError> {
    let totalGasUsed = 0;
    let evaluatedRuleCount = 0;

    for (const entry of this.compiledRules) {
      evaluatedRuleCount += 1;
      const exec = executeBytecodeProgram(entry.program, input, this.maxGasPerRule);
      if (!exec.ok) {
        return exec;
      }
      totalGasUsed += exec.value.gasUsed;

      if (exec.value.result) {
        return ok({
          action: entry.meta.effect,
          matchedRuleId: entry.meta.id,
          totalGasUsed,
          evaluatedRuleCount,
          ...(entry.meta.description !== undefined ? { description: entry.meta.description } : {}),
        });
      }
    }

    return ok({
      action: 'ALLOW',
      totalGasUsed,
      evaluatedRuleCount,
    });
  }
}
