import { createSentinelError, type SentinelError } from '../types/errors.js';
import { err, ok, type Result } from '../types/result.js';
import { type SplToken, type SplTokenKind, tokenizeSpl } from './lexer.js';

export type SplUnaryOperator = 'NOT' | 'NEG';

export type SplBinaryOperator =
  | 'OR'
  | 'AND'
  | 'EQ'
  | 'NEQ'
  | 'LT'
  | 'LTE'
  | 'GT'
  | 'GTE'
  | 'IN'
  | 'MATCHES'
  | 'ADD'
  | 'SUB'
  | 'MUL'
  | 'DIV'
  | 'MOD';

export interface SplLiteralNode {
  readonly kind: 'Literal';
  readonly value: string | number | boolean | null;
  readonly offset: number;
}

export interface SplArrayLiteralNode {
  readonly kind: 'ArrayLiteral';
  readonly elements: readonly SplAstNode[];
  readonly offset: number;
}

export interface SplIdentifierNode {
  readonly kind: 'Identifier';
  readonly name: string;
  readonly offset: number;
}

export interface SplMemberNode {
  readonly kind: 'Member';
  readonly object: SplAstNode;
  readonly property: string;
  readonly offset: number;
}

export interface SplUnaryNode {
  readonly kind: 'Unary';
  readonly operator: SplUnaryOperator;
  readonly operand: SplAstNode;
  readonly offset: number;
}

export interface SplBinaryNode {
  readonly kind: 'Binary';
  readonly operator: SplBinaryOperator;
  readonly left: SplAstNode;
  readonly right: SplAstNode;
  readonly offset: number;
}

export interface SplCallNode {
  readonly kind: 'Call';
  readonly callee: string;
  readonly args: readonly SplAstNode[];
  readonly offset: number;
}

export type SplAstNode =
  | SplLiteralNode
  | SplArrayLiteralNode
  | SplIdentifierNode
  | SplMemberNode
  | SplUnaryNode
  | SplBinaryNode
  | SplCallNode;

const MAX_AST_DEPTH = 48;

interface BindingPower {
  readonly left: number;
  readonly right: number;
  readonly binaryOp?: SplBinaryOperator;
}

function getInfixBindingPower(kind: SplTokenKind): BindingPower | null {
  switch (kind) {
    case 'OR':
      return { left: 10, right: 11, binaryOp: 'OR' };
    case 'AND':
      return { left: 20, right: 21, binaryOp: 'AND' };
    case 'EQ':
      return { left: 30, right: 31, binaryOp: 'EQ' };
    case 'NEQ':
      return { left: 30, right: 31, binaryOp: 'NEQ' };
    case 'LT':
      return { left: 40, right: 41, binaryOp: 'LT' };
    case 'LTE':
      return { left: 40, right: 41, binaryOp: 'LTE' };
    case 'GT':
      return { left: 40, right: 41, binaryOp: 'GT' };
    case 'GTE':
      return { left: 40, right: 41, binaryOp: 'GTE' };
    case 'IN':
      return { left: 40, right: 41, binaryOp: 'IN' };
    case 'MATCHES':
      return { left: 40, right: 41, binaryOp: 'MATCHES' };
    case 'PLUS':
      return { left: 50, right: 51, binaryOp: 'ADD' };
    case 'MINUS':
      return { left: 50, right: 51, binaryOp: 'SUB' };
    case 'STAR':
      return { left: 60, right: 61, binaryOp: 'MUL' };
    case 'SLASH':
      return { left: 60, right: 61, binaryOp: 'DIV' };
    case 'MOD':
      return { left: 60, right: 61, binaryOp: 'MOD' };
    case 'DOT':
    case 'LBRACKET':
    case 'LPAREN':
      return { left: 80, right: 81 };
    default:
      return null;
  }
}

function flattenCalleePath(node: SplAstNode): string | null {
  if (node.kind === 'Identifier') {
    return node.name;
  }
  if (node.kind === 'Member') {
    const prefix = flattenCalleePath(node.object);
    if (prefix === null) {
      return null;
    }
    return `${prefix}.${node.property}`;
  }
  return null;
}

/**
 * Top-down operator-precedence Pratt parser for Sentinel Policy Language (SPL).
 */
export function parseSplTokens(tokens: readonly SplToken[]): Result<SplAstNode, SentinelError> {
  let cursor = 0;

  const current = (): SplToken => {
    const tok = tokens[cursor];
    if (tok !== undefined) {
      return tok;
    }
    const fallback = tokens[tokens.length - 1];
    if (fallback !== undefined) {
      return fallback;
    }
    return { kind: 'EOF', lexeme: '', offset: 0, line: 1, column: 1 };
  };

  const consume = (): SplToken => {
    const tok = current();
    if (cursor < tokens.length - 1) {
      cursor += 1;
    }
    return tok;
  };

  const expect = (expectedKind: SplTokenKind): Result<SplToken, SentinelError> => {
    const tok = current();
    if (tok.kind !== expectedKind) {
      return err(
        createSentinelError(
          'POLICY_VIOLATION',
          `Expected token ${expectedKind} but found ${tok.kind} ("${tok.lexeme}") at line ${tok.line}, column ${tok.column}`,
          'spl-parser',
        ),
      );
    }
    return ok(consume());
  };

  const parseExpression = (minBindingPower: number, depth: number): Result<SplAstNode, SentinelError> => {
    if (depth > MAX_AST_DEPTH) {
      return err(
        createSentinelError(
          'POLICY_VIOLATION',
          `SPL expression exceeded maximum AST nesting depth of ${MAX_AST_DEPTH}`,
          'spl-parser',
        ),
      );
    }

    const prefixToken = consume();
    let lhs: SplAstNode;

    switch (prefixToken.kind) {
      case 'STRING':
      case 'NUMBER':
      case 'BOOLEAN':
      case 'NULL': {
        lhs = {
          kind: 'Literal',
          value: prefixToken.literal ?? null,
          offset: prefixToken.offset,
        };
        break;
      }

      case 'IDENTIFIER': {
        lhs = {
          kind: 'Identifier',
          name: prefixToken.lexeme,
          offset: prefixToken.offset,
        };
        break;
      }

      case 'NOT':
      case 'MINUS': {
        const unaryOp: SplUnaryOperator = prefixToken.kind === 'NOT' ? 'NOT' : 'NEG';
        const operandResult = parseExpression(70, depth + 1);
        if (!operandResult.ok) {
          return operandResult;
        }
        lhs = {
          kind: 'Unary',
          operator: unaryOp,
          operand: operandResult.value,
          offset: prefixToken.offset,
        };
        break;
      }

      case 'LPAREN': {
        const inner = parseExpression(0, depth + 1);
        if (!inner.ok) {
          return inner;
        }
        const closeParen = expect('RPAREN');
        if (!closeParen.ok) {
          return closeParen;
        }
        lhs = inner.value;
        break;
      }

      case 'LBRACKET': {
        const elements: SplAstNode[] = [];
        if (current().kind !== 'RBRACKET') {
          while (true) {
            const elemResult = parseExpression(0, depth + 1);
            if (!elemResult.ok) {
              return elemResult;
            }
            elements.push(elemResult.value);
            if (current().kind === 'COMMA') {
              consume();
              continue;
            }
            break;
          }
        }
        const closeBracket = expect('RBRACKET');
        if (!closeBracket.ok) {
          return closeBracket;
        }
        lhs = {
          kind: 'ArrayLiteral',
          elements,
          offset: prefixToken.offset,
        };
        break;
      }

      default:
        return err(
          createSentinelError(
            'POLICY_VIOLATION',
            `Unexpected token ${prefixToken.kind} ("${prefixToken.lexeme}") at line ${prefixToken.line}, column ${prefixToken.column}`,
            'spl-parser',
          ),
        );
    }

    while (true) {
      const lookahead = current();
      if (lookahead.kind === 'EOF') {
        break;
      }

      const bp = getInfixBindingPower(lookahead.kind);
      if (bp === null || bp.left < minBindingPower) {
        break;
      }

      const opToken = consume();

      if (opToken.kind === 'DOT') {
        const propToken = current();
        if (
          propToken.kind !== 'IDENTIFIER' &&
          propToken.kind !== 'IN' &&
          propToken.kind !== 'MATCHES'
        ) {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Expected property name after "." at line ${propToken.line}, column ${propToken.column}`,
              'spl-parser',
            ),
          );
        }
        consume();
        lhs = {
          kind: 'Member',
          object: lhs,
          property: propToken.lexeme,
          offset: opToken.offset,
        };
        continue;
      }

      if (opToken.kind === 'LBRACKET') {
        const indexExpr = parseExpression(0, depth + 1);
        if (!indexExpr.ok) {
          return indexExpr;
        }
        const closeIdx = expect('RBRACKET');
        if (!closeIdx.ok) {
          return closeIdx;
        }
        if (indexExpr.value.kind !== 'Literal' || typeof indexExpr.value.value !== 'string') {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Bracket member access requires a string literal key at line ${opToken.line}, column ${opToken.column}`,
              'spl-parser',
            ),
          );
        }
        lhs = {
          kind: 'Member',
          object: lhs,
          property: indexExpr.value.value,
          offset: opToken.offset,
        };
        continue;
      }

      if (opToken.kind === 'LPAREN') {
        const calleeName = flattenCalleePath(lhs);
        if (calleeName === null) {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Invalid function call target at line ${opToken.line}, column ${opToken.column}`,
              'spl-parser',
            ),
          );
        }

        const callArgs: SplAstNode[] = [];
        if (current().kind !== 'RPAREN') {
          while (true) {
            const argResult = parseExpression(0, depth + 1);
            if (!argResult.ok) {
              return argResult;
            }
            callArgs.push(argResult.value);
            if (current().kind === 'COMMA') {
              consume();
              continue;
            }
            break;
          }
        }

        const closeCall = expect('RPAREN');
        if (!closeCall.ok) {
          return closeCall;
        }

        lhs = {
          kind: 'Call',
          callee: calleeName,
          args: callArgs,
          offset: lhs.offset,
        };
        continue;
      }

      if (bp.binaryOp === undefined) {
        return err(
          createSentinelError(
            'INTERNAL_ERROR',
            `Missing binary operator mapping for token ${opToken.kind}`,
            'spl-parser',
          ),
        );
      }

      const rhsResult = parseExpression(bp.right, depth + 1);
      if (!rhsResult.ok) {
        return rhsResult;
      }

      lhs = {
        kind: 'Binary',
        operator: bp.binaryOp,
        left: lhs,
        right: rhsResult.value,
        offset: opToken.offset,
      };
    }

    return ok(lhs);
  };

  const astResult = parseExpression(0, 0);
  if (!astResult.ok) {
    return astResult;
  }

  const trailing = current();
  if (trailing.kind !== 'EOF') {
    return err(
      createSentinelError(
        'POLICY_VIOLATION',
        `Unexpected trailing token "${trailing.lexeme}" at line ${trailing.line}, column ${trailing.column}`,
        'spl-parser',
      ),
    );
  }

  return astResult;
}

export function parseSplExpression(source: string): Result<SplAstNode, SentinelError> {
  const tokenized = tokenizeSpl(source);
  if (!tokenized.ok) {
    return tokenized;
  }
  return parseSplTokens(tokenized.value);
}
