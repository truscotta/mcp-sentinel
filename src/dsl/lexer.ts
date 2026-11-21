import { createSentinelError, type SentinelError } from '../types/errors.js';
import { err, ok, type Result } from '../types/result.js';

export type SplTokenKind =
  | 'STRING'
  | 'NUMBER'
  | 'BOOLEAN'
  | 'NULL'
  | 'IDENTIFIER'
  | 'AND'
  | 'OR'
  | 'NOT'
  | 'IN'
  | 'MATCHES'
  | 'EQ'
  | 'NEQ'
  | 'LT'
  | 'LTE'
  | 'GT'
  | 'GTE'
  | 'PLUS'
  | 'MINUS'
  | 'STAR'
  | 'SLASH'
  | 'MOD'
  | 'LPAREN'
  | 'RPAREN'
  | 'LBRACKET'
  | 'RBRACKET'
  | 'DOT'
  | 'COMMA'
  | 'EOF';

export interface SplToken {
  readonly kind: SplTokenKind;
  readonly lexeme: string;
  readonly literal?: string | number | boolean | null;
  readonly offset: number;
  readonly line: number;
  readonly column: number;
}

const KEYWORDS: Readonly<Record<string, SplTokenKind>> = {
  and: 'AND',
  or: 'OR',
  not: 'NOT',
  in: 'IN',
  matches: 'MATCHES',
  true: 'BOOLEAN',
  false: 'BOOLEAN',
  null: 'NULL',
};

function isWhitespace(ch: string): boolean {
  return ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n';
}

function isDigit(ch: string): boolean {
  return ch >= '0' && ch <= '9';
}

function isIdentifierStart(ch: string): boolean {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_';
}

function isIdentifierPart(ch: string): boolean {
  return isIdentifierStart(ch) || isDigit(ch);
}

/**
 * Zero-dependency lexical scanner for Sentinel Policy Language (SPL).
 * Tracks exact line, column, and byte-offset coordinates for every token.
 */
export function tokenizeSpl(source: string): Result<readonly SplToken[], SentinelError> {
  if (source.length > 16_384) {
    return err(
      createSentinelError(
        'POLICY_VIOLATION',
        'SPL expression exceeds maximum length of 16,384 characters',
        'spl-lexer',
      ),
    );
  }

  const tokens: SplToken[] = [];
  let pos = 0;
  let line = 1;
  let column = 1;

  const advance = (): string | undefined => {
    const ch = source[pos];
    if (ch === undefined) {
      return undefined;
    }
    pos += 1;
    if (ch === '\n') {
      line += 1;
      column = 1;
    } else {
      column += 1;
    }
    return ch;
  };

  const peek = (ahead = 0): string | undefined => source[pos + ahead];

  while (pos < source.length) {
    const current = peek();
    if (current === undefined) {
      break;
    }

    if (isWhitespace(current)) {
      advance();
      continue;
    }

    // Support single-line comments (# ... or // ...)
    if (current === '#' || (current === '/' && peek(1) === '/')) {
      while (pos < source.length && peek() !== '\n') {
        advance();
      }
      continue;
    }

    const startOffset = pos;
    const startLine = line;
    const startCol = column;

    // String literals ('...' or "...")
    if (current === '"' || current === "'") {
      const quote = advance();
      let decoded = '';
      let terminated = false;

      while (pos < source.length) {
        const ch = advance();
        if (ch === undefined) {
          break;
        }
        if (ch === quote) {
          terminated = true;
          break;
        }
        if (ch === '\n') {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Unterminated string literal at line ${startLine}, column ${startCol}`,
              'spl-lexer',
            ),
          );
        }
        if (ch === '\\') {
          const escaped = advance();
          if (escaped === undefined) {
            return err(
              createSentinelError(
                'POLICY_VIOLATION',
                `Dangling escape sequence at line ${line}, column ${column}`,
                'spl-lexer',
              ),
            );
          }
          switch (escaped) {
            case 'n':
              decoded += '\n';
              break;
            case 'r':
              decoded += '\r';
              break;
            case 't':
              decoded += '\t';
              break;
            case '\\':
              decoded += '\\';
              break;
            case '"':
              decoded += '"';
              break;
            case "'":
              decoded += "'";
              break;
            default:
              decoded += `\\${escaped}`;
              break;
          }
        } else {
          decoded += ch;
        }
      }

      if (!terminated) {
        return err(
          createSentinelError(
            'POLICY_VIOLATION',
            `Unterminated string literal starting at line ${startLine}, column ${startCol}`,
            'spl-lexer',
          ),
        );
      }

      tokens.push({
        kind: 'STRING',
        lexeme: source.slice(startOffset, pos),
        literal: decoded,
        offset: startOffset,
        line: startLine,
        column: startCol,
      });
      continue;
    }

    // Numeric literals
    if (isDigit(current)) {
      let hasDot = false;
      while (pos < source.length) {
        const ch = peek();
        if (ch !== undefined && isDigit(ch)) {
          advance();
        } else if (ch === '.' && !hasDot) {
          const afterDot = peek(1);
          if (afterDot !== undefined && isDigit(afterDot)) {
            hasDot = true;
            advance();
          } else {
            break;
          }
        } else {
          break;
        }
      }

      const lexeme = source.slice(startOffset, pos);
      const numericValue = Number(lexeme);
      if (!Number.isFinite(numericValue)) {
        return err(
          createSentinelError(
            'POLICY_VIOLATION',
            `Invalid numeric literal "${lexeme}" at line ${startLine}, column ${startCol}`,
            'spl-lexer',
          ),
        );
      }

      tokens.push({
        kind: 'NUMBER',
        lexeme,
        literal: numericValue,
        offset: startOffset,
        line: startLine,
        column: startCol,
      });
      continue;
    }

    // Identifiers and reserved keywords
    if (isIdentifierStart(current)) {
      while (pos < source.length) {
        const ch = peek();
        if (ch !== undefined && isIdentifierPart(ch)) {
          advance();
        } else {
          break;
        }
      }

      const lexeme = source.slice(startOffset, pos);
      const keywordKind = KEYWORDS[lexeme];
      if (keywordKind === 'BOOLEAN') {
        tokens.push({
          kind: 'BOOLEAN',
          lexeme,
          literal: lexeme === 'true',
          offset: startOffset,
          line: startLine,
          column: startCol,
        });
      } else if (keywordKind === 'NULL') {
        tokens.push({
          kind: 'NULL',
          lexeme,
          literal: null,
          offset: startOffset,
          line: startLine,
          column: startCol,
        });
      } else if (keywordKind !== undefined) {
        tokens.push({
          kind: keywordKind,
          lexeme,
          offset: startOffset,
          line: startLine,
          column: startCol,
        });
      } else {
        tokens.push({
          kind: 'IDENTIFIER',
          lexeme,
          offset: startOffset,
          line: startLine,
          column: startCol,
        });
      }
      continue;
    }

    // Operators and punctuation
    const ch = advance();
    if (ch === undefined) {
      break;
    }

    const pushSimple = (kind: SplTokenKind): void => {
      tokens.push({
        kind,
        lexeme: source.slice(startOffset, pos),
        offset: startOffset,
        line: startLine,
        column: startCol,
      });
    };

    switch (ch) {
      case '(':
        pushSimple('LPAREN');
        break;
      case ')':
        pushSimple('RPAREN');
        break;
      case '[':
        pushSimple('LBRACKET');
        break;
      case ']':
        pushSimple('RBRACKET');
        break;
      case '.':
        pushSimple('DOT');
        break;
      case ',':
        pushSimple('COMMA');
        break;
      case '+':
        pushSimple('PLUS');
        break;
      case '-':
        pushSimple('MINUS');
        break;
      case '*':
        pushSimple('STAR');
        break;
      case '/':
        pushSimple('SLASH');
        break;
      case '%':
        pushSimple('MOD');
        break;
      case '=':
        if (peek() === '=') {
          advance();
          pushSimple('EQ');
        } else {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Unexpected single "=" at line ${startLine}, column ${startCol}; use "==" for equality`,
              'spl-lexer',
            ),
          );
        }
        break;
      case '!':
        if (peek() === '=') {
          advance();
          pushSimple('NEQ');
        } else {
          pushSimple('NOT');
        }
        break;
      case '<':
        if (peek() === '=') {
          advance();
          pushSimple('LTE');
        } else {
          pushSimple('LT');
        }
        break;
      case '>':
        if (peek() === '=') {
          advance();
          pushSimple('GTE');
        } else {
          pushSimple('GT');
        }
        break;
      case '&':
        if (peek() === '&') {
          advance();
          pushSimple('AND');
        } else {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Unexpected "&" at line ${startLine}, column ${startCol}; use "and" or "&&"`,
              'spl-lexer',
            ),
          );
        }
        break;
      case '|':
        if (peek() === '|') {
          advance();
          pushSimple('OR');
        } else {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Unexpected "|" at line ${startLine}, column ${startCol}; use "or" or "||"`,
              'spl-lexer',
            ),
          );
        }
        break;
      default:
        return err(
          createSentinelError(
            'POLICY_VIOLATION',
            `Unexpected character "${ch}" at line ${startLine}, column ${startCol}`,
            'spl-lexer',
          ),
        );
    }
  }

  tokens.push({
    kind: 'EOF',
    lexeme: '',
    offset: pos,
    line,
    column,
  });

  return ok(tokens);
}
