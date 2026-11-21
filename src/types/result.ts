/**
 * Algebraic discriminated union representing either a successful computation (`Ok<T>`)
 * or a typed failure (`Err<E>`). Eliminates implicit control flow via thrown exceptions
 * across security-critical governance boundaries.
 */
export interface Ok<T> {
  readonly ok: true;
  readonly value: T;
}

export interface Err<E> {
  readonly ok: false;
  readonly error: E;
}

export type Result<T, E = Error> = Ok<T> | Err<E>;

export function ok<T>(value: T): Ok<T> {
  return { ok: true, value };
}

export function err<E>(error: E): Err<E> {
  return { ok: false, error };
}

export function isOk<T, E>(result: Result<T, E>): result is Ok<T> {
  return result.ok;
}

export function isErr<T, E>(result: Result<T, E>): result is Err<E> {
  return !result.ok;
}

export function mapResult<T, U, E>(result: Result<T, E>, fn: (value: T) => U): Result<U, E> {
  if (result.ok) {
    return ok(fn(result.value));
  }
  return result;
}

export function mapErr<T, E, F>(result: Result<T, E>, fn: (error: E) => F): Result<T, F> {
  if (!result.ok) {
    return err(fn(result.error));
  }
  return result;
}

export function andThen<T, U, E>(
  result: Result<T, E>,
  fn: (value: T) => Result<U, E>,
): Result<U, E> {
  if (result.ok) {
    return fn(result.value);
  }
  return result;
}

export function unwrapOr<T, E>(result: Result<T, E>, fallback: T): T {
  return result.ok ? result.value : fallback;
}

export function collectResults<T, E>(results: readonly Result<T, E>[]): Result<T[], E> {
  const values: T[] = [];
  for (const item of results) {
    if (!item.ok) {
      return item;
    }
    values.push(item.value);
  }
  return ok(values);
}

export function trySync<T, E>(fn: () => T, mapException: (cause: unknown) => E): Result<T, E> {
  try {
    return ok(fn());
  } catch (cause: unknown) {
    return err(mapException(cause));
  }
}

export async function tryAsync<T, E>(
  fn: () => Promise<T>,
  mapException: (cause: unknown) => E,
): Promise<Result<T, E>> {
  try {
    const value = await fn();
    return ok(value);
  } catch (cause: unknown) {
    return err(mapException(cause));
  }
}
