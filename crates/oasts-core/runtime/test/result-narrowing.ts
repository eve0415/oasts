// Narrowing helpers for the transport's erased result mirror.
//
// A generated operation module declares its own literal outcome space, so `switch (result.outcome)`
// narrows there without help. These tests drive `execute` directly against ad-hoc descriptors, so
// they see `ExecutionResult`, whose HTTP arms are keyed on the whole `number | ResponseRangeKey`
// space rather than on one operation's declared keys. These predicates recover the three families
// a test usually wants to assert about.
import type { RequestPhaseFailure, ResponsePhaseFailure } from "../result.ts";
import type { ExecutionResult, ResponseRangeKey } from "../transport.ts";

/** A matched documented branch — success or documented error. */
export type DocumentedResult = Extract<
  ExecutionResult,
  { readonly outcome: number | ResponseRangeKey }
>;

const RANGE_KEY = /^[0-9]XX$/u;

/**
 * True for a branch the document declared, false for `unmatched` and for every failure tag.
 * `result.ok` is not a substitute: a documented non-2xx branch is also `ok: false`.
 */
export function isDocumented(result: ExecutionResult): result is DocumentedResult {
  return (
    typeof result.outcome === "number" ||
    result.outcome === "default" ||
    RANGE_KEY.test(result.outcome)
  );
}

export const RESPONSE_FAILURE_OUTCOMES = [
  "response-aborted",
  "response-timeout",
  "response-decode",
  "response-validation",
  "response-transform",
  "response-middleware",
] as const;

export function isResponsePhaseFailure(
  result: ExecutionResult,
): result is ResponsePhaseFailure<number | ResponseRangeKey> {
  return (
    typeof result.outcome === "string" &&
    RESPONSE_FAILURE_OUTCOMES.some((outcome) => outcome === result.outcome)
  );
}

/** Narrows to a response-phase failure, throwing with the actual outcome when it is not one. */
export function responseFailure(
  result: ExecutionResult,
): ResponsePhaseFailure<number | ResponseRangeKey> {
  if (!isResponsePhaseFailure(result)) {
    throw new Error(`expected a response-phase failure, received ${String(result.outcome)}`);
  }
  return result;
}

/** True for the arms that carry no status, match, or metadata — nothing was ever dispatched. */
export function isRequestPhaseFailure(result: ExecutionResult): result is RequestPhaseFailure {
  return !("status" in result);
}

/** Narrows to a request-phase failure — the arms that carry no status, match, or metadata. */
export function requestFailure(result: ExecutionResult): RequestPhaseFailure {
  if (!isRequestPhaseFailure(result)) {
    throw new Error(`expected a request-phase failure, received ${String(result.outcome)}`);
  }
  return result;
}
