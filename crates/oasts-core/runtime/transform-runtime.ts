/// <reference lib="esnext.temporal" preserve="true" />
// Hand-written date/time codec kernel, emitted verbatim as client/transform/runtime.ts. Every
// export is part of the generated-transform ABI: the Rust emitter compiles call sites against
// these exact signatures, so the surface is fixed and additive-only. All helpers are pure and
// side-effect-free at import time — the module-scope RegExps and the month-length table are
// constant allocations that never throw or touch IO.
//
// The wire grammar is validated here rather than delegated to the engine, because both engines
// are more permissive than the contract: `new Date(...)` accepts shapes outside RFC 3339 and
// `Temporal.Instant.from` silently clamps the leap second `:60` down to `:59`. Every accepted
// string is parsed field by field, and the engine value is then built from the parsed fields.
//
// Encoding runs the inverse: the engine produces its canonical text and that text is checked
// against the same grammar, so an expanded year (`+010000-01-01`) or a calendar annotation
// (`2024-02-29[u-ca=hebrew]`) is refused rather than silently written to the wire.

import { type ApplicationPath, type SourcePointer, TransformError } from "./result.ts";

type RawJson = Readonly<{ rawJSON: string }>;

declare global {
  interface JSON {
    rawJSON?: (text: string) => RawJson;
  }
}

// Captured once: a missing API is a runtime capability, not a value-by-value decision.
const rawJson = typeof JSON.rawJSON === "function" ? JSON.rawJSON : null;

/** Extend a path without mutating the parent, so each nested transform forks its own child path. */
export function pushPath(path: ApplicationPath, key: string | number): ApplicationPath {
  return [...path, key];
}

let losslessJsonValue: unknown;

/** Runs a synchronous schema walk against the exact parse of the same JSON document. */
export function withLosslessJson<T>(lossless: unknown, revive: () => T): T {
  const previous = losslessJsonValue;
  losslessJsonValue = lossless;
  try {
    return revive();
  } finally {
    losslessJsonValue = previous;
  }
}

/** Reads the exact integer token at one schema-selected path in the active JSON document. */
export function losslessInt64(path: ApplicationPath): number | bigint {
  let value = losslessJsonValue;
  for (const key of path) {
    if (typeof value !== "object" || value === null) {
      throw new TypeError("lossless JSON path does not exist");
    }
    value = Reflect.get(value, key);
  }
  if (typeof value !== "number" && typeof value !== "bigint") {
    throw new TypeError("lossless JSON path is not an integer");
  }
  return value;
}

/**
 * Runs one conversion, turning any non-`TransformError` throw into one.
 *
 * The codecs validate every leaf they read, but they walk containers by property access and
 * `.map()` — so a body that parses as JSON and is simply the wrong shape (`null`, or an array where
 * an object is declared) faults natively part-way through rather than at a leaf. That is a decode
 * failure like any other, and the contract is that a decode failure is a result arm, not a rejected
 * promise. Wrapping at the operation's own entry point covers every position beneath it, so the
 * per-property codecs stay free of shape guards they would otherwise repeat at every node.
 *
 * The native error is preserved as `cause`; the pointer is the converting position's own.
 */
export function guarded<T>(
  convert: () => T,
  direction: TransformError["direction"],
  pointer: SourcePointer,
): T {
  try {
    return convert();
  } catch (error) {
    if (error instanceof TransformError) {
      throw error;
    }
    throw new TransformError({
      direction,
      code: direction === "response" ? "invalid-wire-value" : "invalid-application-value",
      sourcePointer: pointer,
      applicationPath: [],
      cause: error,
    });
  }
}

/**
 * `value` without `key`.
 *
 * A converted optional property cannot simply be spread over the original: TypeScript unions the
 * spread of `{} | { at: Date }` with the base's own `at?: string`, so the result keeps both types
 * and assigns to neither surface. Removing the key from the base first is what makes the spread
 * land — and it keeps an absent optional absent, rather than present with `undefined`, which the
 * simpler form would do and which fails outright under `exactOptionalPropertyTypes`.
 */
export function omit<T extends object, K extends keyof T>(value: T, key: K): Omit<T, K> {
  const { [key]: removed, ...rest } = value;
  void removed;
  return rest;
}

// Anchored, and deliberately without `\s` slack: surrounding whitespace is not part of the
// grammar. The fraction is captured at any width and its width is checked per mode, so the
// three-digit `Date` ceiling and the nine-digit `Instant` ceiling share one pattern.
const DATE_TIME =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:([Zz])|([+-])(\d{2}):(\d{2}))$/;
const FULL_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
// The canonical forms each encoder must produce. `Date#toISOString` and `Temporal`'s `toString`
// widen the year and annotate the calendar when the value leaves the representable space, so
// matching these is what makes an unrepresentable application value observable.
const CANONICAL_DATE_TIME_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CANONICAL_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const CANONICAL_FULL_DATE = /^\d{4}-\d{2}-\d{2}$/;

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

// undefined when the month falls outside 1..12: the table lookup is the range check.
function daysInMonth(year: number, month: number): number | undefined {
  return month === 2 && isLeapYear(year) ? 29 : DAYS_IN_MONTH[month - 1];
}

function wireFailure(
  value: unknown,
  pointer: SourcePointer,
  path: ApplicationPath,
): TransformError {
  return new TransformError({
    direction: "response",
    code: "invalid-wire-value",
    sourcePointer: pointer,
    applicationPath: path,
    cause: value,
  });
}

function applicationFailure(
  value: unknown,
  pointer: SourcePointer,
  path: ApplicationPath,
): TransformError {
  return new TransformError({
    direction: "request",
    code: "invalid-application-value",
    sourcePointer: pointer,
    applicationPath: path,
    cause: value,
  });
}

/** Decodes an int64 wire number without losing a digit. */
export function decodeInt64(
  value: number | bigint | RawJson,
  pointer: SourcePointer,
  path: ApplicationPath,
): bigint {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw wireFailure(value, pointer, path);
  }
  return BigInt(value);
}

/** Encodes an int64 bigint as exact unquoted JSON digits where the runtime supports raw JSON. */
export function encodeInt64(
  value: bigint,
  pointer: SourcePointer,
  path: ApplicationPath,
): RawJson | number {
  if (typeof value !== "bigint") {
    throw applicationFailure(value, pointer, path);
  }
  if (rawJson !== null) {
    return rawJson(String(value));
  }
  const number = Number(value);
  if (!Number.isSafeInteger(number)) {
    throw applicationFailure(value, pointer, path);
  }
  return number;
}

function temporalFailure(
  direction: "request" | "response",
  pointer: SourcePointer,
  path: ApplicationPath,
): TransformError {
  return new TransformError({
    direction,
    code: "temporal-unavailable",
    sourcePointer: pointer,
    applicationPath: path,
    cause: undefined,
  });
}

/**
 * The Temporal namespace, or a named failure. Read through this at every call rather than once at
 * import time: a module-scope read would freeze the answer before a polyfill-free host could ever
 * report it, and would make the failure a load-time surprise instead of a result arm.
 */
function requireTemporal(
  direction: "request" | "response",
  pointer: SourcePointer,
  path: ApplicationPath,
): typeof Temporal {
  if (typeof globalThis.Temporal === "undefined") {
    throw temporalFailure(direction, pointer, path);
  }
  return globalThis.Temporal;
}

type WireDateTime = {
  /** Milliseconds since the epoch with the fractional part excluded and the offset applied. */
  readonly epochMilliseconds: number;
  /** The fraction exactly as written, without its leading dot; empty when none was written. */
  readonly fraction: string;
};

/**
 * Parses an RFC 3339 date-time under the contract's exact grammar, returning `null` for anything
 * outside it: a leap second, `-00:00`, a fraction wider than `maxFractionDigits`, an out-of-range
 * field, or a calendar day the month does not have.
 */
function parseDateTime(value: unknown, maxFractionDigits: number): WireDateTime | null {
  if (typeof value !== "string") {
    return null;
  }
  const match = DATE_TIME.exec(value);
  if (match === null) {
    return null;
  }
  const [
    ,
    yearText,
    monthText,
    dayText,
    hourText,
    minuteText,
    secondText,
    fraction,
    zulu,
    sign,
    offsetHourText,
    offsetMinuteText,
  ] = match;
  if (fraction !== undefined && fraction.length > maxFractionDigits) {
    return null;
  }
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const maxDay = daysInMonth(year, month);
  if (maxDay === undefined || day < 1 || day > maxDay) {
    return null;
  }
  // Second 60 is legal RFC 3339 but neither Date nor Instant can hold a leap second.
  if (hour > 23 || minute > 59 || second > 59) {
    return null;
  }
  let offsetMinutes = 0;
  if (zulu === undefined) {
    const offsetHour = Number(offsetHourText);
    const offsetMinute = Number(offsetMinuteText);
    if (offsetHour > 23 || offsetMinute > 59) {
      return null;
    }
    offsetMinutes = offsetHour * 60 + offsetMinute;
    if (sign === "-") {
      // -00:00 denotes an unknown local offset rather than UTC, so it names no instant.
      if (offsetMinutes === 0) {
        return null;
      }
      offsetMinutes = -offsetMinutes;
    }
  }
  // `setUTCFullYear` rather than `Date.UTC`, which maps years 0-99 into the 1900s.
  const utc = new Date(0);
  utc.setUTCFullYear(year, month - 1, day);
  utc.setUTCHours(hour, minute, second, 0);
  return {
    epochMilliseconds: utc.getTime() - offsetMinutes * 60_000,
    fraction: fraction ?? "",
  };
}

/**
 * Whether `value` is a `Temporal.Instant`, answering `false` rather than throwing on a runtime with
 * no Temporal at all.
 *
 * A union branch is selected by the value's own shape, and on the application side a converted
 * branch holds a runtime object where the wire held a string — so the encode direction tests the
 * application shape. A bare `instanceof globalThis.Temporal.Instant` would throw before it could
 * answer where the global is missing.
 */
export function isInstant(value: unknown): value is Temporal.Instant {
  return typeof globalThis.Temporal !== "undefined" && value instanceof globalThis.Temporal.Instant;
}

/** Whether `value` is a `Temporal.PlainDate`; see [`isInstant`] for why this is not bare instanceof. */
export function isPlainDate(value: unknown): value is Temporal.PlainDate {
  return (
    typeof globalThis.Temporal !== "undefined" && value instanceof globalThis.Temporal.PlainDate
  );
}

/** Decodes an RFC 3339 date-time to a `Date`, at millisecond resolution. */
export function decodeDateTimeDate(
  value: unknown,
  pointer: SourcePointer,
  path: ApplicationPath,
): Date {
  const parsed = parseDateTime(value, 3);
  if (parsed === null) {
    throw wireFailure(value, pointer, path);
  }
  return new Date(parsed.epochMilliseconds + Number(parsed.fraction.padEnd(3, "0")));
}

/** Encodes a `Date` as canonical UTC `YYYY-MM-DDTHH:mm:ss.sssZ`; a source offset is normalized. */
export function encodeDateTimeDate(
  value: unknown,
  pointer: SourcePointer,
  path: ApplicationPath,
): string {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw applicationFailure(value, pointer, path);
  }
  const text = value.toISOString();
  if (!CANONICAL_DATE_TIME_MS.test(text)) {
    throw applicationFailure(value, pointer, path);
  }
  return text;
}

/** Decodes an RFC 3339 date-time to a `Temporal.Instant`, at nanosecond resolution. */
export function decodeInstant(
  value: unknown,
  pointer: SourcePointer,
  path: ApplicationPath,
): Temporal.Instant {
  const temporal = requireTemporal("response", pointer, path);
  const parsed = parseDateTime(value, 9);
  if (parsed === null) {
    throw wireFailure(value, pointer, path);
  }
  const nanoseconds =
    BigInt(parsed.epochMilliseconds) * 1_000_000n + BigInt(parsed.fraction.padEnd(9, "0"));
  return new temporal.Instant(nanoseconds);
}

/** Encodes a `Temporal.Instant` as canonical UTC with the minimal fractional digits needed. */
export function encodeInstant(
  value: unknown,
  pointer: SourcePointer,
  path: ApplicationPath,
): string {
  const temporal = requireTemporal("request", pointer, path);
  if (!(value instanceof temporal.Instant)) {
    throw applicationFailure(value, pointer, path);
  }
  const text = value.toString();
  if (!CANONICAL_INSTANT.test(text)) {
    throw applicationFailure(value, pointer, path);
  }
  return text;
}

/** Decodes an RFC 3339 `full-date` to an ISO-calendar `Temporal.PlainDate`. */
export function decodePlainDate(
  value: unknown,
  pointer: SourcePointer,
  path: ApplicationPath,
): Temporal.PlainDate {
  const temporal = requireTemporal("response", pointer, path);
  if (typeof value !== "string") {
    throw wireFailure(value, pointer, path);
  }
  const match = FULL_DATE.exec(value);
  if (match === null) {
    throw wireFailure(value, pointer, path);
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const maxDay = daysInMonth(year, month);
  if (maxDay === undefined || day < 1 || day > maxDay) {
    throw wireFailure(value, pointer, path);
  }
  return new temporal.PlainDate(year, month, day);
}

/** Encodes an ISO-calendar `Temporal.PlainDate` as canonical `YYYY-MM-DD`. */
export function encodePlainDate(
  value: unknown,
  pointer: SourcePointer,
  path: ApplicationPath,
): string {
  const temporal = requireTemporal("request", pointer, path);
  if (!(value instanceof temporal.PlainDate)) {
    throw applicationFailure(value, pointer, path);
  }
  // A non-ISO calendar renders as `YYYY-MM-DD[u-ca=hebrew]` and a year outside the four-digit
  // range renders expanded, so the canonical test refuses both without reading a calendar field
  // whose name has moved between Temporal revisions.
  const text = value.toString();
  if (!CANONICAL_FULL_DATE.test(text)) {
    throw applicationFailure(value, pointer, path);
  }
  return text;
}
