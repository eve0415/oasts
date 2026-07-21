// Hand-written validation kernel, emitted verbatim as validators/runtime.ts. Every export
// is part of the generated-validator ABI: the Rust emitter compiles call sites against these
// exact signatures, so the surface is fixed and additive-only. All helpers are pure and
// side-effect-free at import time — the module-scope RegExp, lookup literals, and reused scratch
// DataView are constant allocations that never throw or touch IO.

export type Issue = {
  readonly message: string;
  readonly path: readonly (string | number)[];
};

// A validation failure at a location. `path` is the caller's array by reference; validators
// treat issues as immutable, and the result is a plain literal so it survives JSON.stringify.
export function issue(path: readonly (string | number)[], message: string): Issue {
  return { message, path };
}

// Extend a path without mutating the parent, so each nested validator forks its own child path.
export function appendKey(
  path: readonly (string | number)[],
  key: string | number,
): readonly (string | number)[] {
  return [...path, key];
}

// Guards narrow `unknown` to concrete container shapes without an `any[]` widening or a cast.
function isArray(value: unknown): value is readonly unknown[] {
  return Array.isArray(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// JSON-value equality: numbers/strings/booleans/null by ===, arrays ordered and pairwise,
// objects by own-enumerable-key set (order-insensitive) with pairwise values. Mixed shapes differ.
export function deepEqual(a: unknown, b: unknown): boolean {
  if (isArray(a)) {
    if (!isArray(b) || a.length !== b.length) {
      return false;
    }
    for (let index = 0; index < a.length; index += 1) {
      if (!deepEqual(a[index], b[index])) {
        return false;
      }
    }
    return true;
  }
  if (isRecord(a)) {
    if (!isRecord(b)) {
      return false;
    }
    const keys = Object.keys(a);
    if (keys.length !== Object.keys(b).length) {
      return false;
    }
    for (const key of keys) {
      if (!Object.hasOwn(b, key) || !deepEqual(a[key], b[key])) {
        return false;
      }
    }
    return true;
  }
  return a === b;
}

// Scratch view for float64 bit reinterpretation, allocated once so decompose stays allocation-free.
// It carries no state between calls: each decompose fully overwrites all eight bytes with
// setFloat64 before reading them back, and JS runs single-threaded so the two isMultipleOf calls
// never interleave.
const decomposeView = new DataView(new ArrayBuffer(8));

// Split a finite f64 into a signed integer mantissa and a base-2 exponent, so `mantissa * 2^exponent`
// reproduces the value exactly. Normal numbers carry the implicit leading 1 bit (bias 1023, 52 fraction
// bits → exponent - 1075); subnormals and zero use the fixed 2^-1074 quantum.
function decompose(value: number): { readonly mantissa: bigint; readonly exponent: number } {
  decomposeView.setFloat64(0, value);
  const bits = decomposeView.getBigUint64(0);
  const negative = (bits >> 63n) & 1n;
  const rawExponent = Number((bits >> 52n) & 0x7ffn);
  const rawMantissa = bits & 0xfffffffffffffn;
  if (rawExponent === 0) {
    return {
      mantissa: negative === 1n ? -rawMantissa : rawMantissa,
      exponent: -1074,
    };
  }
  const fullMantissa = rawMantissa | (1n << 52n);
  return {
    mantissa: negative === 1n ? -fullMantissa : fullMantissa,
    exponent: rawExponent - 1075,
  };
}

// Exact `value % divisor === 0` over the IEEE-754 value domain — never floating `%`, which would
// report false positives around binary-inexact decimals. Both operands become integer mantissa × 2^e,
// then the ratio's power of two is folded into whichever side keeps both operands whole BigInts.
// Divisor is contractually finite and > 0; value is any finite number.
export function isMultipleOf(value: number, divisor: number): boolean {
  const scaledValue = decompose(value);
  const scaledDivisor = decompose(divisor);
  let numerator = scaledValue.mantissa;
  let denominator = scaledDivisor.mantissa;
  const shift = scaledValue.exponent - scaledDivisor.exponent;
  if (shift >= 0) {
    numerator <<= BigInt(shift);
  } else {
    denominator <<= BigInt(-shift);
  }
  return numerator % denominator === 0n;
}

// Count Unicode code points: the string iterator yields whole code points, so an astral character
// like "𝒳" counts as 1 rather than its two UTF-16 code units.
export function codePointLength(s: string): number {
  const iterator = s[Symbol.iterator]();
  let count = 0;
  while (!iterator.next().done) {
    count += 1;
  }
  return count;
}

// Days per 1-indexed month; February is resolved against the leap-year rule at validation time.
const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

const DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/u;
const TIME_PATTERN = /^(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/u;
const DATE_TIME_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/u;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

function isValidDate(year: number, month: number, day: number): boolean {
  if (month < 1 || month > 12) {
    return false;
  }
  const maxDay = month === 2 && isLeapYear(year) ? 29 : DAYS_IN_MONTH[month - 1];
  return day >= 1 && day <= maxDay;
}

function isValidTime(hour: number, minute: number, second: number): boolean {
  // Second 60 is accepted for a positive leap second per RFC 3339.
  return hour <= 23 && minute <= 59 && second <= 60;
}

function isValidOffset(offset: string): boolean {
  if (offset === "Z" || offset === "z") {
    return true;
  }
  const offsetHour = Number(offset.slice(1, 3));
  const offsetMinute = Number(offset.slice(4, 6));
  return offsetHour <= 23 && offsetMinute <= 59;
}

// RFC 3339 date-time: real calendar date, `T`/`t` separator, full-time with a leap-second-aware
// second and a required `Z`/`z` or `±HH:MM` offset. Optional fractional seconds carry no constraint.
export function isDateTime(s: string): boolean {
  const match = DATE_TIME_PATTERN.exec(s);
  if (match === null) {
    return false;
  }
  return (
    isValidDate(Number(match[1]), Number(match[2]), Number(match[3])) &&
    isValidTime(Number(match[4]), Number(match[5]), Number(match[6])) &&
    isValidOffset(match[7])
  );
}

// RFC 3339 full-date on its own, enforcing real calendar validity (month, day, leap February).
export function isDate(s: string): boolean {
  const match = DATE_PATTERN.exec(s);
  if (match === null) {
    return false;
  }
  return isValidDate(Number(match[1]), Number(match[2]), Number(match[3]));
}

// RFC 3339 full-time on its own: partial-time plus a required offset, same second/leap/fraction rules.
export function isTime(s: string): boolean {
  const match = TIME_PATTERN.exec(s);
  if (match === null) {
    return false;
  }
  return (
    isValidTime(Number(match[1]), Number(match[2]), Number(match[3])) && isValidOffset(match[4])
  );
}

// 8-4-4-4-12 hexadecimal groups, any version/variant, case-insensitive — no `urn:` prefix or braces.
export function isUuid(s: string): boolean {
  return UUID_PATTERN.test(s);
}

// Whole number within the signed 32-bit range.
export function isInt32(v: number): boolean {
  return Number.isInteger(v) && v >= -2147483648 && v <= 2147483647;
}
