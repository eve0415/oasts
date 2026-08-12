// Hand-written check kernel, emitted verbatim as zod/runtime.ts. Every export is part of the
// generated-zod ABI: the Rust emitter compiles call sites against these exact signatures, so the
// surface is fixed and additive-only. All helpers are pure and side-effect-free at import time.
//
// Why this file exists at all, when zod ships `.min()`, `.multipleOf()`, `z.iso.datetime()` and
// friends: the zod artifact and the generated-validators artifact must return identical verdicts on
// the shared capability matrix, and zod's natives differ from this compiler's frozen
// contract on several rows. Measured against zod 4.4.3:
//
//   - `.min()`/`.max()` on strings count UTF-16 code units, so a single astral code point measures
//     2. The contract counts code points.
//   - `.multipleOf(0.1)` accepts 0.3 — it compares against a relative epsilon. The contract is exact
//     over IEEE-754, so 0.3 is not a multiple of 0.1.
//   - `.int()` rejects 1e300 and 2**53 as out of range. The contract's integer domain is any finite
//     number for which `Number.isInteger` holds.
//   - `z.iso.datetime()` rejects a numeric offset by default and rejects lowercase `t`/`z`, while
//     accepting a value with no seconds. The contract is RFC 3339 with a required offset.
//
// So every semantically load-bearing predicate is spelled here, mirroring `validators-runtime.ts`
// exactly. Zod's own checks are used only where the semantics coincide with the contract: the
// number domain (`z.number()` already rejects NaN and both infinities), numeric bounds, and array
// element counts.
//
// The predicate block below is duplicated from `validators-runtime.ts` rather than imported,
// because the two artifacts are independently consumable and neither may require the
// other's directory to exist. `zod_and_validators_runtimes_share_their_predicates` pins the two
// copies identical so they cannot drift.
//
// Every issue is pushed with `continue: true`. Zod aborts the remaining custom checks on a node as
// soon as one pushes without it, which would make the emitted schemas fail-fast; the contract is
// collect-all, so each check reports everything it finds and lets its siblings run.

import type { z } from "zod";

export type Check<T> = (payload: z.core.ParsePayload<T>) => void;

type Path = readonly (string | number)[];

type Parsed = {
  readonly success: boolean;
  readonly error?: { readonly issues: readonly z.core.$ZodIssue[] };
};

type Schema = { safeParse(value: unknown): Parsed };

// --- the client-binding surface ----------------------------------------------------------------

/// One validation failure at a location, in the shape the generated client's result variants carry.
export type Issue = {
  readonly message: string;
  readonly path: readonly (string | number)[];
};

/// Runs a schema for its verdict alone, appending each failure to `issues` under `base`.
///
/// The parsed value is deliberately discarded: the client forwards the value it already decoded, so
/// what reaches the caller never depends on which engine is bound and zod's object reconstruction
/// stays invisible at the client seam. This is the entry point the emitted `validate*` wrappers call,
/// so a generated client's call sites are identical under either engine.
export function collect(schema: Schema, value: unknown, base: Path, issues: Issue[]): void {
  const parsed = schema.safeParse(value);
  if (parsed.success || parsed.error === undefined) {
    return;
  }
  for (const issue of parsed.error.issues) {
    // Zod types a path segment as PropertyKey, so it admits a symbol. Decoded wire values are JSON
    // and carry no symbol keys, but the path is kept total rather than narrowed by assertion.
    const path: (string | number)[] = [...base];
    for (const segment of issue.path) {
      path.push(typeof segment === "symbol" ? segment.toString() : segment);
    }
    issues.push({ message: issue.message, path });
  }
}

// Records one failure. `path` is relative to the node the check is attached to; zod appends it to
// the node's own position, so a check on a property pushes `[]` to land on that property.
function report(payload: z.core.ParsePayload, message: string, path: Path = []): void {
  payload.issues.push({
    code: "custom",
    message,
    input: payload.value,
    path: [...path],
    continue: true,
  });
}

// Forwards a subschema's issues onto the parent, rebased under `prefix`. Used by every applicator
// that runs a schema itself rather than letting zod compose it.
function relay(payload: z.core.ParsePayload, parsed: Parsed, prefix: Path = []): void {
  if (parsed.success || parsed.error === undefined) {
    return;
  }
  for (const issue of parsed.error.issues) {
    payload.issues.push({
      code: "custom",
      message: issue.message,
      input: payload.value,
      path: [...prefix, ...issue.path],
      continue: true,
    });
  }
}

function matches(schema: Schema, value: unknown): boolean {
  return schema.safeParse(value).success;
}

// --- shared predicates (mirrored from validators-runtime.ts) -------------------------------------

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
const decomposeView = new DataView(new ArrayBuffer(8));

// Split a finite f64 into a signed integer mantissa and a base-2 exponent, so `mantissa * 2^exponent`
// reproduces the value exactly.
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

// Exact `value % divisor === 0` over the IEEE-754 value domain — never floating `%`.
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

// Count Unicode code points, so an astral character counts as 1 rather than its two UTF-16 units.
export function codePointLength(s: string): number {
  const iterator = s[Symbol.iterator]();
  let count = 0;
  while (!iterator.next().done) {
    count += 1;
  }
  return count;
}

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
  // The table lookup is the month range check: anything outside 1..12 indexes past the table.
  const daysInMonth = DAYS_IN_MONTH[month - 1];
  if (daysInMonth === undefined) {
    return false;
  }
  const maxDay = month === 2 && isLeapYear(year) ? 29 : daysInMonth;
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
  const offset = match[7];
  return (
    offset !== undefined &&
    isValidDate(Number(match[1]), Number(match[2]), Number(match[3])) &&
    isValidTime(Number(match[4]), Number(match[5]), Number(match[6])) &&
    isValidOffset(offset)
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
  const offset = match[4];
  return (
    offset !== undefined &&
    isValidTime(Number(match[1]), Number(match[2]), Number(match[3])) &&
    isValidOffset(offset)
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

// Whole number within JavaScript's safe-integer range.
export function isInt64(v: number): boolean {
  return Number.isSafeInteger(v);
}

const INT64_WIRE_INTEGER = /^-?(?:0|[1-9]\d*)$/;

export function int64WireValue(value: unknown): bigint | null {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return BigInt(value);
  }
  if (
    isRecord(value) &&
    typeof value.rawJSON === "string" &&
    INT64_WIRE_INTEGER.test(value.rawJSON)
  ) {
    return BigInt(value.rawJSON);
  }
  return null;
}

// --- scalar checks -------------------------------------------------------------------------------

// The contract's integer domain: any finite number that is a whole number. Wider than zod's
// `.int()`, which caps at the safe-integer range.
export function integer(): Check<number> {
  return (payload) => {
    if (!Number.isInteger(payload.value)) {
      report(payload, "expected type integer");
    }
  };
}

export function minLength(n: number): Check<string> {
  return (payload) => {
    if (codePointLength(payload.value) < n) {
      report(payload, `shorter than minLength ${n}`);
    }
  };
}

export function maxLength(n: number): Check<string> {
  return (payload) => {
    if (codePointLength(payload.value) > n) {
      report(payload, `longer than maxLength ${n}`);
    }
  };
}

export function pattern(re: RegExp): Check<string> {
  return (payload) => {
    // A shared RegExp is never global here, so `test` carries no lastIndex state between calls.
    if (!re.test(payload.value)) {
      report(payload, "does not match pattern");
    }
  };
}

export function multipleOf(divisor: number): Check<number> {
  return (payload) => {
    if (!isMultipleOf(payload.value, divisor)) {
      report(payload, `not a multiple of ${divisor}`);
    }
  };
}

export function stringFormat(predicate: (s: string) => boolean, name: string): Check<string> {
  return (payload) => {
    if (!predicate(payload.value)) {
      report(payload, `invalid ${name} format`);
    }
  };
}

export function int32(): Check<number> {
  return (payload) => {
    if (!isInt32(payload.value)) {
      report(payload, "out of int32 range");
    }
  };
}

export function int64(): Check<number> {
  return (payload) => {
    if (!isInt64(payload.value)) {
      report(payload, "out of int64 range");
    }
  };
}

export function int64Wire(schema?: Schema): Check<unknown> {
  return (payload) => {
    const normalized = int64WireValue(payload.value);
    if (normalized === null) {
      report(payload, "expected type integer");
    } else if (schema !== undefined) {
      relay(payload, schema.safeParse(Number(normalized)));
    }
  };
}

// `enum` and `const` compare by deep JSON equality, so `{a:1,b:2}` matches `{b:2,a:1}`.
export function enumValues(values: readonly unknown[]): Check<unknown> {
  return (payload) => {
    if (!values.some((candidate) => deepEqual(candidate, payload.value))) {
      report(payload, "value not in enum");
    }
  };
}

export function constValue(value: unknown): Check<unknown> {
  return (payload) => {
    if (!deepEqual(value, payload.value)) {
      report(payload, "value not equal to const");
    }
  };
}

// --- array checks --------------------------------------------------------------------------------

export function uniqueItems(): Check<readonly unknown[]> {
  return (payload) => {
    const items = payload.value;
    for (let i = 0; i < items.length; i += 1) {
      for (let j = i + 1; j < items.length; j += 1) {
        if (deepEqual(items[i], items[j])) {
          report(payload, "items not unique");
          return;
        }
      }
    }
  };
}

// `contains` counts every match rather than short-circuiting, because `maxContains` needs the total.
// An absent `min` means the keyword declared `minContains: 0`, which asserts no lower bound.
export function contains(
  schema: Schema,
  min: number | undefined,
  max: number | undefined,
  minWasExplicit: boolean,
): Check<readonly unknown[]> {
  return (payload) => {
    let matched = 0;
    for (const item of payload.value) {
      if (matches(schema, item)) {
        matched += 1;
      }
    }
    if (min !== undefined && matched < min) {
      report(
        payload,
        minWasExplicit
          ? `fewer matching items than minContains ${min}`
          : "no array item matches contains schema",
      );
    }
    if (max !== undefined && matched > max) {
      report(payload, `more matching items than maxContains ${max}`);
    }
  };
}

// --- object checks -------------------------------------------------------------------------------

export function propertyCount(
  min: number | undefined,
  max: number | undefined,
): Check<Record<string, unknown>> {
  return (payload) => {
    const count = Object.keys(payload.value).length;
    if (min !== undefined && count < min) {
      report(payload, `fewer properties than minProperties ${min}`);
    }
    if (max !== undefined && count > max) {
      report(payload, `more properties than maxProperties ${max}`);
    }
  };
}

// Presence is own-key presence, so a present-but-undefined property counts as present.
export function dependentRequired(
  dependencies: readonly (readonly [string, readonly string[]])[],
): Check<Record<string, unknown>> {
  return (payload) => {
    const value = payload.value;
    for (const [trigger, required] of dependencies) {
      if (!Object.hasOwn(value, trigger)) {
        continue;
      }
      for (const name of required) {
        if (!Object.hasOwn(value, name)) {
          report(payload, `missing required property ${name}`);
        }
      }
    }
  };
}

export function dependentSchemas(
  dependencies: readonly (readonly [string, Schema])[],
): Check<Record<string, unknown>> {
  return (payload) => {
    for (const [trigger, schema] of dependencies) {
      if (Object.hasOwn(payload.value, trigger)) {
        relay(payload, schema.safeParse(payload.value));
      }
    }
  };
}

export function propertyNames(schema: Schema): Check<Record<string, unknown>> {
  return (payload) => {
    for (const key of Object.keys(payload.value)) {
      if (!matches(schema, key)) {
        report(payload, "property name does not satisfy propertyNames schema", [key]);
      }
    }
  };
}

// `patternProperties` cannot ride on `z.strictObject`: a strict object has no knowledge of the
// patterns and would reject a legitimately matched key. The residue check therefore lives here,
// where the evaluated-key set is known. `additional` is `false` to forbid the residue, a schema to
// validate it, or `undefined` to permit it.
export function patternProperties(
  patterns: readonly (readonly [RegExp, Schema])[],
  declared: readonly string[],
  additional: Schema | false | undefined,
): Check<Record<string, unknown>> {
  return (payload) => {
    const value = payload.value;
    for (const key of Object.keys(value)) {
      let evaluated = declared.includes(key);
      for (const [re, schema] of patterns) {
        if (!re.test(key)) {
          continue;
        }
        evaluated = true;
        relay(payload, schema.safeParse(value[key]), [key]);
      }
      if (evaluated) {
        continue;
      }
      if (additional === false) {
        report(payload, "unexpected property", [key]);
      } else if (additional !== undefined) {
        relay(payload, additional.safeParse(value[key]), [key]);
      }
    }
  };
}

// The `if` verdict is private: its issues never surface, only the selected branch's do.
export function conditional(
  condition: Schema,
  then: Schema | undefined,
  otherwise: Schema | undefined,
): Check<unknown> {
  return (payload) => {
    const branch = matches(condition, payload.value) ? then : otherwise;
    if (branch !== undefined) {
      relay(payload, branch.safeParse(payload.value));
    }
  };
}

// `not` is attached to an untyped base, because a typed base would reject on a type mismatch that
// `not` is thereby satisfied by.
export function not(schema: Schema): Check<unknown> {
  return (payload) => {
    if (matches(schema, payload.value)) {
      report(payload, "value matches not schema");
    }
  };
}

// `oneOf` means exactly one branch matches. Zod's union is `anyOf`, so the count is asserted here.
export function oneOf(branches: readonly Schema[]): Check<unknown> {
  return (payload) => {
    let matched = 0;
    for (const branch of branches) {
      if (matches(branch, payload.value)) {
        matched += 1;
      }
    }
    if (matched !== 1) {
      report(payload, "expected exactly one oneOf branch to match");
    }
  };
}

// --- response headers ------------------------------------------------------------------------

/// One declared response header. `schema` is absent for an opaque content header, whose wire value
/// is always a string and therefore carries no schema check at all — only, when required, a presence
/// check. `json` marks a JSON-family content header, whose value is JSON text on the wire and so is
/// parsed before the schema sees it.
export type HeaderCheck = {
  readonly name: string;
  readonly required: boolean;
  readonly schema?: Schema;
  readonly json?: boolean;
};

/// Validates a `Headers`-like object against the declared headers.
///
/// A response's headers reach validation as the platform `Headers` object the client already holds,
/// not as a plain record, so the value is read through `get(name)` rather than by property access —
/// a plain object schema would reject a `Headers` instance outright. A schema-style header value
/// arrives as a wire string and is checked as one, so a non-string schema domain over-reports by
/// design; that is the same bargain the dependency-free engine strikes, and the two must agree.
export function headers<T>(checks: readonly HeaderCheck[]): Check<T> {
  return (payload) => {
    const value: unknown = payload.value;
    if (
      typeof value !== "object" ||
      value === null ||
      !("get" in value) ||
      typeof value.get !== "function"
    ) {
      report(payload, "value is not a Headers object");
      return;
    }
    const read = value.get;
    for (const check of checks) {
      if (check.schema === undefined && !check.required) {
        continue;
      }
      const raw: unknown = read.call(value, check.name);
      if (check.required && raw === null) {
        report(payload, `missing required header ${check.name}`);
      }
      if (check.schema === undefined || raw === null || typeof raw !== "string") {
        continue;
      }
      if (check.json !== true) {
        relay(payload, check.schema.safeParse(raw), [check.name]);
        continue;
      }
      let decoded: unknown;
      try {
        decoded = JSON.parse(raw);
      } catch {
        report(payload, "value is not valid JSON", [check.name]);
        continue;
      }
      relay(payload, check.schema.safeParse(decoded), [check.name]);
    }
  };
}

// --- unevaluated applicators ---------------------------------------------------------------------

// A node of the static applicator tree the emitter builds for `unevaluatedProperties`. Zod exposes
// no way to observe which union branch succeeded, so the evaluated-key set is recomputed here by
// re-running the branch schemas — the same successful-branch-only rule, reached differently.
export type PropertyScope = {
  readonly declared?: readonly string[];
  readonly patterns?: readonly RegExp[];
  readonly additional?: boolean;
  readonly allOf?: readonly PropertyScope[];
  readonly branches?: readonly (readonly [Schema, PropertyScope])[];
  readonly conditional?: {
    readonly condition: Schema;
    readonly whenTrue?: PropertyScope;
    readonly whenFalse?: PropertyScope;
  };
};

function collectProperties(
  scope: PropertyScope,
  value: Record<string, unknown>,
  out: Set<string>,
): void {
  for (const name of scope.declared ?? []) {
    if (Object.hasOwn(value, name)) {
      out.add(name);
    }
  }
  for (const re of scope.patterns ?? []) {
    for (const key of Object.keys(value)) {
      if (re.test(key)) {
        out.add(key);
      }
    }
  }
  if (scope.additional === true) {
    for (const key of Object.keys(value)) {
      out.add(key);
    }
  }
  // allOf branches all apply, so they contribute unconditionally.
  for (const nested of scope.allOf ?? []) {
    collectProperties(nested, value, out);
  }
  // anyOf/oneOf branches contribute only when they match.
  for (const [schema, nested] of scope.branches ?? []) {
    if (matches(schema, value)) {
      collectProperties(nested, value, out);
    }
  }
  const conditionalScope = scope.conditional;
  if (conditionalScope !== undefined) {
    if (matches(conditionalScope.condition, value)) {
      if (conditionalScope.whenTrue !== undefined) {
        collectProperties(conditionalScope.whenTrue, value, out);
      }
    } else if (conditionalScope.whenFalse !== undefined) {
      collectProperties(conditionalScope.whenFalse, value, out);
    }
  }
}

// `allowed` is `false` for `unevaluatedProperties: false`, or a schema every unevaluated property
// must satisfy.
export function unevaluatedProperties(
  scope: PropertyScope,
  allowed: Schema | false,
): Check<Record<string, unknown>> {
  return (payload) => {
    const value = payload.value;
    const evaluated = new Set<string>();
    collectProperties(scope, value, evaluated);
    for (const key of Object.keys(value)) {
      if (evaluated.has(key)) {
        continue;
      }
      if (allowed === false) {
        report(payload, "value not allowed", [key]);
      } else {
        relay(payload, allowed.safeParse(value[key]), [key]);
      }
    }
  };
}

// The array twin. `prefixCount` is how many leading indexes `prefixItems` covers, `itemsCovers`
// records whether an `items` schema evaluated the rest, and each `contains` schema evaluates the
// indexes it matches.
export type ItemScope = {
  readonly prefixCount?: number;
  readonly itemsCovers?: boolean;
  readonly contains?: readonly Schema[];
};

export function unevaluatedItems(
  scope: ItemScope,
  allowed: Schema | false,
): Check<readonly unknown[]> {
  return (payload) => {
    const items = payload.value;
    const evaluated = new Set<number>();
    const prefixCount = Math.min(items.length, scope.prefixCount ?? 0);
    for (let index = 0; index < prefixCount; index += 1) {
      evaluated.add(index);
    }
    if (scope.itemsCovers === true) {
      for (let index = 0; index < items.length; index += 1) {
        evaluated.add(index);
      }
    }
    for (const schema of scope.contains ?? []) {
      for (let index = 0; index < items.length; index += 1) {
        if (matches(schema, items[index])) {
          evaluated.add(index);
        }
      }
    }
    for (let index = 0; index < items.length; index += 1) {
      if (evaluated.has(index)) {
        continue;
      }
      if (allowed === false) {
        report(payload, "value not allowed", [index]);
      } else {
        relay(payload, allowed.safeParse(items[index]), [index]);
      }
    }
  };
}
