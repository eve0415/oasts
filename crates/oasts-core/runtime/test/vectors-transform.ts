/// <reference lib="esnext.temporal" preserve="true" />
// Frozen date/time transform vectors. NEVER regenerate these from implementation output — every
// expected value here is derived from the pinned transform contract, which fixes three modes:
//
//   dateTime: date      JavaScript `Date`. Accepted wire grammar: RFC 3339 date-time with a
//                       four-digit year; `T` or `t` separator; seconds 00-59 (leap-second `60`
//                       rejected); an optional fraction of one to THREE digits (four or more is
//                       rejected even when the extra digits are zeros, because accepting them
//                       would make decode lossy for some inputs and lossless for others with no
//                       way for a caller to tell which); and `Z`, `z`, or a numeric offset other
//                       than `-00:00` (which denotes an unknown local offset, not UTC).
//                       Encoding always emits canonical UTC `YYYY-MM-DDTHH:mm:ss.sssZ`, so a
//                       source offset is normalized, not preserved. Round-trip guarantee:
//                       instant identity, `decode(encode(d)).getTime() === d.getTime()`.
//   dateTime: temporal  `Temporal.Instant`. The same grammar with fractions of ONE TO NINE
//                       digits. Encoding emits canonical UTC with the minimal fractional digits
//                       needed. Round-trip guarantee: `decode(encode(i)).equals(i)`.
//   date: temporal      `Temporal.PlainDate`. Accepted wire grammar: RFC 3339 `full-date` with a
//                       four-digit year, decoded to an ISO-calendar `PlainDate`. Encoding is
//                       canonical `YYYY-MM-DD`. Round-trip guarantee: `decode(encode(d)).equals(d)`.
//
// A wire value that fails its grammar is `code: 'invalid-wire-value'`; an application value that
// cannot be represented on the wire is `code: 'invalid-application-value'`; a Temporal mode used
// where `globalThis.Temporal` is absent is `code: 'temporal-unavailable'`. All three carry the
// schema `sourcePointer` and the `applicationPath` of the offending value.
//
// `format: time` never appears here: RFC 3339 `full-time` carries a mandatory offset that neither
// `Date` nor `Temporal.PlainTime` can represent, so it is a wire and application string always.

/** A wire string the mode's grammar admits. Decoding it must not throw. */
export type WireAcceptVector = {
  readonly cite: string;
  readonly wire: string;
};

/**
 * A wire value the mode's grammar refuses. Decoding it must throw a `TransformError` with
 * `code: 'invalid-wire-value'`. `wire` is `unknown` because the non-string JSON values belong to
 * the same refusal set as the malformed strings.
 */
export type WireRejectVector = {
  readonly cite: string;
  readonly wire: unknown;
  readonly reason: string;
};

/** A wire string and the bytes re-encoding its decoded value must produce. */
export type CanonicalVector = {
  readonly cite: string;
  readonly wire: string;
  readonly canonical: string;
};

/**
 * An application value no wire string can represent. Encoding it must throw a `TransformError`
 * with `code: 'invalid-application-value'`. `build` is a thunk so the Temporal cases construct
 * nothing until a Temporal-capable run evaluates them.
 */
export type ApplicationRejectVector = {
  readonly cite: string;
  readonly mode: "dateTime-date" | "dateTime-temporal" | "date-temporal";
  readonly build: () => unknown;
  readonly reason: string;
};

/** One `direction` x `code` combination of the frozen `TransformError` shape. */
export type TransformErrorCase = {
  readonly direction: "request" | "response";
  readonly code: "temporal-unavailable" | "invalid-wire-value" | "invalid-application-value";
  readonly sourcePointer: { readonly logicalSourceId: string; readonly jsonPointer: string };
  readonly applicationPath: readonly (string | number)[];
  readonly cause: unknown;
};

// --- dateTime: date -------------------------------------------------------------------------

export const DATE_TIME_ACCEPTED: readonly WireAcceptVector[] = [
  { cite: "uppercase T separator, Z designator", wire: "2024-03-01T12:00:00Z" },
  { cite: "lowercase t separator and z designator", wire: "2024-03-01t12:00:00z" },
  { cite: "no fractional part", wire: "2024-03-01T12:00:00Z" },
  { cite: "one fractional digit", wire: "2024-03-01T12:00:00.1Z" },
  { cite: "two fractional digits", wire: "2024-03-01T12:00:00.12Z" },
  {
    cite: "three fractional digits, the Date resolution ceiling",
    wire: "2024-03-01T12:00:00.123Z",
  },
  { cite: "positive numeric offset", wire: "2024-03-01T12:00:00+09:00" },
  { cite: "negative numeric offset with minutes", wire: "2024-03-01T12:00:00-05:30" },
  { cite: "positive offset at the grammar extreme", wire: "2024-03-01T12:00:00+23:59" },
  { cite: "negative offset at the grammar extreme", wire: "2024-03-01T12:00:00-23:59" },
  { cite: "+00:00 is UTC and is admitted; only -00:00 is not", wire: "2024-03-01T12:00:00+00:00" },
  { cite: "year 0000, the low end of the four-digit range", wire: "0000-01-01T00:00:00Z" },
  { cite: "year 9999, the high end of the four-digit range", wire: "9999-12-31T23:59:59.999Z" },
  { cite: "leap day in a leap year", wire: "2024-02-29T00:00:00Z" },
  { cite: "second 59, the highest second the grammar admits", wire: "2024-03-01T12:00:59Z" },
];

export const DATE_TIME_REJECTED: readonly WireRejectVector[] = [
  {
    cite: "leap second",
    wire: "2024-03-01T12:00:60Z",
    reason: "second 60 is legal RFC 3339 but no Date or Instant can represent it",
  },
  {
    cite: "-00:00 offset",
    wire: "2024-03-01T12:00:00-00:00",
    reason: "-00:00 denotes an unknown local offset rather than UTC",
  },
  {
    cite: "four fractional digits",
    wire: "2024-03-01T12:00:00.1234Z",
    reason: "Date carries milliseconds, so a fourth digit would be discarded",
  },
  {
    cite: "four fractional digits that are all zeros",
    wire: "2024-03-01T12:00:00.0000Z",
    reason:
      "trailing zeros are still rejected: accepting them would make decode lossy for some inputs and lossless for others",
  },
  {
    cite: "missing offset",
    wire: "2024-03-01T12:00:00",
    reason: "RFC 3339 full-time carries a mandatory offset",
  },
  {
    cite: "two-digit year",
    wire: "24-03-01T12:00:00Z",
    reason: "the grammar fixes a four-digit year",
  },
  {
    cite: "expanded year",
    wire: "+002024-03-01T12:00:00Z",
    reason: "the grammar fixes a four-digit year with no sign",
  },
  {
    cite: "day out of range for the month",
    wire: "2024-02-30T00:00:00Z",
    reason: "February never has 30 days",
  },
  {
    cite: "day out of range in a non-leap year",
    wire: "2023-02-29T00:00:00Z",
    reason: "2023 is not a leap year",
  },
  { cite: "month 13", wire: "2024-13-01T00:00:00Z", reason: "months are 01-12" },
  { cite: "month 00", wire: "2024-00-01T00:00:00Z", reason: "months are 01-12" },
  { cite: "day 00", wire: "2024-03-00T00:00:00Z", reason: "days are 01-31" },
  { cite: "hour 24", wire: "2024-03-01T24:00:00Z", reason: "hours are 00-23" },
  { cite: "minute 60", wire: "2024-03-01T12:60:00Z", reason: "minutes are 00-59" },
  { cite: "offset hour 24", wire: "2024-03-01T12:00:00+24:00", reason: "offset hours are 00-23" },
  {
    cite: "offset minute 60",
    wire: "2024-03-01T12:00:00+09:60",
    reason: "offset minutes are 00-59",
  },
  { cite: "space separator", wire: "2024-03-01 12:00:00Z", reason: "the separator is T or t" },
  { cite: "seconds omitted", wire: "2024-03-01T12:00Z", reason: "seconds are mandatory" },
  {
    cite: "empty fractional part",
    wire: "2024-03-01T12:00:00.Z",
    reason: "a fraction needs at least one digit",
  },
  { cite: "date only", wire: "2024-03-01", reason: "date-time requires a time" },
  { cite: "empty string", wire: "", reason: "no grammar admits it" },
  {
    cite: "trailing whitespace",
    wire: "2024-03-01T12:00:00Z ",
    reason: "the grammar admits no surrounding whitespace",
  },
  { cite: "non-string JSON null", wire: null, reason: "the wire value must be a string" },
  { cite: "non-string JSON number", wire: 42, reason: "the wire value must be a string" },
  { cite: "non-string JSON object", wire: {}, reason: "the wire value must be a string" },
  { cite: "non-string JSON array", wire: [], reason: "the wire value must be a string" },
  { cite: "non-string JSON boolean", wire: true, reason: "the wire value must be a string" },
  { cite: "undefined", wire: undefined, reason: "the wire value must be a string" },
];

export const CANONICAL_DATE_TIME: readonly CanonicalVector[] = [
  {
    cite: "a positive offset is normalized to UTC, never preserved",
    wire: "2024-03-01T12:00:00+09:00",
    canonical: "2024-03-01T03:00:00.000Z",
  },
  {
    cite: "a negative offset is normalized to UTC",
    wire: "2024-03-01T00:00:00-05:30",
    canonical: "2024-03-01T05:30:00.000Z",
  },
  {
    cite: "an absent fraction encodes as .000",
    wire: "2024-03-01T12:00:00Z",
    canonical: "2024-03-01T12:00:00.000Z",
  },
  {
    cite: "lowercase separator and designator canonicalize to uppercase",
    wire: "2024-03-01t12:00:00z",
    canonical: "2024-03-01T12:00:00.000Z",
  },
  {
    cite: "one fractional digit is tenths, not milliseconds",
    wire: "2024-03-01T12:00:00.5Z",
    canonical: "2024-03-01T12:00:00.500Z",
  },
  {
    cite: "two fractional digits are hundredths",
    wire: "2024-03-01T12:00:00.05Z",
    canonical: "2024-03-01T12:00:00.050Z",
  },
  {
    cite: "three fractional digits pass through",
    wire: "2024-03-01T12:00:00.123Z",
    canonical: "2024-03-01T12:00:00.123Z",
  },
  {
    cite: "+00:00 canonicalizes to Z",
    wire: "2024-03-01T12:00:00+00:00",
    canonical: "2024-03-01T12:00:00.000Z",
  },
  {
    cite: "year 0000 keeps its four digits and gains no sign",
    wire: "0000-01-01T00:00:00Z",
    canonical: "0000-01-01T00:00:00.000Z",
  },
  {
    cite: "year 9999 at the top of the range",
    wire: "9999-12-31T23:59:59.999Z",
    canonical: "9999-12-31T23:59:59.999Z",
  },
  {
    cite: "an offset that crosses a day boundary moves the date too",
    wire: "2024-03-01T01:00:00+09:00",
    canonical: "2024-02-29T16:00:00.000Z",
  },
];

// --- dateTime: temporal ---------------------------------------------------------------------

export const DATE_TIME_NANO_ACCEPTED: readonly WireAcceptVector[] = [
  ...DATE_TIME_ACCEPTED,
  {
    cite: "four fractional digits, beyond Date but within Instant",
    wire: "2024-03-01T12:00:00.1234Z",
  },
  { cite: "six fractional digits, microseconds", wire: "2024-03-01T12:00:00.123456Z" },
  {
    cite: "nine fractional digits, the nanosecond ceiling",
    wire: "2024-03-01T12:00:00.123456789Z",
  },
  {
    cite: "nine fractional zeros are still nine legal digits",
    wire: "2024-03-01T12:00:00.000000000Z",
  },
];

export const DATE_TIME_NANO_REJECTED: readonly WireRejectVector[] = [
  // Every grammar refusal above holds identically for Instant except the fraction-width rule,
  // which widens from three digits to nine. The four-digit cases are therefore dropped here.
  ...DATE_TIME_REJECTED.filter(
    (vector) =>
      vector.wire !== "2024-03-01T12:00:00.1234Z" && vector.wire !== "2024-03-01T12:00:00.0000Z",
  ),
  {
    cite: "ten fractional digits",
    wire: "2024-03-01T12:00:00.1234567891Z",
    reason: "Instant carries nanoseconds, so a tenth digit would be discarded",
  },
  {
    cite: "ten fractional digits that are all zeros",
    wire: "2024-03-01T12:00:00.0000000000Z",
    reason:
      "trailing zeros past nanosecond resolution are rejected on the same lossiness grounds as Date's fourth digit",
  },
];

export const CANONICAL_INSTANT: readonly CanonicalVector[] = [
  {
    cite: "a whole second encodes with no fractional part at all",
    wire: "2024-03-01T12:00:00Z",
    canonical: "2024-03-01T12:00:00Z",
  },
  {
    cite: "an all-zero fraction is dropped, not preserved",
    wire: "2024-03-01T12:00:00.000Z",
    canonical: "2024-03-01T12:00:00Z",
  },
  {
    cite: "tenths encode as one digit, the minimal width",
    wire: "2024-03-01T12:00:00.1Z",
    canonical: "2024-03-01T12:00:00.1Z",
  },
  {
    cite: "milliseconds encode as three digits",
    wire: "2024-03-01T12:00:00.123Z",
    canonical: "2024-03-01T12:00:00.123Z",
  },
  {
    cite: "microseconds keep their leading zeros because they are significant",
    wire: "2024-03-01T12:00:00.000123Z",
    canonical: "2024-03-01T12:00:00.000123Z",
  },
  {
    cite: "nanoseconds encode as nine digits",
    wire: "2024-03-01T12:00:00.123456789Z",
    canonical: "2024-03-01T12:00:00.123456789Z",
  },
  {
    cite: "a trailing zero inside a nanosecond value is trimmed",
    wire: "2024-03-01T12:00:00.123456780Z",
    canonical: "2024-03-01T12:00:00.12345678Z",
  },
  {
    cite: "an offset is normalized because an Instant is offset-free",
    wire: "2024-03-01T12:00:00+09:00",
    canonical: "2024-03-01T03:00:00Z",
  },
  {
    cite: "lowercase separator and designator canonicalize to uppercase",
    wire: "2024-03-01t12:00:00z",
    canonical: "2024-03-01T12:00:00Z",
  },
  {
    cite: "year 0000 keeps its four digits",
    wire: "0000-01-01T00:00:00Z",
    canonical: "0000-01-01T00:00:00Z",
  },
  {
    cite: "the top of the four-digit year range at nanosecond resolution",
    wire: "9999-12-31T23:59:59.999999999Z",
    canonical: "9999-12-31T23:59:59.999999999Z",
  },
];

// --- date: temporal -------------------------------------------------------------------------

export const DATE_ACCEPTED: readonly WireAcceptVector[] = [
  { cite: "an ordinary full-date", wire: "2024-03-01" },
  { cite: "year 0000, the low end of the four-digit range", wire: "0000-01-01" },
  { cite: "year 9999, the high end of the four-digit range", wire: "9999-12-31" },
  { cite: "leap day in a leap year", wire: "2024-02-29" },
  { cite: "a century leap year", wire: "2000-02-29" },
  { cite: "the last day of a 31-day month", wire: "2024-01-31" },
];

export const DATE_REJECTED: readonly WireRejectVector[] = [
  {
    cite: "a date-time where a full-date is required",
    wire: "2024-03-01T00:00:00Z",
    reason: "format: date admits no time part",
  },
  {
    cite: "a full-date with a trailing separator",
    wire: "2024-03-01T",
    reason: "format: date admits no time part",
  },
  {
    cite: "day out of range for the month",
    wire: "2024-02-30",
    reason: "February never has 30 days",
  },
  {
    cite: "day out of range in a non-leap year",
    wire: "2023-02-29",
    reason: "2023 is not a leap year",
  },
  {
    cite: "day 31 in a 30-day month",
    wire: "2024-04-31",
    reason: "April has 30 days",
  },
  {
    cite: "a century year that is not a leap year",
    wire: "1900-02-29",
    reason: "1900 is divisible by 100 but not 400",
  },
  {
    cite: "unpadded month and day",
    wire: "2024-3-1",
    reason: "full-date fixes two-digit month and day",
  },
  { cite: "two-digit year", wire: "24-03-01", reason: "full-date fixes a four-digit year" },
  {
    cite: "expanded year",
    wire: "+002024-03-01",
    reason: "full-date fixes a four-digit year with no sign",
  },
  { cite: "month 13", wire: "2024-13-01", reason: "months are 01-12" },
  { cite: "month 00", wire: "2024-00-10", reason: "months are 01-12" },
  { cite: "day 00", wire: "2024-01-00", reason: "days are 01-31" },
  { cite: "slash separators", wire: "2024/03/01", reason: "full-date separates with hyphens" },
  {
    cite: "a calendar annotation",
    wire: "2024-03-01[u-ca=hebrew]",
    reason: "the wire form is a bare full-date",
  },
  { cite: "empty string", wire: "", reason: "no grammar admits it" },
  {
    cite: "trailing whitespace",
    wire: "2024-03-01 ",
    reason: "the grammar admits no surrounding whitespace",
  },
  { cite: "non-string JSON null", wire: null, reason: "the wire value must be a string" },
  { cite: "non-string JSON number", wire: 20240301, reason: "the wire value must be a string" },
  { cite: "non-string JSON object", wire: {}, reason: "the wire value must be a string" },
  { cite: "non-string JSON array", wire: [], reason: "the wire value must be a string" },
  { cite: "non-string JSON boolean", wire: false, reason: "the wire value must be a string" },
  { cite: "undefined", wire: undefined, reason: "the wire value must be a string" },
];

export const CANONICAL_PLAIN_DATE: readonly CanonicalVector[] = [
  { cite: "a full-date encodes to itself", wire: "2024-03-01", canonical: "2024-03-01" },
  {
    cite: "year 0000 keeps its four digits and gains no sign",
    wire: "0000-01-01",
    canonical: "0000-01-01",
  },
  { cite: "year 9999 at the top of the range", wire: "9999-12-31", canonical: "9999-12-31" },
  { cite: "a leap day round-trips", wire: "2024-02-29", canonical: "2024-02-29" },
];

// --- application values no wire string can carry ---------------------------------------------

export const REQUEST_REJECTED_VALUES: readonly ApplicationRejectVector[] = [
  {
    cite: "an invalid Date",
    mode: "dateTime-date",
    build: () => new Date(NaN),
    reason: "a Date holding NaN has no instant to encode",
  },
  {
    cite: "a Date one millisecond past year 9999",
    mode: "dateTime-date",
    build: () => new Date(253402300800000),
    reason: "UTC year 10000 needs an expanded year the wire grammar does not admit",
  },
  {
    cite: "a Date one millisecond before year 0000",
    mode: "dateTime-date",
    build: () => new Date(-62167219200001),
    reason: "UTC year -0001 needs a sign the wire grammar does not admit",
  },
  {
    cite: "a value that is not a Date at all",
    mode: "dateTime-date",
    build: () => "2024-03-01T12:00:00.000Z",
    reason: "the application value must be a Date",
  },
  {
    cite: "an Instant past year 9999",
    mode: "dateTime-temporal",
    build: () => Temporal.Instant.fromEpochMilliseconds(253402300800000),
    reason: "epoch year 10000 needs an expanded year the wire grammar does not admit",
  },
  {
    cite: "a value that is not an Instant at all",
    mode: "dateTime-temporal",
    build: () => "2024-03-01T12:00:00Z",
    reason: "the application value must be a Temporal.Instant",
  },
  {
    cite: "a non-ISO-calendar PlainDate",
    mode: "date-temporal",
    build: () => Temporal.PlainDate.from("2024-02-29").withCalendar("hebrew"),
    reason:
      "a non-ISO calendar cannot be preserved by full-date, and silently dropping it would be lossy",
  },
  {
    cite: "a PlainDate past year 9999",
    mode: "date-temporal",
    build: () => Temporal.PlainDate.from("+010000-01-01"),
    reason: "year 10000 needs an expanded year the wire grammar does not admit",
  },
  {
    cite: "a value that is not a PlainDate at all",
    mode: "date-temporal",
    build: () => "2024-03-01",
    reason: "the application value must be a Temporal.PlainDate",
  },
];

// --- the frozen TransformError surface --------------------------------------------------------

export const TRANSFORM_ERROR_CASES: readonly TransformErrorCase[] = [
  {
    direction: "request",
    code: "invalid-application-value",
    sourcePointer: {
      logicalSourceId: "workspace/openapi.yaml",
      jsonPointer: "/components/schemas/Pet/properties/bornAt",
    },
    applicationPath: ["body", "bornAt"],
    cause: new RangeError("Invalid time value"),
  },
  {
    direction: "request",
    code: "invalid-wire-value",
    sourcePointer: {
      logicalSourceId: "workspace/openapi.yaml",
      jsonPointer: "/paths/~1pets/get/parameters/0/schema",
    },
    applicationPath: ["query", "since"],
    cause: "2024-03-01T12:00:60Z",
  },
  {
    direction: "request",
    code: "temporal-unavailable",
    sourcePointer: {
      logicalSourceId: "workspace/openapi.yaml",
      jsonPointer: "/components/schemas/Pet/properties/bornOn",
    },
    applicationPath: [],
    cause: undefined,
  },
  {
    direction: "response",
    code: "invalid-wire-value",
    sourcePointer: {
      logicalSourceId: "workspace/openapi.yaml",
      jsonPointer: "/components/schemas/Pet/properties/bornAt",
    },
    applicationPath: ["pets", 0, "bornAt"],
    cause: "not a date",
  },
  {
    direction: "response",
    code: "invalid-application-value",
    sourcePointer: {
      logicalSourceId: "remote/shared.yaml",
      jsonPointer: "/components/schemas/Event/properties/at",
    },
    applicationPath: ["items", 3, "at"],
    cause: new TypeError("unrepresentable"),
  },
  {
    direction: "response",
    code: "temporal-unavailable",
    sourcePointer: {
      logicalSourceId: "workspace/openapi.yaml",
      jsonPointer: "/components/schemas/Event/properties/on",
    },
    applicationPath: ["on"],
    cause: undefined,
  },
];
