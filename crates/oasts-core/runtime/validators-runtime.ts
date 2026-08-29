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

export function hasGet(value: unknown): value is { get(name: string): string | null } {
  return (
    typeof value === "object" && value !== null && "get" in value && typeof value.get === "function"
  );
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

// Exact comparison between an integer and the binary64 rational represented by `other`.
export function compareBigIntToNumber(value: bigint, other: number): number {
  const scaled = decompose(other);
  let scaledInteger = value;
  let rational = scaled.mantissa;
  if (scaled.exponent >= 0) {
    rational <<= BigInt(scaled.exponent);
  } else {
    scaledInteger <<= BigInt(-scaled.exponent);
  }
  return scaledInteger < rational ? -1 : scaledInteger > rational ? 1 : 0;
}

// Exact divisibility by the binary64 rational represented by `divisor`. A fractional divisor is
// valid: the quotient must be an integer under the divisor's exact binary64 value.
export function isBigIntMultipleOf(value: bigint, divisor: number): boolean {
  const scaled = decompose(divisor);
  if (scaled.mantissa === 0n) {
    return false;
  }
  return scaled.exponent >= 0
    ? value % (scaled.mantissa << BigInt(scaled.exponent)) === 0n
    : (value << BigInt(-scaled.exponent)) % scaled.mantissa === 0n;
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

const IPV4_OCTET = /^(?:0|[1-9][0-9]{0,2})$/u;

// RFC 2673 §3.2 dotted-quad: exactly four decimal octets in 0..255, each written without a leading
// zero. The four `IPV4_OCTET` tests are anchored single-quantifier scans over disjoint slices, so
// the total work is one pass over the string.
export function isIpv4(s: string): boolean {
  const parts = s.split(".");
  return parts.length === 4 && parts.every((part) => IPV4_OCTET.test(part) && Number(part) <= 255);
}

const IPV6_GROUP = /^[0-9A-Fa-f]{1,4}$/u;

// Counts the 16-bit groups a colon-separated IPv6 section contributes, or `null` when the section
// is malformed. A trailing dotted-quad counts as the two groups it encodes (RFC 4291 §2.2 form 3).
function ipv6Groups(section: string): number | null {
  const parts = section.split(":");
  let count = 0;
  for (const [index, part] of parts.entries()) {
    if (index === parts.length - 1 && part.includes(".")) {
      if (!isIpv4(part)) {
        return null;
      }
      count += 2;
      continue;
    }
    if (!IPV6_GROUP.test(part)) {
      return null;
    }
    count += 1;
  }
  return count;
}

// RFC 4291 §2.2 textual IPv6: eight 16-bit hexadecimal groups, at most one `::` run standing in for
// one or more omitted zero groups, optionally ending in a dotted-quad that supplies the last two.
// Zone identifiers, CIDR suffixes and surrounding brackets are not part of the address production.
// Each character is visited once by the split-and-test scan.
export function isIpv6(s: string): boolean {
  const elision = s.indexOf("::");
  if (elision === -1) {
    return ipv6Groups(s) === 8;
  }
  if (elision !== s.lastIndexOf("::")) {
    return false;
  }
  const head = s.slice(0, elision);
  const tail = s.slice(elision + 2);
  const headGroups = head === "" ? 0 : ipv6Groups(head);
  const tailGroups = tail === "" ? 0 : ipv6Groups(tail);
  if (headGroups === null || tailGroups === null) {
    return false;
  }
  return headGroups + tailGroups < 8;
}

const HOSTNAME_LABEL = /^[A-Za-z0-9-]+$/u;

function isHostnameLabel(label: string): boolean {
  return (
    label.length <= 63 &&
    HOSTNAME_LABEL.test(label) &&
    !label.startsWith("-") &&
    !label.endsWith("-")
  );
}

// RFC 1123 §2.1 host name: dot-separated labels of at most 63 ASCII letters, digits and hyphens,
// no leading or trailing hyphen in a label, at most 253 characters overall. A leading digit is
// legal. IDNA validity of an `xn--` label is not checked; such a label passes as ordinary LDH text.
export function isHostname(s: string): boolean {
  return s.length <= 253 && s.split(".").every(isHostnameLabel);
}

const EMAIL_ATOM = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+$/u;
const EMAIL_QUOTED = /^"(?:[ !#-[\]-~]|\\[ -~])*"$/u;

function isEmailLocalPart(local: string): boolean {
  if (local.startsWith('"')) {
    return EMAIL_QUOTED.test(local);
  }
  return local !== "" && local.split(".").every((atom) => EMAIL_ATOM.test(atom));
}

function isEmailDomain(domain: string): boolean {
  if (!domain.startsWith("[")) {
    return domain !== "" && isHostname(domain);
  }
  if (!domain.endsWith("]")) {
    return false;
  }
  const literal = domain.slice(1, -1);
  if (literal.slice(0, 5).toLowerCase() === "ipv6:") {
    return isIpv6(literal.slice(5));
  }
  return isIpv4(literal);
}

// RFC 5321 §4.1.2 Mailbox: a dot-string or quoted-string local part, `@`, and either an RFC 1123
// host name or a bracketed IPv4/IPv6 address literal. Comments, folding whitespace and non-ASCII
// (SMTPUTF8) are not accepted. Both halves are scanned once, so the cost is linear in length.
export function isEmail(s: string): boolean {
  const at = s.lastIndexOf("@");
  return at !== -1 && isEmailLocalPart(s.slice(0, at)) && isEmailDomain(s.slice(at + 1));
}

const URI_USERINFO = /^[A-Za-z0-9\-._~!$&'()*+,;=:%]*$/u;
const URI_REG_NAME = /^[A-Za-z0-9\-._~!$&'()*+,;=%]*$/u;
const URI_PATH = /^[A-Za-z0-9\-._~!$&'()*+,;=:@/%]*$/u;
const URI_QUERY = /^[A-Za-z0-9\-._~!$&'()*+,;=:@/?%]*$/u;
const URI_SCHEME = /^[A-Za-z][A-Za-z0-9+\-.]*$/u;
const URI_PORT = /^[0-9]*$/u;
const URI_IPVFUTURE = /^[vV][0-9A-Fa-f]+\.[A-Za-z0-9\-._~!$&'()*+,;=:]+$/u;
const HEX_PAIR = /^[0-9A-Fa-f]{2}$/u;

// Every `%` in a component must introduce a complete `pct-encoded` triplet. Each scan resumes past
// the previous match, so the walk visits each character at most once.
function percentEncodingIsWellFormed(value: string): boolean {
  for (let index = value.indexOf("%"); index !== -1; index = value.indexOf("%", index + 1)) {
    if (!HEX_PAIR.test(value.slice(index + 1, index + 3))) {
      return false;
    }
  }
  return true;
}

function isUriComponent(value: string, charset: RegExp): boolean {
  return charset.test(value) && percentEncodingIsWellFormed(value);
}

function isUriHost(host: string): boolean {
  if (!host.startsWith("[")) {
    return isUriComponent(host, URI_REG_NAME);
  }
  if (!host.endsWith("]")) {
    return false;
  }
  const literal = host.slice(1, -1);
  return URI_IPVFUTURE.test(literal) || isIpv6(literal);
}

function isUriAuthority(authority: string): boolean {
  const at = authority.lastIndexOf("@");
  if (at !== -1 && !isUriComponent(authority.slice(0, at), URI_USERINFO)) {
    return false;
  }
  const hostPort = authority.slice(at + 1);
  const colon = hostPort.indexOf(":", hostPort.lastIndexOf("]") + 1);
  if (colon === -1) {
    return isUriHost(hostPort);
  }
  return isUriHost(hostPort.slice(0, colon)) && URI_PORT.test(hostPort.slice(colon + 1));
}

// RFC 3986 §4.1 URI-reference, split by the Appendix B decomposition and then checked component by
// component: scheme grammar, authority (userinfo/host/port), and the `pchar` character sets for
// path, query and fragment, with every `%` required to introduce a complete triplet. `requireScheme`
// selects §3 URI over §4.1 URI-reference. Splitting and scanning each visit a character once.
function isUriShaped(s: string, requireScheme: boolean): boolean {
  const hash = s.indexOf("#");
  const fragment = hash === -1 ? null : s.slice(hash + 1);
  const withoutFragment = hash === -1 ? s : s.slice(0, hash);
  const mark = withoutFragment.indexOf("?");
  const query = mark === -1 ? null : withoutFragment.slice(mark + 1);
  const withoutQuery = mark === -1 ? withoutFragment : withoutFragment.slice(0, mark);

  const colon = withoutQuery.indexOf(":");
  const slash = withoutQuery.indexOf("/");
  const schemeEnd = colon !== -1 && (slash === -1 || colon < slash) ? colon : -1;
  const scheme =
    schemeEnd !== -1 && URI_SCHEME.test(withoutQuery.slice(0, schemeEnd))
      ? withoutQuery.slice(0, schemeEnd)
      : null;
  if (requireScheme && scheme === null) {
    return false;
  }
  const afterScheme = scheme === null ? withoutQuery : withoutQuery.slice(scheme.length + 1);

  let path = afterScheme;
  if (afterScheme.startsWith("//")) {
    const pathStart = afterScheme.indexOf("/", 2);
    const authority = pathStart === -1 ? afterScheme.slice(2) : afterScheme.slice(2, pathStart);
    if (!isUriAuthority(authority)) {
      return false;
    }
    path = pathStart === -1 ? "" : afterScheme.slice(pathStart);
  } else if (scheme === null) {
    // RFC 3986 §4.2: a relative reference's first path segment may not contain a colon, which would
    // otherwise be re-read as a scheme.
    const segmentEnd = afterScheme.indexOf("/");
    const first = segmentEnd === -1 ? afterScheme : afterScheme.slice(0, segmentEnd);
    if (first.includes(":")) {
      return false;
    }
  }
  return (
    isUriComponent(path, URI_PATH) &&
    (query === null || isUriComponent(query, URI_QUERY)) &&
    (fragment === null || isUriComponent(fragment, URI_QUERY))
  );
}

// RFC 3986 §3 URI: a URI-reference that carries a scheme.
export function isUri(s: string): boolean {
  return isUriShaped(s, true);
}

// RFC 3986 §4.1 URI-reference: a URI or a relative reference.
export function isUriReference(s: string): boolean {
  return isUriShaped(s, false);
}

function scanDigits(s: string, start: number): number {
  let index = start;
  while (index < s.length) {
    const code = s.charCodeAt(index);
    if (code < 0x30 || code > 0x39) {
      break;
    }
    index += 1;
  }
  return index;
}

// Consumes `1*DIGIT <designator>` runs starting at `start`. The designators used must form a
// contiguous run of `designators` — RFC 3339's duration rules nest each unit inside the previous
// one, so `P1Y2D` and `PT1H2S` are not durations. Returns the index after the run, or `null` when
// the run is empty or malformed.
function scanDurationRun(s: string, start: number, designators: string): number | null {
  let index = start;
  let expected = -1;
  while (index < s.length) {
    const digitsEnd = scanDigits(s, index);
    if (digitsEnd === index) {
      break;
    }
    const position = designators.indexOf(s.slice(digitsEnd, digitsEnd + 1));
    if (position === -1 || (expected !== -1 && position !== expected)) {
      return null;
    }
    expected = position + 1;
    index = digitsEnd + 1;
  }
  return expected === -1 ? null : index;
}

// RFC 3339 Appendix A `duration`: `P` followed by either a week count or a date run (years, months,
// days) and/or a `T` time run (hours, minutes, seconds). Values are unsigned integers with no
// fractional part, and weeks combine with nothing else. The two scans walk the string once.
export function isDuration(s: string): boolean {
  if (!s.startsWith("P")) {
    return false;
  }
  if (scanDurationRun(s, 1, "W") === s.length) {
    return true;
  }
  let index = 1;
  if (!s.startsWith("T", index)) {
    const dateEnd = scanDurationRun(s, index, "YMD");
    if (dateEnd === null) {
      return false;
    }
    if (dateEnd === s.length) {
      return true;
    }
    index = dateEnd;
  }
  return s.startsWith("T", index) && scanDurationRun(s, index + 1, "HMS") === s.length;
}

// Whole number within the signed 32-bit range.
export function isInt32(v: number): boolean {
  return Number.isInteger(v) && v >= -2147483648 && v <= 2147483647;
}

const INT64_WIRE_INTEGER = /^-?(?:0|[1-9]\d*)$/;

// The bigint representation validates the pre-transform wire surface: safe JSON integers remain
// numbers, unsafe ones are restored as bigints by the transport, and request encoders contribute a
// raw-JSON token before request validation runs.
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
