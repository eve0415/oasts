// Canonical media-type serializer vectors gating the client conformance gate for the oasts client
// artifact. NEVER regenerate these from implementation output — expected values are derived
// from the frozen contract's canonical-serializer clause: "lowercase type/subtype and parameter
// names; parameters ordered by the UTF-8 bytes of their lowercase names; `; ` as the separator
// with no whitespace around `=`; a value emitted as a token when it is an ASCII token,
// otherwise as a quoted string with quoted-pairs only for DQUOTE and backslash; `charset`
// values lowercased" — plus the media-comparison clause feeding it: "parse per RFC 9110;
// lowercase type, subtype, and parameter names; decode quoted-pairs so token and quoted
// spellings are identical; reject duplicate parameter names case-insensitively". A "token" is
// the RFC 9110 §5.6.2 `token` production: 1*tchar, where
// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" /
// "~" / DIGIT / ALPHA.
//
// Only `charset` VALUES are lowercased by the canonical serializer; every other parameter's
// value keeps its original casing/bytes, re-emitted as a token or quoted string per the rule
// above with no other transformation. This file's vectors deliberately use a mixed-case
// non-charset value (`boundary=AbC123`) to make that asymmetry directly observable.

export type MediaCanonicalVector = {
  readonly cite: string;
  readonly verdict: "canonical";
  /** Vectors sharing a `group` converge on the identical `expectedCanonical` bytes. */
  readonly group: string;
  readonly input: string;
  readonly expectedCanonical: string;
};

export type MediaRejectVector = {
  readonly cite: string;
  readonly verdict: "reject-duplicate" | "reject-invalid";
  readonly input: string;
  readonly reason: string;
};

export type MediaVector = MediaCanonicalVector | MediaRejectVector;

export const MEDIA_VECTORS: readonly MediaVector[] = [
  // --- Group "xml-charset": the spec's own worked example, application/xml; charset=utf-8 ---
  {
    cite: "frozen contract",
    verdict: "canonical",
    group: "xml-charset",
    input: "application/xml; charset=utf-8",
    expectedCanonical: "application/xml; charset=utf-8",
  },
  {
    cite: "frozen contract",
    verdict: "canonical",
    group: "xml-charset",
    input: "Application/XML; charset=UTF-8",
    expectedCanonical: "application/xml; charset=utf-8",
  },
  {
    cite: "frozen contract",
    verdict: "canonical",
    group: "xml-charset",
    input: "application/xml;charset=utf-8",
    expectedCanonical: "application/xml; charset=utf-8",
  },
  {
    // OWS around ";" is grammatically legal (RFC 9110: *( OWS ";" OWS parameter )); contrast
    // with the reject-invalid BWS vector below — the parameter production itself admits no
    // whitespace around "=".
    cite: "frozen contract",
    verdict: "canonical",
    group: "xml-charset",
    input: "application/xml ; charset=utf-8",
    expectedCanonical: "application/xml; charset=utf-8",
  },
  {
    cite: "frozen contract",
    verdict: "canonical",
    group: "xml-charset",
    input: 'application/xml; charset="utf-8"',
    expectedCanonical: "application/xml; charset=utf-8",
  },

  // --- Group "reorder-case": two parameters, out-of-order and case-varied input spellings,
  // converging on parameters ordered by the UTF-8 bytes of their lowercase names
  // ("boundary" < "charset"), with the non-charset value's original casing preserved. ---
  {
    cite: "frozen contract",
    verdict: "canonical",
    group: "reorder-case",
    input: "application/vnd.custom; charset=UTF-8; boundary=AbC123",
    expectedCanonical: "application/vnd.custom; boundary=AbC123; charset=utf-8",
  },
  {
    cite: "frozen contract",
    verdict: "canonical",
    group: "reorder-case",
    input: "APPLICATION/VND.CUSTOM; boundary=AbC123; CHARSET=utf-8",
    expectedCanonical: "application/vnd.custom; boundary=AbC123; charset=utf-8",
  },
  {
    cite: "frozen contract",
    verdict: "canonical",
    group: "reorder-case",
    input: "application/vnd.custom;boundary=AbC123;charset=UTF-8",
    expectedCanonical: "application/vnd.custom; boundary=AbC123; charset=utf-8",
  },

  // --- Group "quoted-escape": a value requiring quoting (it contains DQUOTE and backslash,
  // which are not tchar, so it is not a valid token), presented via
  // equivalent quoted-string spellings (minimal escaping vs. a superfluous-but-legal
  // quoted-pair escape of a plain letter), plus a case/whitespace variant. Logical value:
  // the 5 characters a " b \ c (a, DQUOTE, b, backslash, c). Canonical escaping touches only
  // DQUOTE (-> \") and backslash (-> \\), giving quoted-string bytes "a\"b\\c". ---
  {
    cite: "frozen contract",
    verdict: "canonical",
    group: "quoted-escape",
    input: 'application/vnd.custom2; note="a\\"b\\\\c"',
    expectedCanonical: 'application/vnd.custom2; note="a\\"b\\\\c"',
  },
  {
    // Same logical value via a superfluous-but-grammatically-legal quoted-pair escape of the
    // plain letter c (quoted-pair permits escaping any VCHAR/SP/HTAB, not only DQUOTE and
    // backslash): the encoded bytes here are a \" b \\ \c, which decode to a " b \ c — the
    // same logical value as the vector above — and must re-canonicalize identically because
    // the canonical serializer only ever re-escapes DQUOTE and backslash, discarding any
    // other quoted-pair the input happened to use.
    cite: "frozen contract",
    verdict: "canonical",
    group: "quoted-escape",
    input: 'application/vnd.custom2; note="a\\"b\\\\\\c"',
    expectedCanonical: 'application/vnd.custom2; note="a\\"b\\\\c"',
  },
  {
    cite: "frozen contract",
    verdict: "canonical",
    group: "quoted-escape",
    input: 'APPLICATION/VND.CUSTOM2 ; NOTE="a\\"b\\\\c"',
    expectedCanonical: 'application/vnd.custom2; note="a\\"b\\\\c"',
  },

  // --- reject-duplicate: case-insensitive duplicate parameter name ---
  {
    cite: "frozen contract",
    verdict: "reject-duplicate",
    input: "application/json; charset=utf-8; Charset=utf-16",
    reason: '"charset" and "Charset" are the same parameter name compared case-insensitively.',
  },

  // --- reject-invalid: malformed syntax ---
  {
    cite: "frozen contract",
    verdict: "reject-invalid",
    input: "application/xml; charset = utf-8",
    reason:
      'Whitespace around "=" is outside the RFC 9110 parameter production (parameter-name "=" ' +
      'parameter-value admits no BWS; only OWS around ";" is grammatical), and the frozen contract ' +
      'pins "parse per RFC 9110" — malformed syntax is a declared-position diagnostic and ' +
      "request-encode when runtime-selected.",
  },

  // --- reject-invalid: control or non-ASCII parameter value ---
  {
    cite: "frozen contract",
    verdict: "reject-invalid",
    input: 'text/plain; name="bad\u0001value"',
    reason:
      "The parameter value contains a control byte (U+0001 SOH); the frozen contract requires a " +
      "named generation diagnostic when declared and request-encode when runtime-selected, " +
      "never encoding it into the canonical output.",
  },
  {
    cite: "frozen contract",
    verdict: "reject-invalid",
    input: 'text/plain; name="café"',
    reason:
      "The parameter value contains a non-ASCII byte (é); the frozen contract requires rejection " +
      "rather than encoding it, unlike the type/subtype and value-content rules elsewhere in " +
      "this file that operate entirely within ASCII.",
  },
];
