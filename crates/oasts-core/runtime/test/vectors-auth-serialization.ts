// Hand-derived security-scheme serialization vectors gating the client conformance gate for
// the oasts client artifact. NEVER regenerate these from implementation output — every
// expected value below is derived only from the pinned serialization rules plus the cited
// standards, and the implementation is written to satisfy these frozen vectors, not the
// reverse. Provenance for each rule family:
//
//   - Bearer  -> RFC 6750 (the `b64token` grammar); HTTP bearer, OAuth 2.0, and OpenID
//     Connect all serialize identically, so one table covers all three.
//   - Basic   -> RFC 7617; RFC 7617 leaves the username/password charset open, so this project
//     pins one algorithm (NFC normalize, control/colon rejection, UTF-8, then Base64 per
//     RFC 4648). NFC is Unicode Normalization Form C.
//   - Header API key -> the WHATWG Fetch `Headers` value contract (grammar check, ByteString
//     conversion, and value-normalization comparison), applied BEFORE Request construction so
//     Fetch's own whitespace-trimming never silently mutates a byte-sensitive credential.
//   - Query API key -> RFC 3986 percent-encoding, reusing the exact scalar form-style /
//     explode:true / allowReserved:false query encoder (`encodeComponent` over UTF-8 bytes,
//     percent-encoding every octet outside RFC 3986 "unreserved" with UPPERCASE hex) that the
//     ordinary-query gate already exercises; the duplicate-name rejection is this project's own
//     pre-construction guard, not an RFC rule.
//   - Cookie API key -> WHATWG Fetch forbids a `Cookie` request header, so the credential is an
//     ambient sentinel (the runtime cookie store supplies the cookie) and NO header is emitted.
//
// Base64 and percent-encoding oracles below were computed at authoring time with a throwaway
// `node` one-liner applying exactly these rules (NFC via String.prototype.normalize, UTF-8 via
// TextEncoder, Base64 via Buffer, percent-encoding via the RFC 3986 "unreserved" set) — this
// derives from the rule, never from any implementation.
//
// This module is DATA ONLY: it imports nothing (no runtime imports at all) so it can be
// typechecked and frozen in isolation. Non-ASCII and control code points are written as
// explicit `\uXXXX` escapes so the exact frozen bytes are unambiguous on review.
//
// Reading `expected` (shared across the header/bearer/query tables):
//   - `typeof expected === "string"` -> SUCCESS. The value is the exact bytes the harness must
//     observe (a full `Name: value` header line, or a query component — see each table's doc).
//   - otherwise -> an `AuthFailure` object. The serializer must fail BEFORE Request construction
//     with a typed failure whose `.failure` channel equals `expected.failure` (every failure in
//     this file is an `auth` failure — the `request-encode` arm exists only to type the shared
//     failure shape) and whose human-readable message CONTAINS `expected.messageIncludes` as a
//     substring. `messageIncludes` is deliberately short and semantic; it constrains the
//     implementation's error text, which is why it is frozen alongside the inputs.

export type AuthFailure = {
  readonly failure: "auth" | "request-encode";
  readonly messageIncludes: string;
};

// --- Bearer (RFC 6750) ---
// A single table covers HTTP bearer, OAuth 2.0, and OpenID Connect because all three serialize
// identically. The provider token must satisfy the RFC 6750 `b64token` grammar:
//   1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
// i.e. at least one character drawn from that set, followed by zero or more "=" — and "=" is
// legal ONLY as trailing padding (never interior). A valid token is emitted VERBATIM as the
// full header line `Authorization: Bearer <token>`; the header name is always `Authorization`.
// An invalid token is an `auth` failure before Request construction.
//
// Harness wiring: on success, format the emitted (name, value) as `name + ": " + value` and
// assert it equals `expected`; the name is always `Authorization`. On failure, see the shared
// `expected` doc above. All grammar rejections share the semantic anchor "b64token".

export type BearerInput = { readonly token: string };

export type BearerVector = {
  readonly name: string;
  readonly cite: string;
  readonly input: BearerInput;
  readonly expected: string | AuthFailure;
};

export const BEARER_VECTORS = [
  {
    // Exercises the full grammar alphabet: ALPHA, DIGIT, and every symbol "-._~+/", plus one
    // trailing "=" pad. Emitted verbatim.
    name: "valid-full-alphabet",
    cite: "RFC 6750",
    input: { token: "abc123-._~+/=" },
    expected: "Authorization: Bearer abc123-._~+/=",
  },
  {
    // Valid Base64 token with DOUBLE "=" padding: proves multiple trailing pads are legal and
    // the token is copied verbatim with no re-encoding.
    name: "valid-double-padding-verbatim",
    cite: "RFC 6750",
    input: { token: "YWxhZGRpbg==" },
    expected: "Authorization: Bearer YWxhZGRpbg==",
  },
  {
    // Empty violates the required "1*(...)" (at least one character).
    name: "empty-token",
    cite: "RFC 6750",
    input: { token: "" },
    expected: { failure: "auth", messageIncludes: "b64token" },
  },
  {
    name: "interior-space",
    cite: "RFC 6750",
    input: { token: "ab cd" },
    expected: { failure: "auth", messageIncludes: "b64token" },
  },
  {
    name: "comma",
    cite: "RFC 6750",
    input: { token: "ab,cd" },
    expected: { failure: "auth", messageIncludes: "b64token" },
  },
  {
    name: "double-quote",
    cite: "RFC 6750",
    input: { token: 'ab"cd' },
    expected: { failure: "auth", messageIncludes: "b64token" },
  },
  {
    // "=" appears interior (base chars follow it), so it is not trailing padding -> invalid.
    name: "equals-not-trailing",
    cite: "RFC 6750",
    input: { token: "ab=cd" },
    expected: { failure: "auth", messageIncludes: "b64token" },
  },
] as const satisfies readonly BearerVector[];

// --- Basic (RFC 7617, pinned algorithm) ---
// Algorithm, in order: NFC-normalize BOTH username and password; reject any control character
// (C0 controls U+0000..U+001F and DEL U+007F) in EITHER value as an `auth` failure; reject ":"
// in the USERNAME as an `auth` failure (":" in the password is allowed and is encoded normally);
// UTF-8-encode the string `username + ":" + password`; standard Base64 WITH padding (RFC 4648);
// emit the full header line `Authorization: Basic <base64>`. The header name is always
// `Authorization`.
//
// Harness wiring: identical to Bearer above (success -> `name + ": " + value` equals `expected`,
// name is `Authorization`; failure -> shared `expected` doc). Control-character rejections share
// the anchor "control"; the username-colon rejection uses "colon".
//
// The two non-ASCII vectors carry the SAME é (U+00E9) in NFC and in NFD (e + U+0301); the NFD
// input MUST normalize to the identical Base64 as the NFC input — that equality is the whole
// point of the pair. Base64 oracle (computed from the rule): "user:café" -> dXNlcjpjYWbDqQ==.

export type BasicInput = {
  readonly username: string;
  readonly password: string;
};

export type BasicVector = {
  readonly name: string;
  readonly cite: string;
  readonly input: BasicInput;
  readonly expected: string | AuthFailure;
};

export const BASIC_VECTORS = [
  {
    // RFC 7617's own worked example: "Aladdin:open sesame".
    name: "ascii-happy-path",
    cite: "RFC 7617",
    input: { username: "Aladdin", password: "open sesame" },
    expected: "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
  },
  {
    // é already in NFC (U+00E9): password "café". "user:café" UTF-8 -> Base64.
    name: "non-ascii-nfc",
    cite: "RFC 7617",
    input: { username: "user", password: "caf\u00E9" },
    expected: "Authorization: Basic dXNlcjpjYWbDqQ==",
  },
  {
    // Same é as NFD: password "cafe" + combining acute U+0301. NFC normalization collapses it to
    // U+00E9, so the Base64 MUST match the previous vector byte-for-byte.
    name: "non-ascii-nfd-equals-nfc",
    cite: "RFC 7617",
    input: { username: "user", password: "cafe\u0301" },
    expected: "Authorization: Basic dXNlcjpjYWbDqQ==",
  },
  {
    // ":" in the username is rejected (it would corrupt the credential delimiter).
    name: "colon-in-username",
    cite: "RFC 7617",
    input: { username: "ala:ddin", password: "secret" },
    expected: { failure: "auth", messageIncludes: "colon" },
  },
  {
    // ":" in the password is allowed. "user:pa:ss" UTF-8 -> Base64.
    name: "colon-in-password-allowed",
    cite: "RFC 7617",
    input: { username: "user", password: "pa:ss" },
    expected: "Authorization: Basic dXNlcjpwYTpzcw==",
  },
  {
    // U+0007 (BEL), a C0 control, in the password.
    name: "bel-control-in-password",
    cite: "RFC 7617",
    input: { username: "user", password: "pa\u0007ss" },
    expected: { failure: "auth", messageIncludes: "control" },
  },
  {
    // U+000A (LF), a C0 control, in the username.
    name: "lf-control-in-username",
    cite: "RFC 7617",
    input: { username: "us\u000Aer", password: "secret" },
    expected: { failure: "auth", messageIncludes: "control" },
  },
  {
    // U+007F (DEL) is rejected alongside the C0 controls.
    name: "del-control-in-password",
    cite: "RFC 7617",
    input: { username: "user", password: "pa\u007Fss" },
    expected: { failure: "auth", messageIncludes: "control" },
  },
  {
    // Empty username -> ":secret" UTF-8 -> Base64. No colon/control, so valid.
    name: "empty-username",
    cite: "RFC 7617",
    input: { username: "", password: "secret" },
    expected: "Authorization: Basic OnNlY3JldA==",
  },
  {
    // Empty password -> "user:" UTF-8 -> Base64.
    name: "empty-password",
    cite: "RFC 7617",
    input: { username: "user", password: "" },
    expected: "Authorization: Basic dXNlcjo=",
  },
  {
    // Both empty -> ":" (single 0x3A byte) -> Base64 "Og==".
    name: "both-empty",
    cite: "RFC 7617",
    input: { username: "", password: "" },
    expected: "Authorization: Basic Og==",
  },
] as const satisfies readonly BasicVector[];

// --- Header API key (WHATWG Fetch value contract, pre-construction) ---
// The declared header name carries the EXACT provider bytes, validated before Request
// construction by three checks IN THIS ORDER, any failure being an `auth` failure:
//   1. header-value grammar check: 0x00 (NUL), 0x0A (LF), or 0x0D (CR) at ANY position rejects.
//   2. ByteString conversion: any code point above U+00FF rejects.
//   3. normalization comparison: the value with leading/trailing HTTP whitespace stripped must
//      equal the original value, so a leading or trailing SP (0x20) or HTAB (0x09) rejects.
//      INTERIOR spaces pass. (NUL/CR/LF are already excluded by step 1, so step 3 only ever
//      catches edge SP/HTAB.)
// A passing value is emitted as the full header line `<declared-name>: <exact provider bytes>`.
//
// Harness wiring: on success, format the emitted (name, value) as `name + ": " + value` and
// assert it equals `expected`; the name is `input.headerName`. On failure, see the shared
// `expected` doc. Per-step anchors, chosen to pin which check fired: "control" (step 1),
// "ByteString" (step 2), "whitespace" (step 3). The order matters — e.g. a leading LF is a
// step-1 "control" failure, NOT a step-3 whitespace failure, because grammar runs first.

export type HeaderKeyInput = {
  readonly headerName: string;
  readonly value: string;
};

export type HeaderKeyVector = {
  readonly name: string;
  readonly cite: string;
  readonly input: HeaderKeyInput;
  readonly expected: string | AuthFailure;
};

export const HEADER_KEY_VECTORS = [
  {
    name: "unchanged-ascii-passes",
    cite: "WHATWG Fetch",
    input: { headerName: "X-API-Key", value: "abc123" },
    expected: "X-API-Key: abc123",
  },
  {
    // Interior space is not edge whitespace, so normalization leaves it untouched -> passes.
    name: "interior-space-passes",
    cite: "WHATWG Fetch",
    input: { headerName: "X-API-Key", value: "ab cd" },
    expected: "X-API-Key: ab cd",
  },
  {
    // U+00FF is the ByteString upper bound (<= U+00FF) and not NUL/CR/LF nor edge whitespace, so
    // it passes all three checks and is emitted verbatim — the tight boundary of step 2.
    name: "boundary-u00ff-passes",
    cite: "WHATWG Fetch",
    input: { headerName: "X-API-Key", value: "a\u00FFb" },
    expected: "X-API-Key: a\u00FFb",
  },
  {
    // NUL interior -> step 1 grammar rejection.
    name: "nul-interior",
    cite: "WHATWG Fetch",
    input: { headerName: "X-API-Key", value: "ab\u0000cd" },
    expected: { failure: "auth", messageIncludes: "control" },
  },
  {
    // CR at end -> step 1 grammar rejection.
    name: "cr-trailing",
    cite: "WHATWG Fetch",
    input: { headerName: "X-API-Key", value: "abc\u000D" },
    expected: { failure: "auth", messageIncludes: "control" },
  },
  {
    // LF at start -> step 1 grammar rejection, NOT step 3, proving grammar precedes normalization.
    name: "lf-leading",
    cite: "WHATWG Fetch",
    input: { headerName: "X-API-Key", value: "\u000Aabc" },
    expected: { failure: "auth", messageIncludes: "control" },
  },
  {
    name: "leading-space",
    cite: "WHATWG Fetch",
    input: { headerName: "X-API-Key", value: " abc" },
    expected: { failure: "auth", messageIncludes: "whitespace" },
  },
  {
    name: "trailing-space",
    cite: "WHATWG Fetch",
    input: { headerName: "X-API-Key", value: "abc " },
    expected: { failure: "auth", messageIncludes: "whitespace" },
  },
  {
    name: "leading-htab",
    cite: "WHATWG Fetch",
    input: { headerName: "X-API-Key", value: "\u0009abc" },
    expected: { failure: "auth", messageIncludes: "whitespace" },
  },
  {
    name: "trailing-htab",
    cite: "WHATWG Fetch",
    input: { headerName: "X-API-Key", value: "abc\u0009" },
    expected: { failure: "auth", messageIncludes: "whitespace" },
  },
  {
    // U+3042 (HIRAGANA A) passes step 1 but is above U+00FF -> step 2 ByteString rejection.
    name: "non-latin1-hiragana",
    cite: "WHATWG Fetch",
    input: { headerName: "X-API-Key", value: "ab\u3042cd" },
    expected: { failure: "auth", messageIncludes: "ByteString" },
  },
  {
    // U+0100 is one past the ByteString bound -> step 2 rejection (complements u00ff-passes).
    name: "just-over-boundary-u0100",
    cite: "WHATWG Fetch",
    input: { headerName: "X-API-Key", value: "a\u0100b" },
    expected: { failure: "auth", messageIncludes: "ByteString" },
  },
] as const satisfies readonly HeaderKeyVector[];

// --- Query API key (RFC 3986, reusing the scalar form-style query encoder) ---
// The key is serialized by the SAME scalar form-style / explode:true / allowReserved:false
// encoder as an ordinary scalar query parameter: both the key NAME and the key VALUE are
// percent-encoded over their UTF-8 bytes, encoding every octet outside RFC 3986 "unreserved"
// (ALPHA / DIGIT / "-" / "." / "_" / "~") with UPPERCASE hex, producing `name=value`. The
// fragment is APPENDED AFTER the ordinary query fields. If the resolved base/server URL already
// carries that query parameter NAME, it is an `auth` failure before Request construction.
//
// Field model (matches the sibling parameter-style vectors' convention: query components carry
// NO leading "?"): `existingQuery` is the already-serialized ordinary query component without a
// leading "?" ("" when there is none); `keyName`/`keyValue` are the raw (un-encoded) API-key
// name and value. On success `expected` is the FULL resulting query component (again no leading
// "?"), i.e. `existingQuery` with the encoded `keyName=keyValue` fragment appended after a "&"
// (or standing alone when `existingQuery` is ""). The caller prepends the "?" URL delimiter; it
// is not part of these strings.
//
// Harness wiring: on success assert the produced query component equals `expected`; on failure
// see the shared `expected` doc. The duplicate-name rejection uses the colliding param name
// itself as the anchor.
//
// Percent-encoding oracle (from the rule): value "/?#[]@&= " (the 8 RFC 3986 reserved chars plus
// a space) under allowReserved:false -> %2F%3F%23%5B%5D%40%26%3D%20; value "café" -> caf%C3%A9.

export type QueryKeyInput = {
  readonly existingQuery: string;
  readonly keyName: string;
  readonly keyValue: string;
};

export type QueryKeyVector = {
  readonly name: string;
  readonly cite: string;
  readonly input: QueryKeyInput;
  readonly expected: string | AuthFailure;
};

export const QUERY_KEY_VECTORS = [
  {
    // Plain append after an existing ordinary field; nothing needs encoding.
    name: "plain-append",
    cite: "RFC 3986",
    input: { existingQuery: "a=1", keyName: "api_key", keyValue: "secret123" },
    expected: "a=1&api_key=secret123",
  },
  {
    // No existing query -> the key fragment stands alone (no leading "&").
    name: "empty-existing-query",
    cite: "RFC 3986",
    input: { existingQuery: "", keyName: "api_key", keyValue: "secret123" },
    expected: "api_key=secret123",
  },
  {
    // Reserved characters in the value are all percent-encoded under allowReserved:false.
    name: "reserved-chars-value",
    cite: "RFC 3986",
    input: { existingQuery: "a=1", keyName: "token", keyValue: "/?#[]@&= " },
    expected: "a=1&token=%2F%3F%23%5B%5D%40%26%3D%20",
  },
  {
    // Non-ASCII value: é (U+00E9) UTF-8 is 0xC3 0xA9 -> %C3%A9, uppercase hex.
    name: "non-ascii-value",
    cite: "RFC 3986",
    input: { existingQuery: "a=1", keyName: "token", keyValue: "caf\u00E9" },
    expected: "a=1&token=caf%C3%A9",
  },
  {
    // The base query already carries "token" -> duplicate-name auth failure; anchor is the name.
    name: "collision-with-existing-key",
    cite: "RFC 3986",
    input: { existingQuery: "token=old", keyName: "token", keyValue: "new" },
    expected: { failure: "auth", messageIncludes: "token" },
  },
] as const satisfies readonly QueryKeyVector[];

// --- Cookie API key (WHATWG Fetch: no Cookie request header) ---
// A cookie-located API key credential is an ambient SENTINEL, not a string. The real sentinel is
// a unique symbol that cannot be imported into this data-only module, so it is represented
// symbolically: `{ kind: "ambient" }` stands for that sentinel, and `{ kind: "string", value }`
// stands for a caller mistakenly supplying a plain string.
//
// Selecting the ambient sentinel emits NO header at all (WHATWG Fetch forbids a `Cookie` request
// header); the runtime cookie store is asserted to supply the cookie and the request proceeds.
// Supplying a plain string for a cookie scheme is an `auth` failure (of ANY content — even the
// empty string — since the type, not the value, is wrong).
//
// Reading `expected` here (distinct from the shared string/failure discrimination above):
//   - `"noHeader" in expected` -> SUCCESS: assert the serializer emits no `Cookie` (indeed no)
//     header for this credential and lets the request proceed.
//   - otherwise -> an `AuthFailure` (see the shared `expected` doc). The string rejection uses
//     the anchor "ambient" (the required credential kind).

export type CookieCredential =
  | { readonly kind: "ambient" }
  | { readonly kind: "string"; readonly value: string };

export type CookieExpectation = { readonly noHeader: true };

export type CookieVector = {
  readonly name: string;
  readonly cite: string;
  readonly input: CookieCredential;
  readonly expected: CookieExpectation | AuthFailure;
};

export const COOKIE_SENTINEL_VECTORS = [
  {
    // Ambient sentinel selected -> no header emitted, request proceeds.
    name: "ambient-sentinel-no-header",
    cite: "WHATWG Fetch",
    input: { kind: "ambient" },
    expected: { noHeader: true },
  },
  {
    // A plain string for a cookie scheme is rejected.
    name: "plain-string-rejected",
    cite: "WHATWG Fetch",
    input: { kind: "string", value: "sessionid=abc" },
    expected: { failure: "auth", messageIncludes: "ambient" },
  },
  {
    // Even an empty string is rejected — the credential TYPE is wrong, independent of content.
    name: "empty-string-still-rejected",
    cite: "WHATWG Fetch",
    input: { kind: "string", value: "" },
    expected: { failure: "auth", messageIncludes: "ambient" },
  },
] as const satisfies readonly CookieVector[];
