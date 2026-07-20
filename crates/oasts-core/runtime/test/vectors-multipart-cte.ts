// Content-Transfer-Encoding byte-domain vectors gating the client conformance gate for the oasts
// client artifact. Split out of vectors-multipart.ts to keep each file under ~400 lines.
// NEVER regenerate these from implementation output — expected verdicts are derived from
// the frozen contract : "`7bit` requires octets ≤ 127, no NUL, and CRLF-delimited lines of ≤ 998
// octets; `8bit` requires no NUL and the same line limits; `binary` is unrestricted —
// violations are `request-encode`." `Content-Transfer-Encoding` is admitted only as `7bit`,
// `8bit`, or `binary`; none of the three transforms part bytes, so these are
// pure byte-domain / line-framing acceptance checks over the identity-encoded input.
//
// Resolved ambiguity: the frozen contract says lines must be "≤ 998 octets" but does not itself state
// whether the CRLF terminator counts toward that length. This file reads "line" as the octets
// between line boundaries, NOT counting the terminating CRLF itself — i.e. a line of exactly
// 998 content octets followed by CRLF is the maximum allowed, and 999 content octets followed
// by CRLF is the first violating length. This matches the conventional MIME line-length
// convention (RFC 2045's own "line length" counts content, not the CRLF that delimits it).
//
// Each vector's `bytes` is a readonly number[] because every vector in this file exercises
// control-byte and non-ASCII-byte boundaries — there is no ASCII-only-string-safe vector here.

export type CteEncoding = "7bit" | "8bit" | "binary";

export type CteVector = {
  readonly cite: string;
  readonly encoding: CteEncoding;
  readonly description: string;
  readonly bytes: readonly number[];
  readonly verdict: "ok" | "request-encode";
};

/** Builds an array of `count` copies of `byte` — used for the 998/999-octet line vectors. */
function repeatedByte(byte: number, count: number): number[] {
  return Array.from({ length: count }, () => byte);
}

const CR = 0x0d;
const LF = 0x0a;
const A = 0x41; // 'A', a plain 7bit-safe filler octet used for line-length vectors

export const CTE_VECTORS: readonly CteVector[] = [
  // --- 7bit ---
  {
    cite: "frozen contract",
    encoding: "7bit",
    description:
      "Octet 127 (DEL) is the maximum allowed 7bit value; no NUL, no bare CR/LF present.",
    bytes: [A, 0x7f],
    verdict: "ok",
  },
  {
    cite: "frozen contract",
    encoding: "7bit",
    description: "Octet 128 exceeds the 7bit maximum of 127 (7bit permits only octets <= 127).",
    bytes: [A, 0x80],
    verdict: "request-encode",
  },
  {
    cite: "frozen contract",
    encoding: "7bit",
    description: "An embedded NUL is forbidden under 7bit.",
    bytes: [A, 0x00, A],
    verdict: "request-encode",
  },
  {
    cite: "frozen contract",
    encoding: "7bit",
    description: "A CR not immediately followed by LF violates the CRLF-delimited line rule.",
    bytes: [A, CR, A],
    verdict: "request-encode",
  },
  {
    cite: "frozen contract",
    encoding: "7bit",
    description: "An LF not immediately preceded by CR violates the CRLF-delimited line rule.",
    bytes: [A, LF, A],
    verdict: "request-encode",
  },
  {
    cite: "frozen contract",
    encoding: "7bit",
    description: "A properly paired CRLF line terminator is allowed.",
    bytes: [A, CR, LF, A],
    verdict: "ok",
  },
  {
    cite: "frozen contract",
    encoding: "7bit",
    description:
      "A 998-octet line (the maximum allowed length, not counting the terminating CRLF) is allowed.",
    bytes: [...repeatedByte(A, 998), CR, LF],
    verdict: "ok",
  },
  {
    cite: "frozen contract",
    encoding: "7bit",
    description:
      "A 999-octet line exceeds the 998-octet maximum and violates the line-length rule.",
    bytes: [...repeatedByte(A, 999), CR, LF],
    verdict: "request-encode",
  },

  // --- 8bit ---
  {
    cite: "frozen contract",
    encoding: "8bit",
    description:
      "Octet 128 is allowed under 8bit (contrast with the identical byte sequence under 7bit above, which is a violation) — 8bit has no upper octet-value ceiling.",
    bytes: [A, 0x80],
    verdict: "ok",
  },
  {
    cite: "frozen contract",
    encoding: "8bit",
    description: "An embedded NUL is forbidden under 8bit, exactly as under 7bit.",
    bytes: [A, 0x00, A],
    verdict: "request-encode",
  },
  {
    cite: "frozen contract",
    encoding: "8bit",
    description: "8bit shares 7bit's line-length limit: a 998-octet line is allowed.",
    bytes: [...repeatedByte(A, 998), CR, LF],
    verdict: "ok",
  },
  {
    cite: "frozen contract",
    encoding: "8bit",
    description: "8bit shares 7bit's line-length limit: a 999-octet line violates it.",
    bytes: [...repeatedByte(A, 999), CR, LF],
    verdict: "request-encode",
  },
  // the frozen contract's "the same line limits" imports 7bit's whole line-framing rule — "CRLF-
  // delimited lines of <= 998 octets" — so a lone (unpaired) CR or LF violates 8bit exactly
  // as it violates 7bit.
  {
    cite: "frozen contract",
    encoding: "8bit",
    description: "A CR not immediately followed by LF violates 8bit's CRLF-delimited line rule.",
    bytes: [A, CR, A],
    verdict: "request-encode",
  },
  {
    cite: "frozen contract",
    encoding: "8bit",
    description: "An LF not immediately preceded by CR violates 8bit's CRLF-delimited line rule.",
    bytes: [A, LF, A],
    verdict: "request-encode",
  },

  // --- binary ---
  {
    cite: "frozen contract",
    encoding: "binary",
    description:
      "binary has no byte-domain or line-length restrictions at all: NUL and a lone (unpaired) CR, both of which violate 7bit and 8bit, are permitted here.",
    bytes: [0x00, CR, A, 0xff],
    verdict: "ok",
  },
];
