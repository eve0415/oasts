// Hand-derived multipart/form-data encoder vectors gating the client conformance gate for the
// oasts client artifact. NEVER regenerate these from implementation output — expected
// values are derived from the frozen contract (byte grammar, boundary algorithm,
// Content-Disposition rules) plus RFC 7578 (multipart/form-data) and RFC 2046 (MIME
// multipart) for the parts the frozen contract itself defers to.
//
// PINNED INTERPRETATION for the boundary algorithm (per the task brief — not re-derived,
// the frozen contract's "concatenated length-prefixed part bytes" is read literally as PAYLOAD bytes
// only, never part header bytes):
//
//   candidate = "oxb-" + lowercase-hex(SHA-256(preimage))[0:24]
//   preimage  = concat over parts, in emission order, of:
//                 big-endian u64 length of the part's PAYLOAD bytes  ||  the payload bytes
//
//   Collision scan: does `candidate` occur anywhere inside any ENCAPSULATED part (that part's
//   header lines + the blank CRLF + its payload bytes)? If so, append "-1" and rescan with the
//   new candidate string; repeat with "-2", "-3", ... until no encapsulated part contains the
//   current candidate as a substring. Because part HEADERS (e.g. a caller-supplied filename)
//   are scanned but never hashed, a collision is constructible without touching the hash input:
//   compute the candidate from the payloads alone, then plant that exact string inside a
//   header (see Vector B below).
//
// Body grammar (the frozen contract, byte-exact):
//   - no preamble
//   - first delimiter:      "--" boundary CRLF                      (no leading CRLF)
//   - each part:             header-line CRLF { header-line CRLF }  CRLF  payload-bytes
//   - each later delimiter:  CRLF "--" boundary CRLF
//   - close:                 CRLF "--" boundary "--"                (no trailing bytes at all)
//   - per-part header order: Content-Disposition, then Content-Type when present, then
//     admitted extra headers (the frozen contract)
//   - top-level Content-Type carries the boundary parameter UNQUOTED (the frozen contract)
//
// SHA-256 was computed with the throwaway authoring-time script reproduced verbatim below
// (also saved at the scratch path noted in the task report) — this is legitimate
// authoring-time tooling, not implementation-derived data, because the algorithm and its
// inputs are fully pinned by the task brief and the frozen contract before the script ever runs.
//
// ```js
// import { createHash } from 'node:crypto';
//
// function u64be(n) {
//   const buf = Buffer.alloc(8);
//   buf.writeBigUInt64BE(BigInt(n));
//   return buf;
// }
//
// function candidateBoundary(payloads) {
//   const chunks = [];
//   for (const p of payloads) {
//     chunks.push(u64be(p.length));
//     chunks.push(p);
//   }
//   const preimage = Buffer.concat(chunks);
//   const fullHashHex = createHash('sha256').update(preimage).digest('hex');
//   const boundary = 'oxb-' + fullHashHex.slice(0, 24);
//   return { boundary, fullHashHex, preimageHex: preimage.toString('hex'), preimageLength: preimage.length };
// }
//
// // Vector A
// candidateBoundary([Buffer.from('hello', 'ascii'), Buffer.from('world', 'ascii')]);
// // -> preimage hex 000000000000000568656c6c6f0000000000000005776f726c64 (26 bytes)
// // -> full sha256  2e3babebf8f4063be0a8da570523b3355e0d8f1010cb1ad8c67f5f2c3ab7e787... (64 hex chars)
// // -> candidate    oxb-2e3babebf8f4063be0a8da57  (no collision against either encapsulated part)
//
// // Vector B
// candidateBoundary([Buffer.from('hi', 'ascii'), Buffer.from('ok', 'ascii')]);
// // -> preimage hex 0000000000000002686900000000000000026f6b (20 bytes)
// // -> full sha256  5fec25a323ed462b87da0fb3429367ffcba6c56af577801d8f1ca0e3130bead4... (64 hex chars)
// // -> candidate    oxb-5fec25a323ed462b87da0fb3  (before collision check)
// ```
//
// Vector A's SHA-256 preimage, worked by hand from the ASCII payloads:
//   part1 payload "hello" = 5 bytes (0x68 0x65 0x6c 0x6c 0x6f)
//   part2 payload "world" = 5 bytes (0x77 0x6f 0x72 0x6c 0x64)
//   preimage = u64be(5) || "hello" || u64be(5) || "world"
//            = 00 00 00 00 00 00 00 05 68 65 6c 6c 6f 00 00 00 00 00 00 00 05 77 6f 72 6c 64
//              (26 bytes total)
//   SHA-256(preimage) = 2e3babebf8f4063be0a8da570523b3355e0d8f1010cb1ad8c67f5f2c3ab7e787... (script output above; 64 hex chars)
//   first 24 hex chars = 2e3babebf8f4063be0a8da57
//   candidate = "oxb-2e3babebf8f4063be0a8da57" (matches `expectedBoundary` below byte-for-byte)
//   Neither "hello"/text-part headers nor "world"/file-part headers contain this candidate
//   substring, so the collision scan is a no-op and the final boundary equals the candidate.

export type MultipartPartSpec = {
  readonly name: string;
  readonly filename?: string;
  readonly contentType: string;
  readonly payloadAscii: string;
};

export type MultipartBodyVector = {
  readonly cite: string;
  readonly description: string;
  readonly representation: "ascii-string";
  readonly parts: readonly MultipartPartSpec[];
  readonly expectedBoundary: string;
  readonly expectedContentTypeHeader: string;
  /** Explicit \r\n; tests TextEncoder-encode this string to get the wire bytes. */
  readonly expectedBody: string;
};

export const MULTIPART_BODY_VECTORS: readonly MultipartBodyVector[] = [
  {
    cite: "frozen contract",
    description:
      "Two-part body: a text field (name only, Content-Type: text/plain) and a file field " +
      "(name + filename, Content-Type: application/octet-stream). No collision — the " +
      "computed candidate is used verbatim as the boundary.",
    representation: "ascii-string",
    parts: [
      { name: "field1", contentType: "text/plain", payloadAscii: "hello" },
      {
        name: "file1",
        filename: "a.txt",
        contentType: "application/octet-stream",
        payloadAscii: "world",
      },
    ],
    expectedBoundary: "oxb-2e3babebf8f4063be0a8da57",
    expectedContentTypeHeader: "multipart/form-data; boundary=oxb-2e3babebf8f4063be0a8da57",
    expectedBody:
      "--oxb-2e3babebf8f4063be0a8da57\r\n" +
      'Content-Disposition: form-data; name="field1"\r\n' +
      "Content-Type: text/plain\r\n" +
      "\r\n" +
      "hello\r\n" +
      "--oxb-2e3babebf8f4063be0a8da57\r\n" +
      'Content-Disposition: form-data; name="file1"; filename="a.txt"\r\n' +
      "Content-Type: application/octet-stream\r\n" +
      "\r\n" +
      "world\r\n" +
      "--oxb-2e3babebf8f4063be0a8da57--",
  },
  {
    cite: "frozen contract",
    description:
      'Boundary-collision case: payloads "hi"/"ok" hash to candidate ' +
      "oxb-5fec25a323ed462b87da0fb3, and the file part's caller-supplied filename is " +
      "engineered to contain that exact candidate substring " +
      '("oxb-5fec25a323ed462b87da0fb3-evil.bin"). Because headers are scanned but never ' +
      "hashed, the hash is unaffected but the collision scan finds the candidate inside part " +
      '2\'s Content-Disposition header line, so the encoder appends "-1" and rescans; the ' +
      'lengthened boundary "oxb-5fec25a323ed462b87da0fb3-1" does not itself occur anywhere in ' +
      "either encapsulated part, so the scan stops after one iteration.",
    representation: "ascii-string",
    parts: [
      { name: "field1", contentType: "text/plain", payloadAscii: "hi" },
      {
        name: "file1",
        filename: "oxb-5fec25a323ed462b87da0fb3-evil.bin",
        contentType: "application/octet-stream",
        payloadAscii: "ok",
      },
    ],
    expectedBoundary: "oxb-5fec25a323ed462b87da0fb3-1",
    expectedContentTypeHeader: "multipart/form-data; boundary=oxb-5fec25a323ed462b87da0fb3-1",
    expectedBody:
      "--oxb-5fec25a323ed462b87da0fb3-1\r\n" +
      'Content-Disposition: form-data; name="field1"\r\n' +
      "Content-Type: text/plain\r\n" +
      "\r\n" +
      "hi\r\n" +
      "--oxb-5fec25a323ed462b87da0fb3-1\r\n" +
      'Content-Disposition: form-data; name="file1"; filename="oxb-5fec25a323ed462b87da0fb3-evil.bin"\r\n' +
      "Content-Type: application/octet-stream\r\n" +
      "\r\n" +
      "ok\r\n" +
      "--oxb-5fec25a323ed462b87da0fb3-1--",
  },
];

// --- Content-Disposition `name` vectors (the frozen contract) ---
// `name` carries the exact UTF-8 form field name as a quoted string with quoted-pair
// escaping for `"` and `\` ONLY (nothing else is escaped) — this is a completely different
// algorithm from `filename`'s percent-encoding below, per the frozen contract's explicit "different
// algorithms" callout, because RFC 7578 treats the two parameters differently.

export type ContentDispositionNameVector = {
  readonly cite: string;
  readonly description: string;
  readonly fieldName: string;
  /** When true, generation fails with a named diagnostic and no wire bytes are produced. */
  readonly expectGenerationDiagnostic?: true;
  /** The exact `Content-Disposition` header value, only present when there is no diagnostic. */
  readonly expectedHeaderValue?: string;
};

export const CONTENT_DISPOSITION_NAME_VECTORS: readonly ContentDispositionNameVector[] = [
  {
    cite: "frozen contract",
    description: "Plain field name, no characters requiring quoted-pair escaping.",
    fieldName: "field1",
    expectedHeaderValue: 'Content-Disposition: form-data; name="field1"',
  },
  {
    cite: "frozen contract",
    description:
      "Field name containing both a double-quote and a backslash: only those two " +
      'characters are quoted-pair escaped (" -> \\", \\ -> \\\\), nothing else is touched.',
    fieldName: 'a"b\\c',
    expectedHeaderValue: 'Content-Disposition: form-data; name="a\\"b\\\\c"',
  },
  {
    cite: "frozen contract",
    description:
      "Field name containing a control character (LF) is unrepresentable as a quoted " +
      "string without alteration, so it is a generation diagnostic — the server must always " +
      "observe the original OpenAPI property name, never a percent-mangled substitute, so " +
      "the encoder fails generation instead of lossily encoding it.",
    fieldName: "bad\nname",
    expectGenerationDiagnostic: true,
  },
];

// --- `filename` vectors (the frozen contract, RFC 7578 injective percent policy) ---
// ASCII printable except `%`, `"`, `\` passes through raw; `%` -> %25; `"` -> %22; `\` -> %5C;
// every C0 control (including NUL) and DEL (0x7F) is percent-encoded; every non-ASCII UTF-8
// BYTE is percent-encoded with UPPERCASE hex; `filename*` is never emitted. Because `%`, `"`,
// and `\` are themselves always percent-encoded away, the encoded result never contains a raw
// `"` or `\`, so — unlike `name` above — no further quoted-string escaping is layered on top:
// the encoded text is embedded directly between the surrounding quotes.

export type FilenameVector = {
  readonly cite: string;
  readonly description: string;
  readonly filename: string;
  /** The full `filename="..."` Content-Disposition parameter, percent-encoded per RFC 7578. */
  readonly expectedFilenameParam: string;
};

export const FILENAME_VECTORS: readonly FilenameVector[] = [
  {
    cite: "frozen contract",
    description: "Plain filename, no characters requiring percent-encoding.",
    filename: "report.pdf",
    expectedFilenameParam: 'filename="report.pdf"',
  },
  {
    cite: "frozen contract",
    description:
      'Filename containing a literal double-quote character: only the two `"` occurrences ' +
      "are percent-encoded (-> %22); every other character passes through raw.",
    filename: 'say"hi".txt',
    expectedFilenameParam: 'filename="say%22hi%22.txt"',
  },
  {
    cite: "frozen contract",
    description:
      'Filename containing the literal 3-character text "%22" (not a quote character, the ' +
      "literal percent-two-two text) as a DIFFERENT input from the previous vector: only the " +
      '"%" is percent-encoded (-> %25), so "%22" becomes the 5-character output "%2522" ' +
      '(%25 + literal "22"). Compared against the previous vector this proves the policy is ' +
      'injective — "say\\"hi\\".txt" and "say%22hi%22.txt" never collide on the wire.',
    filename: "say%22hi%22.txt",
    expectedFilenameParam: 'filename="say%2522hi%2522.txt"',
  },
  {
    cite: "frozen contract",
    description: '"%" alone.',
    filename: "%",
    expectedFilenameParam: 'filename="%25"',
  },
  {
    cite: "frozen contract",
    description: "NUL (0x00), a C0 control.",
    filename: "\u0000",
    expectedFilenameParam: 'filename="%00"',
  },
  {
    cite: "frozen contract",
    description: "HTAB (0x09), a C0 control.",
    filename: "\u0009",
    expectedFilenameParam: 'filename="%09"',
  },
  {
    cite: "frozen contract",
    description: "DEL (0x7F), percent-encoded alongside the C0 controls per the frozen contract.",
    filename: "\u007F",
    expectedFilenameParam: 'filename="%7F"',
  },
  {
    cite: "frozen contract",
    description:
      'Non-ASCII filename "résumé.pdf": each non-ASCII UTF-8 byte is percent-encoded with ' +
      "uppercase hex. é is U+00E9; its UTF-8 encoding is the 2 bytes 0xC3 0xA9 (2-byte form " +
      "110xxxxx 10xxxxxx over the low 11 bits of 0x00E9 = 000_1110_1001 -> 0xC3, 0xA9), so " +
      "each of the two é occurrences becomes %C3%A9; the ASCII letters r/s/u/m/./p/d/f pass through raw.",
    filename: "résumé.pdf",
    expectedFilenameParam: 'filename="r%C3%A9sum%C3%A9.pdf"',
  },
  {
    cite: "frozen contract",
    description: "Empty filename.",
    filename: "",
    expectedFilenameParam: 'filename=""',
  },
];
