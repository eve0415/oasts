// Hand-derived parameter-style serialization vectors gating the client conformance gate for the
// oasts client artifact. NEVER regenerate these from implementation output — every
// expected value below is derived from the frozen contract ("Oasts implements OpenAPI
// defaults and declared `style`, `explode`, and `allowReserved` behavior for path, query,
// and header parameters: `form`, `simple`, `label`, `matrix`, `spaceDelimited`,
// `pipeDelimited`, and `deepObject`") plus the OpenAPI 3.1 Parameter Object serialization
// table, which itself follows RFC 6570 (URI Template) semantics for the RFC-backed styles:
//
//   - path/simple   -> RFC 6570 §3.2.2 Simple String Expansion (unnamed, no operator)
//   - path/label    -> RFC 6570 §3.2.5 Label Expansion with Dot-Prefix ({.var})
//   - path/matrix   -> RFC 6570 §3.2.7 Path-Style Parameter Expansion ({;var}) — RFC 6570
//                      calls this style "path-style"; OpenAPI names the same operator "matrix"
//   - query/form    -> RFC 6570 §3.2.9 Form-Style Query Continuation ({&var}), NOT §3.2.8
//                      (§3.2.8 is the *first* query parameter with a leading "?"; §3.2.9 is
//                      every subsequent "name=value" fragment joined by "&" with no leading
//                      "?" — that is exactly the single-parameter fragment this file's
//                      `expected` field records, per the task contract's "id=3&id=4" example)
//   - header/simple -> RFC 6570 §3.2.2, identical algorithm to path/simple; a header value
//                      carries no leading separator either way
//
// `spaceDelimited`, `pipeDelimited`, and `deepObject` have NO RFC 6570 operator — they are
// OpenAPI-only inventions layered on top of the same percent-encoding semantics.
//
// Percent-encoding is RFC 3986 with UPPERCASE hex digits throughout. The structural
// characters a style's own algorithm introduces (the "," joining a non-exploded array/object,
// the "&"/"=" of form-explode, the leading "." of label, the ";"/"=" of matrix, and the
// "[","]" of deepObject) are NEVER percent-encoded — they are wire syntax, not data, exactly
// as RFC 6570's own operators never escape their own literal/prefix/separator characters.
// Only the actual VALUE substrings are subject to percent-encoding, gated by `allowReserved`
// for query parameters only (`allowReserved` "only applies to parameters with an in value of
// query" per the OpenAPI Parameter Object). For path/label/matrix/header locations
// `allowReserved` is structurally inapplicable, so every such vector below carries
// `allowReserved: false` uniformly per the task's authoring contract.
//
// allowReserved algorithm (both branches percent-encode with uppercase hex):
//   - false (default): every octet outside RFC 3986 "unreserved" (ALPHA / DIGIT / "-" / "."
//     / "_" / "~") is percent-encoded — this includes every RFC 3986 reserved character
//     (gen-delims ":/?#[]@" and sub-delims "!$&'()*+,;=") appearing IN THE VALUE, plus space,
//     "%", and every non-ASCII UTF-8 byte.
//   - true: RFC 3986 reserved characters (gen-delims ∪ sub-delims) pass through raw when they
//     appear in the value, but space, "%", and non-ASCII bytes are still percent-encoded,
//     because none of those three is a member of gen-delims ∪ sub-delims — allowReserved only
//     ever widens the untouched set to "unreserved ∪ reserved", never further.
//
// Two resolved ambiguities (the frozen contract states the RFC 6570 style table applies but does not
// itself spell out these two byte-level questions; both are resolved below rather than copied
// verbatim from OpenAPI's own — non-normative, illustrative-only — worked examples):
//
//   1. pipeDelimited's "|" join character. OpenAPI's own worked example table shows
//      "color=3|4|5" with the pipe left raw, but "|" is a member of neither RFC 3986
//      gen-delims nor sub-delims, so it is — like space — always outside "unreserved ∪
//      reserved" and must always be percent-encoded (%7C) to be a conformant query
//      component, independent of allowReserved (which only ever un-escapes the reserved set).
//      This file treats pipeDelimited's separator as %7C, not raw "|", because the encoder
//      commits to RFC 3986 conformance rather than OpenAPI's illustrative table.
//   2. header value percent-encoding. HTTP header field values are not URI components, so no
//      percent-encoding step applies to them at all — `header`/`simple` vectors below use
//      exactly the same structural join algorithm as `path`/`simple` (comma/equals joining)
//      with no percent-encoding layered on top. None of the sample values used for header
//      vectors contain characters that would make this distinction visible, so it does not
//      change any expected string here, but it is the encoder's implied behavior this file
//      assumes and future header reserved-character vectors would need to confirm.
//
// Sample values are held constant across the whole style/explode/location matrix so every
// cell is directly comparable: primitive "blue", array ["blue", "black"], object
// { R: 100, G: 200 } — matching the shape (not the literal content) of OpenAPI's own
// Parameter Object examples ("blue", ["blue","black","brown"], {"R":100,"G":200,"B":150}).

export type StyleLocation = "path" | "query" | "header";

export type StyleName =
  | "simple"
  | "label"
  | "matrix"
  | "form"
  | "spaceDelimited"
  | "pipeDelimited"
  | "deepObject";

export type JsonPrimitive = string | number | boolean;
export type StyleValue =
  | JsonPrimitive
  | readonly JsonPrimitive[]
  | Readonly<Record<string, JsonPrimitive>>;

export type StyleVector = {
  readonly cite: string;
  readonly location: StyleLocation;
  readonly style: StyleName;
  readonly explode: boolean;
  readonly allowReserved: boolean;
  readonly paramName: string;
  readonly value: StyleValue;
  readonly expected: string;
};

const PRIMITIVE: StyleValue = "blue";
const ARRAY: StyleValue = ["blue", "black"];
const OBJECT: StyleValue = { R: 100, G: 200 };

export const STYLE_VECTORS: readonly StyleVector[] = [
  // --- path / simple (RFC 6570 §3.2.2 simple string expansion) ---
  {
    cite: "RFC 6570 §3.2.2",
    location: "path",
    style: "simple",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: PRIMITIVE,
    expected: "blue",
  },
  {
    cite: "RFC 6570 §3.2.2",
    location: "path",
    style: "simple",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: ARRAY,
    expected: "blue,black",
  },
  {
    cite: "RFC 6570 §3.2.2",
    location: "path",
    style: "simple",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: OBJECT,
    expected: "R,100,G,200",
  },
  // explode=true does not change array joining under simple (no per-item separator exists
  // beyond the comma the style itself always uses); it changes ONLY object serialization
  // (each entry becomes key=value, comma-joined, no flattening) — this asymmetry is the
  // whole point of exercising both explode states here.
  {
    cite: "RFC 6570 §3.2.2",
    location: "path",
    style: "simple",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: PRIMITIVE,
    expected: "blue",
  },
  {
    cite: "RFC 6570 §3.2.2",
    location: "path",
    style: "simple",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: ARRAY,
    expected: "blue,black",
  },
  {
    cite: "RFC 6570 §3.2.2",
    location: "path",
    style: "simple",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: OBJECT,
    expected: "R=100,G=200",
  },

  // --- path / label (RFC 6570 §3.2.5 label expansion with dot-prefix) ---
  {
    cite: "RFC 6570 §3.2.5",
    location: "path",
    style: "label",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: PRIMITIVE,
    expected: ".blue",
  },
  {
    cite: "RFC 6570 §3.2.5",
    location: "path",
    style: "label",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: ARRAY,
    expected: ".blue,black",
  },
  {
    cite: "RFC 6570 §3.2.5",
    location: "path",
    style: "label",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: OBJECT,
    expected: ".R,100,G,200",
  },
  {
    cite: "RFC 6570 §3.2.5",
    location: "path",
    style: "label",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: PRIMITIVE,
    expected: ".blue",
  },
  // explode=true repeats the dot-prefix per array element (no comma at all between elements).
  {
    cite: "RFC 6570 §3.2.5",
    location: "path",
    style: "label",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: ARRAY,
    expected: ".blue.black",
  },
  {
    cite: "RFC 6570 §3.2.5",
    location: "path",
    style: "label",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: OBJECT,
    expected: ".R=100.G=200",
  },

  // --- path / matrix (RFC 6570 §3.2.7 path-style parameter expansion; OpenAPI calls it "matrix") ---
  {
    cite: "RFC 6570 §3.2.7",
    location: "path",
    style: "matrix",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: PRIMITIVE,
    expected: ";color=blue",
  },
  {
    cite: "RFC 6570 §3.2.7",
    location: "path",
    style: "matrix",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: ARRAY,
    expected: ";color=blue,black",
  },
  {
    cite: "RFC 6570 §3.2.7",
    location: "path",
    style: "matrix",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: OBJECT,
    expected: ";color=R,100,G,200",
  },
  {
    cite: "RFC 6570 §3.2.7",
    location: "path",
    style: "matrix",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: PRIMITIVE,
    expected: ";color=blue",
  },
  // explode=true repeats ";color=" per array element.
  {
    cite: "RFC 6570 §3.2.7",
    location: "path",
    style: "matrix",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: ARRAY,
    expected: ";color=blue;color=black",
  },
  // explode=true drops the outer "color" name for objects: each property becomes its own ;key=value.
  {
    cite: "RFC 6570 §3.2.7",
    location: "path",
    style: "matrix",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: OBJECT,
    expected: ";R=100;G=200",
  },

  // --- query / form (RFC 6570 §3.2.9 form-style query continuation; default query style) ---
  {
    cite: "RFC 6570 §3.2.9",
    location: "query",
    style: "form",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: PRIMITIVE,
    expected: "color=blue",
  },
  {
    cite: "RFC 6570 §3.2.9",
    location: "query",
    style: "form",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: ARRAY,
    expected: "color=blue,black",
  },
  {
    cite: "RFC 6570 §3.2.9",
    location: "query",
    style: "form",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: OBJECT,
    expected: "color=R,100,G,200",
  },
  {
    cite: "RFC 6570 §3.2.9",
    location: "query",
    style: "form",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: PRIMITIVE,
    expected: "color=blue",
  },
  // explode=true repeats "color=" per array element, joined by "&" (this is the task's own
  // "id=3&id=4" example shape).
  {
    cite: "RFC 6570 §3.2.9",
    location: "query",
    style: "form",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: ARRAY,
    expected: "color=blue&color=black",
  },
  // explode=true drops the outer "color" name for objects: each property becomes its own key=value.
  {
    cite: "RFC 6570 §3.2.9",
    location: "query",
    style: "form",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: OBJECT,
    expected: "R=100&G=200",
  },

  // --- query / spaceDelimited (array only, explode=false only; OpenAPI-only, no RFC 6570 operator) ---
  // The space join character is outside unreserved ∪ reserved, so it is percent-encoded to
  // %20 regardless of allowReserved (OpenAPI's own example table already shows this: "color=3%204%205").
  {
    cite: "frozen contract",
    location: "query",
    style: "spaceDelimited",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: ARRAY,
    expected: "color=blue%20black",
  },

  // --- query / pipeDelimited (array only, explode=false only; OpenAPI-only, no RFC 6570 operator) ---
  // Resolved ambiguity #1 above: "|" is outside unreserved ∪ reserved, so it is percent-encoded
  // to %7C, unlike OpenAPI's own (non-normative) "color=3|4|5" worked example.
  {
    cite: "frozen contract",
    location: "query",
    style: "pipeDelimited",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: ARRAY,
    expected: "color=blue%7Cblack",
  },

  // --- query / deepObject (object only, explode=true only; OpenAPI-only, no RFC 6570 operator) ---
  // "[" and "]" are structural style syntax (like "," or "&" elsewhere), never percent-encoded.
  {
    cite: "frozen contract",
    location: "query",
    style: "deepObject",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: OBJECT,
    expected: "color[R]=100&color[G]=200",
  },

  // --- query / form reserved-character + allowReserved matrix ---
  // Value = the literal 9 characters "/?#[]@&= " (8 RFC 3986 reserved characters + a space),
  // covering every gen-delim/sub-delim the task names plus the always-encoded space, in a
  // single primitive under both allowReserved states.
  //   allowReserved=false: every one of the 9 characters is outside "unreserved", so all 9
  //     are percent-encoded: / -> %2F, ? -> %3F, # -> %23, [ -> %5B, ] -> %5D, @ -> %40,
  //     & -> %26, = -> %3D, space -> %20.
  {
    cite: "frozen contract",
    location: "query",
    style: "form",
    explode: false,
    allowReserved: false,
    paramName: "value",
    value: "/?#[]@&= ",
    expected: "value=%2F%3F%23%5B%5D%40%26%3D%20",
  },
  //   allowReserved=true: the 8 reserved characters pass through raw; the space is still
  //     outside unreserved ∪ reserved and stays percent-encoded (%20).
  {
    cite: "frozen contract",
    location: "query",
    style: "form",
    explode: false,
    allowReserved: true,
    paramName: "value",
    value: "/?#[]@&= ",
    expected: "value=/?#[]@&=%20",
  },
  // Non-ASCII value "café": 'c','a','f' are unreserved ASCII and stay raw; é is U+00E9, whose
  // UTF-8 encoding is the 2 bytes 0xC3 0xA9 (U+00E9 = 0b0000_0000_1110_1001; a 2-byte UTF-8
  // sequence is 110xxxxx 10xxxxxx over the low 11 bits 000_1110_1001 -> byte1 = 110_00011 =
  // 0xC3, byte2 = 10_101001 = 0xA9), each percent-encoded with uppercase hex: %C3%A9.
  // Non-ASCII bytes are outside unreserved ∪ reserved, so this result is IDENTICAL under both
  // allowReserved states — allowReserved only ever widens the untouched set to include the
  // RFC 3986 reserved characters, never non-ASCII bytes.
  {
    cite: "frozen contract",
    location: "query",
    style: "form",
    explode: false,
    allowReserved: false,
    paramName: "value",
    value: "café",
    expected: "value=caf%C3%A9",
  },
  {
    cite: "frozen contract",
    location: "query",
    style: "form",
    explode: false,
    allowReserved: true,
    paramName: "value",
    value: "café",
    expected: "value=caf%C3%A9",
  },
  // "%" itself (0x25) is outside unreserved ∪ reserved (it is not a gen-delim or sub-delim),
  // so it is always percent-encoded to %25 regardless of allowReserved — this is the "%" case
  // named alongside space and non-ASCII in the allowReserved=true carve-out.
  {
    cite: "frozen contract",
    location: "query",
    style: "form",
    explode: false,
    allowReserved: false,
    paramName: "value",
    value: "100%",
    expected: "value=100%25",
  },
  {
    cite: "frozen contract",
    location: "query",
    style: "form",
    explode: false,
    allowReserved: true,
    paramName: "value",
    value: "100%",
    expected: "value=100%25",
  },

  // --- header / simple (RFC 6570 §3.2.2, identical algorithm to path/simple; no percent-encoding — resolved ambiguity #2 above) ---
  {
    cite: "RFC 6570 §3.2.2",
    location: "header",
    style: "simple",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: PRIMITIVE,
    expected: "blue",
  },
  {
    cite: "RFC 6570 §3.2.2",
    location: "header",
    style: "simple",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: ARRAY,
    expected: "blue,black",
  },
  {
    cite: "RFC 6570 §3.2.2",
    location: "header",
    style: "simple",
    explode: false,
    allowReserved: false,
    paramName: "color",
    value: OBJECT,
    expected: "R,100,G,200",
  },
  {
    cite: "RFC 6570 §3.2.2",
    location: "header",
    style: "simple",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: PRIMITIVE,
    expected: "blue",
  },
  {
    cite: "RFC 6570 §3.2.2",
    location: "header",
    style: "simple",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: ARRAY,
    expected: "blue,black",
  },
  {
    cite: "RFC 6570 §3.2.2",
    location: "header",
    style: "simple",
    explode: true,
    allowReserved: false,
    paramName: "color",
    value: OBJECT,
    expected: "R=100,G=200",
  },
];
