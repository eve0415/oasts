// Regions are ordered as oxs:core followed by byte-lexicographically sorted helper ids;
// the Rust embedding engine preserves this exact order when emitting any helper subset.

//#region oxs:core
export type ParamPrimitive = string | number | boolean | bigint;
export type ParamValue =
  | ParamPrimitive
  | readonly ParamPrimitive[]
  | Readonly<Record<string, ParamPrimitive>>;

type ComponentPolicy = boolean | null;

const UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
const RESERVED = ":/?#[]@!$&'()*+,;=";
const TCHAR = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~";
const TOKEN_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const QDTEXT_PATTERN = /^[\t\x20\x21\x23-\x5b\x5d-\x7e\u0080-\u00ff]$/u;
const QUOTED_PAIR_PATTERN = /^[\t\x20-\x7e\u0080-\u00ff]$/u;
const SAFE_PARAMETER_VALUE_PATTERN = /^[\x20-\x7e]*$/u;
const UTF8_ENCODER = new TextEncoder();

export class EncodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EncodeError";
  }
}

export function encodeComponent(
  text: string,
  allowReserved: boolean,
): string {
  let encoded = "";

  for (const byte of UTF8_ENCODER.encode(text)) {
    const character = String.fromCharCode(byte);
    if (
      UNRESERVED.includes(character) ||
      (allowReserved && RESERVED.includes(character))
    ) {
      encoded += character;
    } else {
      encoded += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    }
  }

  return encoded;
}

function isParamArray(value: ParamValue): value is readonly ParamPrimitive[] {
  return Array.isArray(value);
}

function isParamObject(
  value: ParamValue,
): value is Readonly<Record<string, ParamPrimitive>> {
  return typeof value === "object" && !Array.isArray(value);
}

function renderComponent(text: string, policy: ComponentPolicy): string {
  return policy === null ? text : encodeComponent(text, policy);
}

function renderPrimitive(
  value: ParamPrimitive,
  policy: ComponentPolicy,
): string {
  return renderComponent(String(value), policy);
}

function renderName(name: string): string {
  return encodeComponent(name, false);
}

function serializeSimpleValue(
  value: ParamValue,
  explode: boolean,
  policy: ComponentPolicy,
): string {
  if (isParamArray(value)) {
    return value.map((item) => renderPrimitive(item, policy)).join(",");
  }
  if (isParamObject(value)) {
    return Object.entries(value)
      .map(([key, item]) =>
        explode
          ? `${renderComponent(key, policy)}=${renderPrimitive(item, policy)}`
          : `${renderComponent(key, policy)},${renderPrimitive(item, policy)}`,
      )
      .join(",");
  }
  return renderPrimitive(value, policy);
}

function serializeQueryFormValue(
  name: string,
  value: ParamValue,
  explode: boolean,
  allowReserved: boolean,
): string {
  const encodedName = renderName(name);
  if (!explode) {
    return `${encodedName}=${serializeSimpleValue(value, false, allowReserved)}`;
  }
  if (isParamArray(value)) {
    return value
      .map(
        (item) =>
          `${encodedName}=${renderPrimitive(item, allowReserved)}`,
      )
      .join("&");
  }
  if (isParamObject(value)) {
    return Object.entries(value)
      .map(
        ([key, item]) =>
          `${renderComponent(key, allowReserved)}=${renderPrimitive(item, allowReserved)}`,
      )
      .join("&");
  }
  return `${encodedName}=${renderPrimitive(value, allowReserved)}`;
}

function serializeDelimitedQueryValue(
  name: string,
  value: readonly ParamPrimitive[],
  separator: "%20" | "%7C",
  allowReserved: boolean,
): string {
  return `${renderName(name)}=${value
    .map((item) => renderPrimitive(item, allowReserved))
    .join(separator)}`;
}

function serializeDeepObjectValue(
  name: string,
  value: Readonly<Record<string, ParamPrimitive>>,
  allowReserved: boolean,
): string {
  const encodedName = renderName(name);
  return Object.entries(value)
    .map(
      ([key, item]) =>
        `${encodedName}[${renderComponent(key, allowReserved)}]=${renderPrimitive(item, allowReserved)}`,
    )
    .join("&");
}

// Bracket-path encoding, dispatched on the value's shape: `p[key]=v` for an object — the form
// OpenAPI defines — `p[0]=v` for an array, and `p=v` for a scalar, which has no nesting to bracket
// and so is the same rule at depth zero. Measured against `qs.stringify`, the library `deepObject`
// is modelled on. Only the object form is specified, so the generator admits the other shapes only
// under `compat.deepObjectEncoding: "extended"`.
function serializeDeepObjectDispatched(
  name: string,
  value: ParamValue,
  allowReserved: boolean,
): string {
  if (isParamArray(value)) {
    const encodedName = renderName(name);
    return value
      .map(
        (item, index) =>
          `${encodedName}[${index}]=${renderPrimitive(item, allowReserved)}`,
      )
      .join("&");
  }
  if (isParamObject(value)) {
    return serializeDeepObjectValue(name, value, allowReserved);
  }
  return `${renderName(name)}=${renderPrimitive(value, allowReserved)}`;
}

function consumeToken(input: string, start: number): number {
  let index = start;
  // The length check runs first, so charAt is only ever asked for an in-range index — which matters
  // because `includes("")` is true for every string and would otherwise never terminate.
  while (index < input.length && TCHAR.includes(input.charAt(index))) {
    index += 1;
  }
  return index;
}

function consumeOws(input: string, start: number): number {
  let index = start;
  while (input[index] === " " || input[index] === "\t") {
    index += 1;
  }
  return index;
}

function isToken(value: string): boolean {
  return TOKEN_PATTERN.test(value);
}

function compareAsciiBytes(left: string, right: string): number {
  const sharedLength = Math.min(left.length, right.length);
  for (let index = 0; index < sharedLength; index += 1) {
    const difference = left.charCodeAt(index) - right.charCodeAt(index);
    if (difference !== 0) {
      return difference;
    }
  }
  return left.length - right.length;
}

function escapeMultipartName(name: string): string {
  for (const byte of UTF8_ENCODER.encode(name)) {
    if (byte < 0x20 || byte === 0x7f) {
      throw new EncodeError("multipart field name contains a control byte");
    }
  }

  return name.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

function encodeMultipartFilenameValue(filename: string): string {
  let encoded = "";

  for (const byte of UTF8_ENCODER.encode(filename)) {
    if (
      byte >= 0x20 &&
      byte <= 0x7e &&
      byte !== 0x25 &&
      byte !== 0x22 &&
      byte !== 0x5c
    ) {
      encoded += String.fromCharCode(byte);
    } else {
      encoded += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    }
  }

  return encoded;
}
// The multipart response decoding plan, declared here rather than beside the decoder in its own
// helper region: transport.ts type-imports it unconditionally, so a client that selects no
// multipart helper would otherwise import a name its serialize.ts no longer declares. Types are
// erased, so carrying them in core costs an emitted client nothing.
//
// How a part decodes is fixed at generation time from the declared schema, not sniffed from the
// wire, because the decoded value has to inhabit the TypeScript type the same schema produced. The
// one exception is `"wire"`, emitted where the schema constrains nothing and the property type is
// therefore `unknown`: there the part's own `Content-Type` decides, defaulting to `text/plain`
// (RFC 7578 §4.4).
export type MultipartResponsePayload = "json" | "text" | "binary" | "wire";

export type MultipartResponsePartShape = {
  readonly payload: MultipartResponsePayload;
  // True when the property's schema is an array: every part carrying this name contributes one
  // element, in wire order, and a single occurrence still decodes to a one-element array.
  readonly repeated: boolean;
};

export type MultipartResponsePartPlan = MultipartResponsePartShape & {
  readonly name: string;
};

export type MultipartResponsePlan = {
  readonly parts: readonly MultipartResponsePartPlan[];
  // The shape a part whose name matches no declared property decodes under: the schema's
  // `additionalProperties`, or the wire-classified fallback when the schema omits or closes it.
  readonly additional: MultipartResponsePartShape;
};
//#endregion

//#region oxs:helper:content-json-header
export function serializeContentJsonHeader(
  _name: string,
  value: unknown,
  _allowReserved: boolean,
): string {
  // Content JSON header parameter: the JSON text is the simple-style header value, emitted verbatim
  // with no component encoding (the `null` policy).
  return serializeSimpleValue(contentJsonString(value), false, null);
}
//#endregion

//#region oxs:helper:content-json-path
export function serializeContentJsonPath(
  _name: string,
  value: unknown,
  _allowReserved: boolean,
): string {
  // Content JSON path parameter: the JSON text is percent-encoded as a single path segment (the
  // simple-style `false` policy), with no name prefix.
  return serializeSimpleValue(contentJsonString(value), false, false);
}
//#endregion

//#region oxs:helper:content-json-query
export function serializeContentJsonQuery(
  name: string,
  value: unknown,
  _allowReserved: boolean,
): string {
  // Content JSON query parameter: the JSON text becomes one `name=value` pair whose value takes the
  // component encoding form query values use.
  return serializeQueryFormValue(name, contentJsonString(value), false, false);
}
//#endregion

//#region oxs:helper:content-json-value
// The JSON text a content-sourced parameter (OpenAPI Parameter Object `content` with a JSON-family
// media type) puts on the wire before location encoding. `JSON.stringify` returns `undefined` for a
// value it cannot represent (a function, a symbol, or bare `undefined`); the caller-facing types
// never admit those, but the guard turns a would-be `undefined` wire value into a clear failure.
function contentJsonString(value: unknown): string {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) {
    throw new TypeError("content parameter value is not JSON-serializable");
  }
  return serialized;
}
//#endregion

//#region oxs:helper:form-urlencoded-body
export type UrlencodedStyleField = {
  readonly name: string;
  readonly value: ParamValue;
  readonly style?: "form" | "spaceDelimited" | "pipeDelimited" | "deepObject";
  readonly explode?: boolean;
  readonly allowReserved?: boolean;
};

// Discriminated by property presence (`"json" in field`) rather than a `kind` tag like every other
// descriptor union: a tag string would ship in the descriptor bytes of every generated client, and
// these urlencoded field descriptors are emitted per field. Size over the tagging convention, on
// purpose. `UrlencodedFieldPlan` in transport.ts makes the same tradeoff (`"payloads" in`).
export type UrlencodedField =
  | UrlencodedStyleField
  | {
      readonly name: string;
      readonly json: unknown;
    };

export function encodeFormUrlencodedBody(
  fields: readonly UrlencodedField[],
): string {
  return fields
    .map((field) => {
      if ("json" in field) {
        // OAS 3.1.1: urlencoded bodies serialize complex objects to a string (JSON) before RFC1866
        // percent-encoding; JSON.stringify returns undefined for values it cannot represent.
        const serialized = JSON.stringify(field.json);
        if (serialized === undefined) {
          throw new TypeError(`json form field ${field.name} is not serializable`);
        }
        return `${renderName(field.name)}=${encodeComponent(serialized, false)}`;
      }
      const style = field.style ?? "form";
      const explode = field.explode ?? true;
      const allowReserved = field.allowReserved ?? false;

      if (style === "form") {
        return serializeQueryFormValue(
          field.name,
          field.value,
          explode,
          allowReserved,
        );
      }
      if (style === "spaceDelimited") {
        if (!isParamArray(field.value)) {
          throw new TypeError("spaceDelimited fields require an array value");
        }
        return serializeDelimitedQueryValue(
          field.name,
          field.value,
          "%20",
          allowReserved,
        );
      }
      if (style === "pipeDelimited") {
        if (!isParamArray(field.value)) {
          throw new TypeError("pipeDelimited fields require an array value");
        }
        return serializeDelimitedQueryValue(
          field.name,
          field.value,
          "%7C",
          allowReserved,
        );
      }
      // A field only ever holds a non-object value under `compat.deepObjectEncoding: "extended"`,
      // where the generator has already admitted the shape; under the strict default the schema is
      // object-only, so the dispatch takes its object branch and the wire bytes are unchanged.
      return serializeDeepObjectDispatched(
        field.name,
        field.value,
        allowReserved,
      );
    })
    .join("&");
}
//#endregion

//#region oxs:helper:header-simple
export function serializeHeaderSimple(
  _name: string,
  value: ParamValue,
  _allowReserved: boolean,
): string {
  return serializeSimpleValue(value, false, null);
}
//#endregion

//#region oxs:helper:header-simple-explode
export function serializeHeaderSimpleExplode(
  _name: string,
  value: ParamValue,
  _allowReserved: boolean,
): string {
  return serializeSimpleValue(value, true, null);
}
//#endregion

//#region oxs:helper:media-canonical
export type ParsedMediaType = {
  readonly type: string;
  readonly subtype: string;
  readonly parameters: readonly (readonly [string, string])[];
};

export function parseMediaType(input: string): ParsedMediaType | null {
  const typeEnd = consumeToken(input, 0);
  if (typeEnd === 0 || input[typeEnd] !== "/") {
    return null;
  }

  const subtypeStart = typeEnd + 1;
  const subtypeEnd = consumeToken(input, subtypeStart);
  if (subtypeEnd === subtypeStart) {
    return null;
  }

  const parameters: [string, string][] = [];
  const parameterNames = new Set<string>();
  let index = subtypeEnd;

  while (index < input.length) {
    index = consumeOws(input, index);
    if (index === input.length || input[index] !== ";") {
      return null;
    }
    index = consumeOws(input, index + 1);

    const nameStart = index;
    index = consumeToken(input, index);
    if (index === nameStart || input[index] !== "=") {
      return null;
    }
    const name = input.slice(nameStart, index).toLowerCase();
    index += 1;

    let value = "";
    const tokenEnd = consumeToken(input, index);
    if (tokenEnd > index) {
      value = input.slice(index, tokenEnd);
      index = tokenEnd;
    } else {
      if (input[index] !== '"') {
        return null;
      }
      index += 1;
      let closed = false;
      while (index < input.length) {
        // charAt over [] because the loop condition already proves the index is in range, and it
        // types as string rather than string | undefined without adding a check that never fires.
        const character = input.charAt(index);
        if (character === '"') {
          closed = true;
          index += 1;
          break;
        }
        if (character === "\\") {
          index += 1;
          const escaped = input[index];
          if (escaped === undefined || !QUOTED_PAIR_PATTERN.test(escaped)) {
            return null;
          }
          value += escaped;
          index += 1;
          continue;
        }
        if (!QDTEXT_PATTERN.test(character)) {
          return null;
        }
        value += character;
        index += 1;
      }
      if (!closed) {
        return null;
      }
    }

    if (!SAFE_PARAMETER_VALUE_PATTERN.test(value)) {
      return null;
    }
    if (parameterNames.has(name)) {
      return null;
    }
    parameterNames.add(name);
    parameters.push([name, name === "charset" ? value.toLowerCase() : value]);
  }

  parameters.sort(([left], [right]) => compareAsciiBytes(left, right));
  return {
    type: input.slice(0, typeEnd).toLowerCase(),
    subtype: input.slice(subtypeStart, subtypeEnd).toLowerCase(),
    parameters,
  };
}

export function serializeMediaType(parsed: ParsedMediaType): string {
  let serialized = `${parsed.type}/${parsed.subtype}`;
  for (const [name, value] of parsed.parameters) {
    const emittedValue = isToken(value)
      ? value
      : `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
    serialized += `; ${name}=${emittedValue}`;
  }
  return serialized;
}
//#endregion

//#region oxs:helper:multipart
export type MultipartPart = {
  readonly name: string;
  readonly payload: Uint8Array;
  readonly contentType?: string;
  readonly filename?: string;
};

export type MultipartBody = {
  readonly boundary: string;
  readonly contentTypeHeader: string;
  readonly body: Uint8Array;
};

function concatMultipartBytes(
  chunks: readonly Uint8Array[],
): Uint8Array<ArrayBuffer> {
  let length = 0;
  for (const chunk of chunks) {
    length += chunk.length;
  }

  const concatenated = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    concatenated.set(chunk, offset);
    offset += chunk.length;
  }
  return concatenated;
}

function buildEncapsulatedPart(part: MultipartPart): Uint8Array {
  let contentDisposition =
    `Content-Disposition: form-data; name="${escapeMultipartName(part.name)}"`;
  if (part.filename !== undefined) {
    contentDisposition +=
      `; filename="${encodeMultipartFilenameValue(part.filename)}"`;
  }

  const headerLines = [contentDisposition];
  if (part.contentType !== undefined) {
    headerLines.push(`Content-Type: ${part.contentType}`);
  }

  return concatMultipartBytes([
    UTF8_ENCODER.encode(`${headerLines.join("\r\n")}\r\n\r\n`),
    part.payload,
  ]);
}

function multipartBytesContain(
  bytes: Uint8Array,
  candidate: Uint8Array,
): boolean {
  const lastStart = bytes.length - candidate.length;
  for (let start = 0; start <= lastStart; start += 1) {
    let matches = true;
    for (let offset = 0; offset < candidate.length; offset += 1) {
      if (bytes[start + offset] !== candidate[offset]) {
        matches = false;
        break;
      }
    }
    if (matches) {
      return true;
    }
  }
  return false;
}

async function multipartBoundary(
  parts: readonly MultipartPart[],
  encapsulatedParts: readonly Uint8Array[],
): Promise<string> {
  const preimageChunks: Uint8Array[] = [];
  for (const part of parts) {
    const lengthPrefix = new Uint8Array(8);
    new DataView(lengthPrefix.buffer).setBigUint64(
      0,
      BigInt(part.payload.length),
    );
    preimageChunks.push(lengthPrefix, part.payload);
  }

  const digest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      concatMultipartBytes(preimageChunks),
    ),
  );
  let digestHex = "";
  for (const byte of digest) {
    digestHex += byte.toString(16).padStart(2, "0");
  }

  const candidate = `oxb-${digestHex.slice(0, 24)}`;
  let boundary = candidate;
  let suffix = 1;
  while (
    encapsulatedParts.some((part) =>
      multipartBytesContain(part, UTF8_ENCODER.encode(boundary)),
    )
  ) {
    boundary = `${candidate}-${suffix}`;
    suffix += 1;
  }
  return boundary;
}

function buildMultipartBody(
  boundary: string,
  encapsulatedParts: readonly Uint8Array[],
): Uint8Array {
  if (encapsulatedParts.length === 0) {
    return UTF8_ENCODER.encode(`--${boundary}--`);
  }

  // Iterated by value rather than by index, and the inter-part delimiter is encoded once instead
  // of once per part.
  const between = UTF8_ENCODER.encode(`\r\n--${boundary}\r\n`);
  const chunks: Uint8Array[] = [UTF8_ENCODER.encode(`--${boundary}\r\n`)];
  let first = true;
  for (const part of encapsulatedParts) {
    if (!first) {
      chunks.push(between);
    }
    chunks.push(part);
    first = false;
  }
  chunks.push(UTF8_ENCODER.encode(`\r\n--${boundary}--`));
  return concatMultipartBytes(chunks);
}

export async function encodeMultipart(
  parts: readonly MultipartPart[],
): Promise<MultipartBody> {
  const encapsulatedParts = parts.map(buildEncapsulatedPart);
  const boundary = await multipartBoundary(parts, encapsulatedParts);
  return {
    boundary,
    contentTypeHeader: `multipart/form-data; boundary=${boundary}`,
    body: buildMultipartBody(boundary, encapsulatedParts),
  };
}
//#endregion

//#region oxs:helper:multipart-cd
export function escapeContentDispositionName(name: string): string {
  return escapeMultipartName(name);
}

export function encodeContentDispositionFilename(filename: string): string {
  return encodeMultipartFilenameValue(filename);
}
//#endregion

//#region oxs:helper:multipart-response
// The response-side counterpart to the multipart request encoder, in its own helper region and
// reached only through the response descriptor — never through a static transport import — so a
// client whose operations declare no multipart response carries none of this, in the emitted file
// or in a bundle. Its plan types live in `oxs:core`; see the note there.
type MultipartResponsePart = {
  readonly name: string;
  readonly contentType: string | undefined;
  readonly body: Uint8Array;
};

const CARRIAGE_RETURN = 0x0d;
const LINE_FEED = 0x0a;
const HYPHEN = 0x2d;
const SPACE = 0x20;
const HORIZONTAL_TAB = 0x09;
const UTF8_DECODER = new TextDecoder();

export class DecodeError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DecodeError";
  }
}

// `start + needle.length <= haystack.length` is the caller's loop bound, so no length guard here.
function bytesMatchAt(
  haystack: Uint8Array,
  needle: Uint8Array,
  start: number,
): boolean {
  for (let offset = 0; offset < needle.length; offset += 1) {
    if (haystack[start + offset] !== needle[offset]) {
      return false;
    }
  }
  return true;
}

// The next `--boundary` at or after `from` that sits where RFC 2046 §5.1.1 puts a delimiter: at the
// very start of the body, or on its own line. `\n` alone is accepted as well as `\r\n`, because a
// receiver has to take what a server sends, not only what this repo's own encoder would produce.
function nextDelimiter(
  bytes: Uint8Array,
  marker: Uint8Array,
  from: number,
): number {
  for (let start = from; start + marker.length <= bytes.length; start += 1) {
    if (!bytesMatchAt(bytes, marker, start)) {
      continue;
    }
    if (start === 0 || bytes[start - 1] === LINE_FEED) {
      return start;
    }
  }
  return -1;
}

// Consumes the transport padding RFC 2046 §5.1.1 allows after a delimiter and returns the index the
// following line starts at.
function lineStartAfter(bytes: Uint8Array, from: number): number {
  let index = from;
  while (index < bytes.length) {
    const byte = bytes[index];
    if (byte === LINE_FEED) {
      return index + 1;
    }
    if (byte !== SPACE && byte !== HORIZONTAL_TAB && byte !== CARRIAGE_RETURN) {
      throw new DecodeError("multipart boundary delimiter carries trailing data");
    }
    index += 1;
  }
  throw new DecodeError("multipart body ends inside a boundary delimiter");
}

// Drops the line break that belongs to the delimiter rather than to the part body.
function withoutTrailingBreak(
  bytes: Uint8Array,
  start: number,
  end: number,
): Uint8Array {
  let stop = end;
  if (stop > start && bytes[stop - 1] === LINE_FEED) {
    stop -= 1;
  }
  if (stop > start && bytes[stop - 1] === CARRIAGE_RETURN) {
    stop -= 1;
  }
  return bytes.subarray(start, stop);
}

// Splits the encapsulation boundaries, discarding the preamble and the epilogue (RFC 2046 §5.1.1
// makes both ignorable). A body with no delimiter at all, or one that stops before its closing
// delimiter, is malformed and never yields a partial object.
function splitEncapsulations(
  bytes: Uint8Array,
  boundary: string,
): readonly Uint8Array[] {
  const marker = UTF8_ENCODER.encode(`--${boundary}`);
  let cursor = nextDelimiter(bytes, marker, 0);
  if (cursor < 0) {
    throw new DecodeError("multipart body has no boundary delimiter");
  }
  const encapsulations: Uint8Array[] = [];
  for (;;) {
    cursor += marker.length;
    if (bytes[cursor] === HYPHEN && bytes[cursor + 1] === HYPHEN) {
      return encapsulations;
    }
    const start = lineStartAfter(bytes, cursor);
    const next = nextDelimiter(bytes, marker, start);
    if (next < 0) {
      throw new DecodeError("multipart body has no closing boundary delimiter");
    }
    encapsulations.push(withoutTrailingBreak(bytes, start, next));
    cursor = next;
  }
}

// Splits one encapsulation into its header fields and its body. Header field names fold to
// lowercase; obs-fold continuation lines are rejected rather than unfolded, which is the option
// RFC 9112 §5.2 leaves a recipient that is not a proxy.
function partHeaders(encapsulation: Uint8Array): {
  readonly headers: ReadonlyMap<string, string>;
  readonly body: Uint8Array;
} {
  const headers = new Map<string, string>();
  let index = 0;
  for (;;) {
    let end = index;
    while (end < encapsulation.length && encapsulation[end] !== LINE_FEED) {
      end += 1;
    }
    if (end >= encapsulation.length) {
      throw new DecodeError("multipart part has no header terminator");
    }
    const line = withoutTrailingBreak(encapsulation, index, end + 1);
    index = end + 1;
    if (line.length === 0) {
      return { headers, body: encapsulation.subarray(index) };
    }
    const text = UTF8_DECODER.decode(line);
    const separator = text.indexOf(":");
    if (separator <= 0) {
      throw new DecodeError("multipart part header field is malformed");
    }
    const name = text.slice(0, separator).trim().toLowerCase();
    if (!headers.has(name)) {
      headers.set(name, text.slice(separator + 1).trim());
    }
  }
}

// RFC 7578 §4.2 requires `Content-Disposition: form-data` with a `name` parameter on every part, so
// a part without one has no property to map onto and the whole body is rejected.
function dispositionName(disposition: string | undefined): string {
  if (disposition === undefined) {
    throw new DecodeError("multipart part has no Content-Disposition header field");
  }
  for (const [index, segment] of splitOutsideQuotes(disposition, ";").entries()) {
    if (index === 0) {
      if (segment.trim().toLowerCase() !== "form-data") {
        throw new DecodeError("multipart part is not a form-data disposition");
      }
      continue;
    }
    const separator = segment.indexOf("=");
    if (separator < 0 || segment.slice(0, separator).trim().toLowerCase() !== "name") {
      continue;
    }
    return unquoteDispositionValue(segment.slice(separator + 1).trim());
  }
  throw new DecodeError("multipart part Content-Disposition has no name parameter");
}

function splitOutsideQuotes(input: string, separator: string): string[] {
  const segments: string[] = [];
  let start = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < input.length; index += 1) {
    const character = input[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quoted && character === "\\") {
      escaped = true;
      continue;
    }
    if (character === '"') {
      quoted = !quoted;
      continue;
    }
    if (!quoted && character === separator) {
      segments.push(input.slice(start, index));
      start = index + 1;
    }
  }
  segments.push(input.slice(start));
  return segments;
}

function unquoteDispositionValue(value: string): string {
  if (!value.startsWith('"')) {
    return value;
  }
  let unquoted = "";
  let escaped = false;
  for (const character of value.slice(1)) {
    if (escaped) {
      unquoted += character;
      escaped = false;
      continue;
    }
    if (character === "\\") {
      escaped = true;
      continue;
    }
    if (character === '"') {
      return unquoted;
    }
    unquoted += character;
  }
  throw new DecodeError("multipart part name is an unterminated quoted string");
}

// A part's own Content-Type reduced to what a json/text/bytes decision needs: the essence,
// lowercased, parameters dropped. Deliberately not the canonical media-type parser — a helper
// region may not name another helper region's export, and the full RFC 9110 parse is far more than
// this decision asks for.
function partMediaEssence(contentType: string | undefined): string {
  // RFC 7578 §4.4: a part's Content-Type defaults to text/plain.
  const value = contentType ?? "text/plain";
  const parameters = value.indexOf(";");
  return (parameters < 0 ? value : value.slice(0, parameters)).trim().toLowerCase();
}

function wireClassifiedPayload(
  contentType: string | undefined,
): Exclude<MultipartResponsePayload, "wire"> {
  const essence = partMediaEssence(contentType);
  // The same JSON family the compiler recognizes everywhere else: RFC 8259 application/json and
  // any `+json` structured suffix. Unregistered aliases like text/json are text, as they are there.
  if (essence === "application/json" || essence.endsWith("+json")) {
    return "json";
  }
  if (essence.startsWith("text/") || essence === "application/x-www-form-urlencoded") {
    return "text";
  }
  return "binary";
}

function decodePart(shape: MultipartResponsePartShape, part: MultipartResponsePart): unknown {
  const payload = shape.payload === "wire"
    ? wireClassifiedPayload(part.contentType)
    : shape.payload;
  if (payload === "binary") {
    return part.body;
  }
  const text = UTF8_DECODER.decode(part.body);
  if (payload !== "json") {
    return text;
  }
  try {
    return JSON.parse(text);
  } catch (cause) {
    throw new DecodeError(`multipart part "${part.name}" is not valid JSON`, { cause });
  }
}

/**
 * Decodes a `multipart/form-data` response body into the object its declared schema describes.
 *
 * A part maps to the property named by its `Content-Disposition` `name`; a part naming no declared
 * property is kept and decoded under the schema's `additionalProperties`, and a declared property
 * with no part is simply absent — both mirroring how a JSON body decodes without consulting the
 * schema. Filenames and per-part headers are not surfaced: the declared object schema has no place
 * to put them.
 *
 * The boundary is read from `parameters` — the received `Content-Type`'s own parameters, which RFC
 * 2046 §5.1.1 requires to carry it. Nothing in an OpenAPI description can declare it, so a response
 * that arrives without one is rejected rather than guessed at.
 *
 * Throws `DecodeError` on any malformed body; the transport turns that into a `response-decode`
 * failure.
 */
export function decodeMultipartResponse(
  bytes: Uint8Array,
  parameters: readonly (readonly [string, string])[],
  plan: MultipartResponsePlan,
): Readonly<Record<string, unknown>> {
  const boundary = parameters.find(([name]) => name === "boundary")?.[1];
  if (boundary === undefined || boundary.length === 0) {
    throw new DecodeError("multipart response Content-Type has no boundary parameter");
  }
  const order: string[] = [];
  const repeated = new Map<string, unknown[]>();
  const single = new Map<string, unknown>();
  for (const encapsulation of splitEncapsulations(bytes, boundary)) {
    const { headers, body } = partHeaders(encapsulation);
    const name = dispositionName(headers.get("content-disposition"));
    const part: MultipartResponsePart = {
      name,
      contentType: headers.get("content-type"),
      body,
    };
    const shape = plan.parts.find((declared) => declared.name === name) ?? plan.additional;
    const value = decodePart(shape, part);
    if (!repeated.has(name) && !single.has(name)) {
      order.push(name);
    }
    if (shape.repeated) {
      const bucket = repeated.get(name);
      if (bucket === undefined) {
        repeated.set(name, [value]);
      } else {
        bucket.push(value);
      }
      continue;
    }
    if (single.has(name)) {
      // RFC 7578 §5.2 forbids coalescing parts that share a field name, and the declared property
      // is not an array, so there is no non-lossy value to produce.
      throw new DecodeError(
        `multipart response repeats part "${name}", which is not declared as an array`,
      );
    }
    single.set(name, value);
  }

  const decoded: Record<string, unknown> = {};
  for (const name of order) {
    const bucket = repeated.get(name);
    // Part names are attacker-controlled, so every property is defined rather than assigned: a
    // plain assignment to `__proto__` would reach the prototype setter instead of adding a key.
    Object.defineProperty(decoded, name, {
      value: bucket ?? single.get(name),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return decoded;
}
//#endregion

//#region oxs:helper:path-label
export function serializePathLabel(
  _name: string,
  value: ParamValue,
  _allowReserved: boolean,
): string {
  return serializeLabelValue(value, false, false);
}
//#endregion

//#region oxs:helper:path-label-explode
export function serializePathLabelExplode(
  _name: string,
  value: ParamValue,
  _allowReserved: boolean,
): string {
  return serializeLabelValue(value, true, false);
}
//#endregion

//#region oxs:helper:path-label-value
function serializeLabelValue(
  value: ParamValue,
  explode: boolean,
  policy: ComponentPolicy,
): string {
  if (!explode) {
    return `.${serializeSimpleValue(value, false, policy)}`;
  }
  if (isParamArray(value)) {
    return value.map((item) => `.${renderPrimitive(item, policy)}`).join("");
  }
  if (isParamObject(value)) {
    return Object.entries(value)
      .map(
        ([key, item]) =>
          `.${renderComponent(key, policy)}=${renderPrimitive(item, policy)}`,
      )
      .join("");
  }
  return `.${renderPrimitive(value, policy)}`;
}
//#endregion

//#region oxs:helper:path-matrix
export function serializePathMatrix(
  name: string,
  value: ParamValue,
  _allowReserved: boolean,
): string {
  return serializeMatrixValue(name, value, false, false);
}
//#endregion

//#region oxs:helper:path-matrix-explode
export function serializePathMatrixExplode(
  name: string,
  value: ParamValue,
  _allowReserved: boolean,
): string {
  return serializeMatrixValue(name, value, true, false);
}
//#endregion

//#region oxs:helper:path-matrix-value
function serializeMatrixValue(
  name: string,
  value: ParamValue,
  explode: boolean,
  policy: ComponentPolicy,
): string {
  const encodedName = renderName(name);
  if (!explode) {
    return `;${encodedName}=${serializeSimpleValue(value, false, policy)}`;
  }
  if (isParamArray(value)) {
    return value
      .map((item) => `;${encodedName}=${renderPrimitive(item, policy)}`)
      .join("");
  }
  if (isParamObject(value)) {
    return Object.entries(value)
      .map(
        ([key, item]) =>
          `;${renderComponent(key, policy)}=${renderPrimitive(item, policy)}`,
      )
      .join("");
  }
  return `;${encodedName}=${renderPrimitive(value, policy)}`;
}
//#endregion

//#region oxs:helper:path-simple
export function serializePathSimple(
  _name: string,
  value: ParamValue,
  _allowReserved: boolean,
): string {
  return serializeSimpleValue(value, false, false);
}
//#endregion

//#region oxs:helper:path-simple-explode
export function serializePathSimpleExplode(
  _name: string,
  value: ParamValue,
  _allowReserved: boolean,
): string {
  return serializeSimpleValue(value, true, false);
}
//#endregion

//#region oxs:helper:query-deep-object
export function serializeQueryDeepObject(
  name: string,
  value: Readonly<Record<string, ParamPrimitive>>,
  allowReserved: boolean,
): string {
  return serializeDeepObjectValue(name, value, allowReserved);
}
//#endregion

//#region oxs:helper:query-deep-object-extended
export function serializeQueryDeepObjectExtended(
  name: string,
  value: ParamValue,
  allowReserved: boolean,
): string {
  return serializeDeepObjectDispatched(name, value, allowReserved);
}
//#endregion

//#region oxs:helper:query-delimited-object-value
function serializeDelimitedObjectValue(
  name: string,
  value: Readonly<Record<string, ParamPrimitive>>,
  separator: "%20" | "%7C",
  allowReserved: boolean,
): string {
  return `${renderName(name)}=${Object.entries(value)
    .flatMap(([key, item]) => [
      renderComponent(key, allowReserved),
      renderPrimitive(item, allowReserved),
    ])
    .join(separator)}`;
}
//#endregion

//#region oxs:helper:query-form
export function serializeQueryForm(
  name: string,
  value: ParamValue,
  allowReserved: boolean,
): string {
  return serializeQueryFormValue(name, value, false, allowReserved);
}
//#endregion

//#region oxs:helper:query-form-explode
export function serializeQueryFormExplode(
  name: string,
  value: ParamValue,
  allowReserved: boolean,
): string {
  return serializeQueryFormValue(name, value, true, allowReserved);
}
//#endregion

//#region oxs:helper:query-pipe-delimited
export function serializeQueryPipeDelimited(
  name: string,
  value: readonly ParamPrimitive[],
  allowReserved: boolean,
): string {
  return serializeDelimitedQueryValue(name, value, "%7C", allowReserved);
}
//#endregion

//#region oxs:helper:query-pipe-delimited-object
export function serializeQueryPipeDelimitedObject(
  name: string,
  value: Readonly<Record<string, ParamPrimitive>>,
  allowReserved: boolean,
): string {
  return serializeDelimitedObjectValue(name, value, "%7C", allowReserved);
}
//#endregion

//#region oxs:helper:query-space-delimited
export function serializeQuerySpaceDelimited(
  name: string,
  value: readonly ParamPrimitive[],
  allowReserved: boolean,
): string {
  return serializeDelimitedQueryValue(name, value, "%20", allowReserved);
}
//#endregion

//#region oxs:helper:query-space-delimited-object
export function serializeQuerySpaceDelimitedObject(
  name: string,
  value: Readonly<Record<string, ParamPrimitive>>,
  allowReserved: boolean,
): string {
  return serializeDelimitedObjectValue(name, value, "%20", allowReserved);
}
//#endregion

//#region oxs:helper:sse-decode
// The response-side SSE parser, in its own helper region and reached only through the response
// descriptor — never through a static transport import — so a client whose operations declare no
// event-stream response carries none of this, in the emitted file or in a bundle.
//
// `oxs:helper:stream-raw` is always selected alongside this region, so `saturatingAdd`, `abortCancel`
// and that region's `StreamFailure` import are used from there rather than restated here.
//
// `SseEvent` arrives under a local alias because `oxs:helper:sse-encode` binds the same name and is
// NOT guaranteed to be co-selected — a client selecting both regions would otherwise carry two
// bindings of one identifier. The import sits inside the region for the reason spelled out there.
import type { SseEvent as StreamedSseEvent } from "./result.ts";

// WHATWG HTML "server-sent events", id field: a value carrying U+0000 is ignored entirely. Spelled
// as a string because a NUL inside a regex literal is a lint error, and this is a membership test.
const SSE_NULL = "\u0000";
// retry field: "if the field value consists of only ASCII digits" — ASCII specifically, so a
// Unicode digit property would be wrong here, and the empty string is excluded by `+`.
const SSE_ASCII_DIGITS = /^[0-9]+$/u;
const SSE_LINE_FEED = "\n";

/** The index of the next line terminator at or after `from`, or -1 when the text carries none. */
function nextSseTerminator(text: string, from: number): number {
  const carriageReturn = text.indexOf("\r", from);
  const lineFeed = text.indexOf(SSE_LINE_FEED, from);
  if (carriageReturn < 0) {
    return lineFeed;
  }
  if (lineFeed < 0) {
    return carriageReturn;
  }
  return Math.min(carriageReturn, lineFeed);
}

/**
 * The framing half of the parser, split from the JSON stage so each is exercised on its own: this
 * one is pure WHATWG stream parsing over bytes, and `data` is the accumulated buffer before any
 * decoding.
 */
export type SseFramer = {
  /** Frames one upstream chunk and returns the events it completed, in dispatch order. */
  push(chunk: Uint8Array): readonly StreamedSseEvent<string>[];
  /** The standard's "last event ID string": committed by dispatch step 1 and never reset. */
  readonly lastEventId: string;
};

/** A WHATWG event-stream parser over the bytes of one response body. */
export function createSseFramer(): SseFramer {
  // One decoder for the whole stream, which is what makes the UTF-8 decode algorithm's "strip one
  // leading BOM" apply to the stream rather than to each chunk, and lets a multi-byte sequence —
  // the BOM included — straddle a chunk boundary.
  const decoder = new TextDecoder();
  let pendingLine = "";
  // A CR ends its line the moment it is seen; a following LF is then that same terminator's second
  // half and is swallowed, including when the pair straddles a chunk boundary. Ending the line
  // eagerly is also what dispatches a CR that turns out to be the last byte of the stream.
  let afterCarriageReturn = false;
  let data = "";
  let eventType = "";
  let retry: number | undefined;
  let lastEventIdBuffer = "";
  let lastEventId = "";
  let dispatched: StreamedSseEvent<string>[] = [];

  const dispatch = (): void => {
    // Step 1 runs before step 2's early return, and no step resets the last event ID buffer, so an
    // id-only block commits an id that every later event carries.
    lastEventId = lastEventIdBuffer;
    if (data === "") {
      // Step 2 resets the data and event type buffers and returns without dispatching. The Oasts
      // per-event `retry` is per-block by the same rule, so it is cleared here too.
      eventType = "";
      retry = undefined;
      return;
    }
    // Step 3 removes "the last character", singular — never every trailing LF. Every `data` field
    // appended a value plus an LF and step 2 already returned on an empty buffer, so there is
    // always exactly one to remove.
    const event: StreamedSseEvent<string> = { data: data.slice(0, -1) };
    // Step 6 overrides the type only when the event type buffer is non-empty.
    if (eventType !== "") {
      event.event = eventType;
    }
    // Oasts convention: `id` mirrors the last event ID string, and is absent when that is empty.
    if (lastEventId !== "") {
      event.id = lastEventId;
    }
    if (retry !== undefined) {
      event.retry = retry;
    }
    dispatched.push(event);
    // Step 7.
    data = "";
    eventType = "";
    retry = undefined;
  };

  const processLine = (line: string): void => {
    if (line === "") {
      dispatch();
      return;
    }
    if (line.startsWith(":")) {
      return;
    }
    const colon = line.indexOf(":");
    // A non-empty line with no colon is the whole line as the field name and the empty string as
    // the field value.
    const field = colon < 0 ? line : line.slice(0, colon);
    const raw = colon < 0 ? "" : line.slice(colon + 1);
    // "If value starts with a U+0020 SPACE character, remove it from value" — one, not all.
    const value = raw.startsWith(" ") ? raw.slice(1) : raw;
    if (field === "data") {
      data += `${value}${SSE_LINE_FEED}`;
      return;
    }
    if (field === "event") {
      eventType = value;
      return;
    }
    if (field === "id") {
      // A value carrying NUL leaves the buffer at its prior value rather than clearing it.
      if (!value.includes(SSE_NULL)) {
        lastEventIdBuffer = value;
      }
      return;
    }
    if (field === "retry" && SSE_ASCII_DIGITS.test(value)) {
      retry = Number.parseInt(value, 10);
    }
    // Every other field name — and a `retry` that is not all ASCII digits — is ignored.
  };

  const push = (chunk: Uint8Array): readonly StreamedSseEvent<string>[] => {
    // A fresh array per chunk: the one returned is never touched again.
    dispatched = [];
    const text = decoder.decode(chunk, { stream: true });
    let start = 0;
    while (start < text.length) {
      if (afterCarriageReturn) {
        afterCarriageReturn = false;
        if (text.startsWith(SSE_LINE_FEED, start)) {
          start += 1;
          continue;
        }
      }
      const terminator = nextSseTerminator(text, start);
      if (terminator < 0) {
        // An unterminated trailing line is held for the next chunk, and discarded unread if the
        // stream ends first.
        pendingLine += text.slice(start);
        break;
      }
      processLine(pendingLine + text.slice(start, terminator));
      pendingLine = "";
      afterCarriageReturn = !text.startsWith(SSE_LINE_FEED, terminator);
      start = terminator + 1;
    }
    return dispatched;
  };

  return {
    push,
    get lastEventId(): string {
      return lastEventId;
    },
  };
}

function sseStreamFailure(eventsYielded: number, cause: unknown): StreamFailure {
  return { kind: "sse", eventsYielded, cause };
}

async function* sseEvents(
  body: ReadableStream<Uint8Array>,
  signal: AbortSignal,
  onEvent: ((data: unknown) => unknown) | null,
): AsyncGenerator<StreamedSseEvent<unknown>> {
  const framer = createSseFramer();
  const reader = body.getReader();
  const abort = abortCancel(signal, reader);
  let eventsYielded = 0;
  try {
    for (;;) {
      let step: ReadableStreamReadResult<Uint8Array>;
      try {
        step = await reader.read();
      } catch (cause) {
        // The abort check comes first here for the same reason it does below: a cancel racing an
        // in-flight read settles it either way — resolved as done, or rejected with the abort
        // error, depending on the host — and a caller's cancellation must never reach them dressed
        // as a mid-stream stream failure. Which of the two happens is not something to depend on.
        if (signal.aborted) {
          throw signal.reason;
        }
        throw sseStreamFailure(eventsYielded, cause);
      }
      // Before the done check: cancelling on abort is what settles the read, so an aborted stream
      // arrives here as a completed one and must reject with the caller's own reason.
      if (signal.aborted) {
        throw signal.reason;
      }
      if (step.done) {
        return;
      }
      for (const framed of framer.push(step.value)) {
        // One chunk can carry several complete frames, and the caller may abort while its loop body
        // is handling the first. Re-checked per frame, not per read, so a cancelled consumer's body
        // does not run again for events that happened to arrive in the same chunk.
        if (signal.aborted) {
          throw signal.reason;
        }
        let data: unknown;
        try {
          // The declared schema describes the decoded value, so JSON decoding runs before the
          // per-event pipeline, and either failing is a mid-stream failure.
          data = JSON.parse(framed.data);
          if (onEvent !== null) {
            data = onEvent(data);
          }
        } catch (cause) {
          throw sseStreamFailure(eventsYielded, cause);
        }
        yield { ...framed, data };
        // Counted only once the consumer has the event: framing, decoding and the per-event
        // pipeline all succeeded before this point.
        eventsYielded = saturatingAdd(eventsYielded, 1);
      }
    }
  } finally {
    abort.release();
    // Reached from a normal end, from a failure, and from a `break` out of a `for await` alike. An
    // upstream failure makes the cancel itself reject with that same error, which must not replace
    // the failure being thrown.
    await reader.cancel().catch(IGNORE_CANCEL_FAILURE);
  }
}

/**
 * Decodes a `text/event-stream` body into its events. `onEvent` is the generated per-event
 * validate-then-transform pipeline, which throws on failure; `null` means the operation declares no
 * per-event checking. The iterable is single-consumer: the body is read once and cannot be replayed.
 */
export function decodeSseStream(
  body: ReadableStream<Uint8Array>,
  signal: AbortSignal,
  onEvent: ((data: unknown) => unknown) | null,
): AsyncIterable<StreamedSseEvent<unknown>> {
  let consumed = false;
  return {
    [Symbol.asyncIterator](): AsyncIterator<StreamedSseEvent<unknown>> {
      if (consumed) {
        throw new TypeError("an event stream response body can only be consumed once");
      }
      consumed = true;
      return sseEvents(body, signal, onEvent);
    },
  };
}
//#endregion

//#region oxs:helper:sse-encode
// The import sits inside the region, not at the top of the file: a top-level import would be
// emitted for every client, and one that nothing in the rendered helper subset uses fails a
// consumer's `noUnusedLocals`. Relative `.ts` suffixes are contractual — the Rust embedding engine
// rewrites them to the configured emit extension — and `result.ts` is emitted for every client, so
// this resolves wherever the region lands.
import type { SseEvent } from "./result.ts";

// The Oasts-owned SSE frame encoder, shared by streaming request bodies and the msw stream
// resolver so both sides of a round trip frame identically. It is a separate export rather than a
// wrapper the client applies for the caller: every failure it can raise happens while the stream
// is being read, which is after the request was dispatched, and the result model has no arm for
// that. Held here, a bad event is an ordinary exception in the caller's own code.
//
// Field values are checked, never escaped. SSE defines no escape for a line terminator inside a
// field, so a value carrying one cannot be represented at all — refusing it is the only option
// that does not silently reframe the stream into different events than the caller wrote. An `id`
// carrying U+0000 is refused for the same reason one layer up: a conforming parser ignores that
// field entirely, so the stream's last event id would silently disagree with what was sent.
// A source that throws on close is telling us about its own cleanup, not about the failure being
// reported; swallowing it keeps the caller's error intact.
const IGNORE_ITERATOR_CLOSE_FAILURE = (): void => {};

const SSE_UNFRAMABLE = /[\r\n]/u;
// A plain string rather than a character class: a NUL inside a regex literal is a lint error,
// and this check is a membership test, not a pattern.
const SSE_NUL = "\u0000";

function sseField(name: "event" | "id", value: string): string {
  if (SSE_UNFRAMABLE.test(value) || (name === "id" && value.includes(SSE_NUL))) {
    throw new TypeError(`SSE ${name} field carries a character that cannot be framed`);
  }
  return `${name}: ${value}\n`;
}

function encodeSseFrame<TData>(event: SseEvent<TData>): string {
  const data = JSON.stringify(event.data);
  if (data === undefined) {
    throw new TypeError("SSE event data is not JSON-serializable");
  }
  let frame = "";
  if (event.event !== undefined) {
    frame += sseField("event", event.event);
  }
  if (event.id !== undefined) {
    frame += sseField("id", event.id);
  }
  if (event.retry !== undefined) {
    if (!Number.isSafeInteger(event.retry) || event.retry < 0) {
      throw new TypeError("SSE retry field must be a non-negative safe integer");
    }
    frame += `retry: ${String(event.retry)}\n`;
  }
  return `${frame}data: ${data}\n\n`;
}

/** Frames typed events as a `text/event-stream` byte stream. */
export function encodeSseEvents<TData>(
  events: AsyncIterable<SseEvent<TData>>,
): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  // Taken here rather than in `start`, which would leave `pull` with an `undefined` case that the
  // streams contract says can never happen — `start` always runs first — and therefore a branch no
  // test could ever reach.
  const iterator = events[Symbol.asyncIterator]();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      const step = await iterator.next();
      if (step.done === true) {
        controller.close();
        return;
      }
      let frame: string;
      try {
        frame = encodeSseFrame(step.value);
      } catch (cause) {
        // Erroring the stream does not run `cancel`, so without this the source iterable is never
        // returned and a generator's own cleanup — a `finally`, an open handle — is held for as
        // long as the caller's scope lives. The original failure is what the reader must see, so
        // the close is best-effort and never replaces it.
        await iterator.return?.(cause).catch(IGNORE_ITERATOR_CLOSE_FAILURE);
        throw cause;
      }
      controller.enqueue(encoder.encode(frame));
    },
    async cancel(reason: unknown) {
      // Cancellation has to reach the source iterable, or a generator holding a resource keeps it
      // for as long as the caller's own scope lives.
      await iterator.return?.(reason);
    },
  });
}
//#endregion

//#region oxs:helper:stream-raw
// The raw response byte stream, reached only through the response descriptor for the same reason
// the multipart and SSE response decoders are: a client whose operations declare no streaming
// response links none of this. `oxs:helper:sse-decode` is never selected without this region, and
// uses `saturatingAdd`, `abortCancel` and this `StreamFailure` import rather than restating them —
// which is also why the import lives here and not there: this region can be selected alone, that
// one cannot.
import type { StreamFailure } from "./result.ts";

/**
 * One step of stream progress, pinned at `Number.MAX_SAFE_INTEGER`. Both stream counters report
 * `min(actual, MAX_SAFE_INTEGER)`, so a stream that outruns the representable range holds the
 * ceiling instead of drifting into an imprecise float — and never fails or alters the stream.
 */
export function saturatingAdd(total: number, step: number): number {
  const sum = total + step;
  return sum > Number.MAX_SAFE_INTEGER ? Number.MAX_SAFE_INTEGER : sum;
}

// Caller cancellation has to reach a read that may never settle on its own, and cancelling the
// upstream reader is what settles it: a cancelled read resolves as done, so both consumers below
// re-check `signal.aborted` right after every read instead of racing a promise. Racing would attach
// one reaction per chunk to a promise that never settles on a healthy stream — unbounded growth on
// exactly the long-lived streams this exists for. `release` drops the listener once the stream is
// done with it.
type StreamAbort = { readonly release: () => void };

// The teardown for a signal that was already aborted when the stream started: no listener was ever
// registered, so there is nothing to drop.
const NO_ABORT_LISTENER = (): void => {};

// Cancelling a body that has already failed rejects with that same failure. Every cancel here is
// part of tearing the stream down, so that rejection is dropped rather than left to surface as an
// unhandled rejection or to replace the failure actually being reported.
const IGNORE_CANCEL_FAILURE = (): void => {};

function abortCancel(
  signal: AbortSignal,
  reader: ReadableStreamDefaultReader<Uint8Array>,
): StreamAbort {
  if (signal.aborted) {
    void reader.cancel(signal.reason).catch(IGNORE_CANCEL_FAILURE);
    return { release: NO_ABORT_LISTENER };
  }
  const onAbort = (): void => {
    void reader.cancel(signal.reason).catch(IGNORE_CANCEL_FAILURE);
  };
  signal.addEventListener("abort", onAbort, { once: true });
  return {
    release: (): void => {
      signal.removeEventListener("abort", onAbort);
    },
  };
}

/**
 * Passes an upstream response body through chunk for chunk, counting the bytes successfully read so
 * a mid-stream failure can report how far the caller got. An upstream read failure errors the
 * stream with a `StreamFailure`; caller cancellation cancels the upstream body and errors with the
 * signal's own abort reason, never with a synthesized failure.
 */
export function readRawStream(
  body: ReadableStream<Uint8Array>,
  signal: AbortSignal,
): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  const abort = abortCancel(signal, reader);
  let bytesRead = 0;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      let step: ReadableStreamReadResult<Uint8Array>;
      try {
        step = await reader.read();
      } catch (cause) {
        abort.release();
        // A read rejected by the caller's own cancellation is a cancellation, not a stream
        // failure — the host decides whether an aborted in-flight read resolves as done or
        // rejects, and the reported reason must not depend on which.
        if (signal.aborted) {
          controller.error(signal.reason);
          return;
        }
        void reader.cancel(cause).catch(IGNORE_CANCEL_FAILURE);
        const failure: StreamFailure = { kind: "raw", bytesRead, cause };
        controller.error(failure);
        return;
      }
      // Before the done check: cancelling on abort is what settles the read, so an aborted stream
      // arrives here as a completed one and must error with the caller's reason, not close.
      if (signal.aborted) {
        abort.release();
        controller.error(signal.reason);
        return;
      }
      if (step.done) {
        abort.release();
        controller.close();
        return;
      }
      bytesRead = saturatingAdd(bytesRead, step.value.byteLength);
      controller.enqueue(step.value);
    },
    async cancel(reason: unknown) {
      abort.release();
      // Cancelling an already-errored stream rejects with its stored error, and this cancel runs on
      // the ordinary teardown path — a `break` out of a `for await`, a `pipeTo` without
      // `preventCancel`. Without the catch, stopping a stream that had already failed throws the
      // bare upstream cause at the consumer instead of the failure envelope this module exists to
      // provide. The SSE teardown swallows it for the same reason.
      await reader.cancel(reason).catch(IGNORE_CANCEL_FAILURE);
    },
  });
}
//#endregion
