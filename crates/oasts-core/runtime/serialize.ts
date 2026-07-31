// Regions are ordered as oxs:core followed by byte-lexicographically sorted helper ids;
// the Rust embedding engine preserves this exact order when emitting any helper subset.

//#region oxs:core
export type ParamPrimitive = string | number | boolean;
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

function consumeToken(input: string, start: number): number {
  let index = start;
  while (index < input.length && TCHAR.includes(input[index])) {
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
        const character = input[index];
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

  const chunks: Uint8Array[] = [
    UTF8_ENCODER.encode(`--${boundary}\r\n`),
    encapsulatedParts[0],
  ];
  for (let index = 1; index < encapsulatedParts.length; index += 1) {
    chunks.push(
      UTF8_ENCODER.encode(`\r\n--${boundary}\r\n`),
      encapsulatedParts[index],
    );
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
  // The same JSON family the compiler recognizes everywhere else: RFC 8259 application/json, the
  // de-facto text/json alias, and any `+json` structured suffix.
  if (essence === "application/json" || essence === "text/json" || essence.endsWith("+json")) {
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
