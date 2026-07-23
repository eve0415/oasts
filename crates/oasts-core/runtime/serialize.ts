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
      if (!isParamObject(field.value)) {
        throw new TypeError("deepObject fields require an object value");
      }
      return serializeDeepObjectValue(
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
