import type { DefaultBodyType } from "msw";

import { OastsHandlerError, type ApplicationPath, type SourcePointer } from "./msw-runtime.ts";

/**
 * The body type MSW is told a handler may send.
 *
 * A document that leaves a media entry's schema open renders as `unknown`, which is not a body MSW
 * knows how to send — and a named alias resolving to `unknown` is not detectable by looking at the
 * emitted text. Deciding it in the type system instead makes the check total: a representable
 * union passes through unchanged, anything else widens to whatever MSW accepts.
 */
export type SendableBody<T> = [T] extends [DefaultBodyType] ? T : DefaultBodyType;

export type ParameterHelper =
  | "path-simple"
  | "path-simple-explode"
  | "path-label"
  | "path-label-explode"
  | "path-matrix"
  | "path-matrix-explode"
  | "query-form"
  | "query-form-explode"
  | "query-space-delimited"
  | "query-space-delimited-object"
  | "query-pipe-delimited"
  | "query-pipe-delimited-object"
  | "query-deep-object"
  | "query-deep-object-extended"
  | "header-simple"
  | "header-simple-explode"
  | "content-json-path"
  | "content-json-query"
  | "content-json-header";

type ScalarShape =
  | { readonly kind: "string"; readonly enum?: readonly unknown[] }
  | { readonly kind: "number"; readonly enum?: readonly unknown[] }
  | { readonly kind: "integer"; readonly enum?: readonly unknown[] }
  | { readonly kind: "boolean"; readonly enum?: readonly unknown[] }
  | { readonly kind: "null"; readonly enum?: readonly unknown[] };

type LiteralShape = {
  readonly kind: "literal";
  readonly values: readonly unknown[];
};

type ParameterProperty = {
  readonly required: boolean;
  readonly shape: ParameterShape;
};

type ObjectShape = {
  readonly kind: "object";
  readonly properties: Readonly<Record<string, ParameterProperty>>;
  readonly additional: ParameterShape | boolean;
};

export type ParameterShape =
  | ScalarShape
  | LiteralShape
  | { readonly kind: "array"; readonly items: ParameterShape }
  | ObjectShape
  | { readonly kind: "nullable"; readonly value: ParameterShape }
  | { readonly kind: "union"; readonly variants: readonly ParameterShape[] }
  | { readonly kind: "intersection"; readonly variants: readonly ParameterShape[] }
  | { readonly kind: "unknown" }
  | { readonly kind: "never" };

type RequiredPropertyKeys<P extends Readonly<Record<string, ParameterProperty>>> = {
  [K in keyof P]: P[K]["required"] extends true ? K : never;
}[keyof P];

type OptionalPropertyKeys<P extends Readonly<Record<string, ParameterProperty>>> = Exclude<
  keyof P,
  RequiredPropertyKeys<P>
>;

type ProjectedObject<
  P extends Readonly<Record<string, ParameterProperty>>,
  D extends readonly unknown[],
> = {
  readonly [K in RequiredPropertyKeys<P>]: ProjectedValue<P[K]["shape"], [...D, unknown]>;
} & {
  readonly [K in OptionalPropertyKeys<P>]?: ProjectedValue<P[K]["shape"], [...D, unknown]>;
};

type ProjectedAdditional<
  S extends ObjectShape,
  D extends readonly unknown[],
> = S["additional"] extends ParameterShape
  ? { readonly [key: string]: ProjectedValue<S["additional"], [...D, unknown]> }
  : unknown;

type UnionValues<
  S extends readonly ParameterShape[],
  D extends readonly unknown[],
> = ProjectedValue<S[number], [...D, unknown]>;

type IntersectionValues<
  S extends readonly ParameterShape[],
  D extends readonly unknown[],
> = S extends readonly [
  infer Head extends ParameterShape,
  ...infer Tail extends readonly ParameterShape[],
]
  ? ProjectedValue<Head, [...D, unknown]> & IntersectionValues<Tail, D>
  : unknown;

type ProjectedScalar<S extends ScalarShape> = S extends {
  readonly enum: infer E extends readonly unknown[];
}
  ? E[number]
  : S extends { readonly kind: "string" }
    ? string
    : S extends { readonly kind: "number" | "integer" }
      ? number
      : S extends { readonly kind: "boolean" }
        ? boolean
        : null;

// Generated descriptors stop two levels before this guard. It terminates instantiation only when
// callers widen a descriptor back to the recursive ParameterShape union.
export type ProjectedValue<
  S extends ParameterShape,
  D extends readonly unknown[] = [],
> = D["length"] extends 12
  ? unknown
  : S extends {
        readonly kind: "literal";
        readonly values: infer V extends readonly unknown[];
      }
    ? V[number]
    : S extends ScalarShape
      ? ProjectedScalar<S>
      : S extends { readonly kind: "array"; readonly items: infer I extends ParameterShape }
        ? ProjectedValue<I, [...D, unknown]>[]
        : S extends ObjectShape
          ? ProjectedObject<S["properties"], D> & ProjectedAdditional<S, D>
          : S extends {
                readonly kind: "nullable";
                readonly value: infer V extends ParameterShape;
              }
            ? ProjectedValue<V, [...D, unknown]> | null
            : S extends {
                  readonly kind: "union";
                  readonly variants: infer V extends readonly ParameterShape[];
                }
              ? UnionValues<V, D>
              : S extends {
                    readonly kind: "intersection";
                    readonly variants: infer V extends readonly ParameterShape[];
                  }
                ? IntersectionValues<V, D>
                : S extends { readonly kind: "never" }
                  ? never
                  : unknown;

/**
 * A projected parameter group, as the handler actually hands it over.
 *
 * Projection always writes every declared key and stores `undefined` where the request carried no
 * value, so an optional member is present-and-undefined rather than absent. Under
 * `exactOptionalPropertyTypes` those are different types, and a plain `tags?: string[]` would
 * reject the object the handler builds — so the optional members widen to admit the `undefined`
 * they really hold. Required members are untouched: this is a homomorphic mapped type, so it keeps
 * each member's optionality and only widens the ones that were already optional.
 */
export type Projected<T> = {
  [K in keyof T]: undefined extends T[K] ? T[K] | undefined : T[K];
};

export type RequestBodyMediaKind = "json" | "text" | "binary" | "urlencoded" | "multipart";

type BodyFieldDescriptor = {
  readonly name: string;
  readonly required: boolean;
  readonly sourcePointer: SourcePointer;
};

export type UrlencodedFieldDescriptor = BodyFieldDescriptor &
  (
    | {
        readonly decoder: "style";
        readonly helper: Extract<ParameterHelper, `query-${string}`>;
        readonly shape: ParameterShape;
      }
    | { readonly decoder: "json" }
    | { readonly decoder: "text"; readonly shape: ParameterShape }
  );

export type MultipartContentTypeDescriptor =
  | { readonly kind: "none" }
  | { readonly kind: "fixed"; readonly value: string }
  | { readonly kind: "selected"; readonly admitted: readonly string[] };

export type MultipartFieldDescriptor = BodyFieldDescriptor & {
  readonly repeated: boolean;
  readonly payload: "json" | "text" | "binary";
  readonly payloads?: readonly ("json" | "text" | "binary")[];
  readonly contentType: MultipartContentTypeDescriptor;
  readonly filename: boolean;
};

export type RequestBodyMediaDescriptor = {
  readonly media: string;
  readonly kind: RequestBodyMediaKind;
  readonly sourcePointer: SourcePointer;
  readonly fields?: readonly (UrlencodedFieldDescriptor | MultipartFieldDescriptor)[];
};

export type RequestBodyDescriptor = {
  readonly required: boolean;
  readonly discriminated: boolean;
  readonly sourcePointer: SourcePointer;
  readonly media: readonly RequestBodyMediaDescriptor[];
};

type RequiredRequestBodyDescriptor = RequestBodyDescriptor & { readonly required: true };
type OptionalRequestBodyDescriptor = RequestBodyDescriptor & { readonly required: false };

type ParsedBodyMediaType = {
  readonly type: string;
  readonly subtype: string;
  readonly parameters: readonly (readonly [string, string])[];
};

type SelectedRequestBodyMedia = {
  readonly descriptor: RequestBodyMediaDescriptor;
  readonly actual: ParsedBodyMediaType;
};

type MultipartPart = {
  readonly name: string;
  readonly filename: string | undefined;
  readonly contentType: string | undefined;
  readonly body: Uint8Array;
};

const BODY_UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const BODY_TCHAR = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BODY_TOKEN_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const BODY_QUOTED_PAIR_PATTERN = /^[\t\x20-\x7e\x80-\xff]$/u;
const BODY_QDTEXT_PATTERN = /^[\t\x20-!#-[\]-~\x80-\xff]$/u;
const BODY_SAFE_PARAMETER_VALUE_PATTERN = /^[\t\x20-\x7e]*$/u;

export function projectRequestBody<T>(
  request: Request,
  descriptor: RequiredRequestBodyDescriptor,
): Promise<T>;
export function projectRequestBody<T>(
  request: Request,
  descriptor: OptionalRequestBodyDescriptor,
): Promise<T | undefined>;
export async function projectRequestBody(
  request: Request,
  descriptor: RequestBodyDescriptor,
): Promise<unknown> {
  if (request.body === null) {
    if (!descriptor.required) {
      return undefined;
    }
    throw bodyError(
      "body-missing",
      descriptor.sourcePointer,
      null,
      new TypeError("body is absent"),
    );
  }

  const contentType = request.headers.get("content-type");
  let selected: SelectedRequestBodyMedia;
  try {
    selected = selectRequestBodyMedia(contentType, descriptor.media);
  } catch (cause) {
    throw bodyError("content-type-mismatch", descriptor.sourcePointer, null, cause);
  }

  try {
    const body = await decodeRequestBody(request, selected);
    return descriptor.discriminated
      ? { contentType: selectedBodyDiscriminant(selected), body }
      : body;
  } catch (cause) {
    throw bodyError(
      selected.descriptor.kind === "multipart" ? "multipart-decode" : "body-decode",
      selected.descriptor.sourcePointer,
      ["body"],
      cause,
    );
  }
}

function bodyError(
  code: "content-type-mismatch" | "body-decode" | "multipart-decode" | "body-missing",
  sourcePointer: SourcePointer,
  applicationPath: ApplicationPath | null,
  cause: unknown,
): OastsHandlerError {
  return new OastsHandlerError({ code, sourcePointer, applicationPath, cause });
}

function selectRequestBodyMedia(
  contentType: string | null,
  media: readonly RequestBodyMediaDescriptor[],
): SelectedRequestBodyMedia {
  if (contentType === null) {
    throw new TypeError("request body has no Content-Type header");
  }
  const actual = parseBodyMediaType(contentType);
  if (actual === null || actual.type === "*" || actual.subtype === "*") {
    throw new TypeError("request Content-Type is not a concrete media type");
  }
  let selected: RequestBodyMediaDescriptor | undefined;
  let selectedScore = -1;
  for (const candidate of media) {
    const declared = parseBodyMediaType(candidate.media);
    if (declared === null) {
      continue;
    }
    const score = requestMediaScore(declared, actual, candidate.kind === "multipart");
    if (score > selectedScore) {
      selected = candidate;
      selectedScore = score;
    }
  }
  if (selected === undefined) {
    throw new TypeError("request Content-Type matches no declared media type");
  }
  return { descriptor: selected, actual };
}

function requestMediaScore(
  declared: ParsedBodyMediaType,
  actual: ParsedBodyMediaType,
  multipart: boolean,
): number {
  if (declared.type === "*" && declared.subtype === "*" && declared.parameters.length === 0) {
    return 0;
  }
  if (
    declared.type === actual.type &&
    declared.subtype === "*" &&
    declared.parameters.length === 0
  ) {
    return 1;
  }
  if (declared.type !== actual.type || declared.subtype !== actual.subtype) {
    return -1;
  }
  const actualParameters = multipart
    ? actual.parameters.filter(([name]) => name !== "boundary")
    : actual.parameters;
  return sameBodyParameters(declared.parameters, actualParameters) ? 2 : -1;
}

function sameBodyParameters(
  left: readonly (readonly [string, string])[],
  right: readonly (readonly [string, string])[],
): boolean {
  return (
    left.length === right.length &&
    left.every(([name, value], index) => {
      const candidate = right[index];
      return candidate !== undefined && candidate[0] === name && candidate[1] === value;
    })
  );
}

function selectedBodyDiscriminant(selected: SelectedRequestBodyMedia): string {
  const declared = parseBodyMediaType(selected.descriptor.media);
  if (declared !== null && declared.type !== "*" && declared.subtype !== "*") {
    return selected.descriptor.media;
  }
  return serializeBodyMediaType(selected.actual);
}

async function decodeRequestBody(
  request: Request,
  selected: SelectedRequestBodyMedia,
): Promise<unknown> {
  if (selected.descriptor.kind === "binary") {
    return new Uint8Array(await request.arrayBuffer());
  }
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (selected.descriptor.kind === "multipart") {
    return decodeMultipartBody(bytes, selected.actual, multipartFields(selected.descriptor));
  }
  const text = BODY_UTF8_DECODER.decode(bytes);
  if (selected.descriptor.kind === "json") {
    return JSON.parse(text);
  }
  if (selected.descriptor.kind === "urlencoded") {
    return decodeUrlencodedBody(text, urlencodedFields(selected.descriptor));
  }
  return text;
}

function urlencodedFields(
  descriptor: RequestBodyMediaDescriptor,
): readonly UrlencodedFieldDescriptor[] {
  const fields = descriptor.fields ?? [];
  if (fields.some(isMultipartField)) {
    throw new TypeError("urlencoded descriptor contains a multipart field");
  }
  return fields.filter(isUrlencodedField);
}

function multipartFields(
  descriptor: RequestBodyMediaDescriptor,
): readonly MultipartFieldDescriptor[] {
  const fields = descriptor.fields ?? [];
  if (fields.some(isUrlencodedField)) {
    throw new TypeError("multipart descriptor contains a urlencoded field");
  }
  return fields.filter(isMultipartField);
}

function isMultipartField(
  field: UrlencodedFieldDescriptor | MultipartFieldDescriptor,
): field is MultipartFieldDescriptor {
  return "repeated" in field;
}

function isUrlencodedField(
  field: UrlencodedFieldDescriptor | MultipartFieldDescriptor,
): field is UrlencodedFieldDescriptor {
  return "decoder" in field;
}

function decodeUrlencodedBody(
  text: string,
  fields: readonly UrlencodedFieldDescriptor[],
): Readonly<Record<string, unknown>> {
  const pairs = bodyQueryPairs(text);
  const claimed = new Set<number>();
  const decoded: Record<string, unknown> = {};
  const fieldNames = fields.map((field) => field.name);
  for (const field of fields) {
    const indexes = urlencodedClaimedIndexes(pairs, field, fieldNames);
    for (const index of indexes) {
      if (claimed.has(index)) {
        throw new TypeError(`form pair ${index} is claimed by more than one field`);
      }
      claimed.add(index);
    }
    const value = decodeUrlencodedField(pairs, field, fieldNames);
    if (value === MISSING) {
      if (field.required) {
        throw new TypeError(`required form field ${field.name} is absent`);
      }
    } else {
      define(decoded, field.name, value);
    }
  }
  if (claimed.size !== pairs.length) {
    throw new TypeError("form body carries an undeclared field");
  }
  return decoded;
}

function decodeUrlencodedField(
  pairs: readonly QueryPair[],
  field: UrlencodedFieldDescriptor,
  fieldNames: readonly string[],
): unknown {
  if (field.decoder === "json") {
    const raw = singleQueryValue(pairs, field.name);
    return raw === MISSING ? MISSING : JSON.parse(decodeComponent(raw));
  }
  const descriptor: ParameterDescriptor = {
    location: "query",
    name: field.name,
    helper: field.decoder === "text" ? "query-form-explode" : field.helper,
    required: field.required,
    shape: field.shape,
    sourcePointer: field.sourcePointer,
    applicationPath: ["body", field.name],
    queryParameterNames: fieldNames,
  };
  return decodeQueryValue(pairs, descriptor);
}

function urlencodedClaimedIndexes(
  pairs: readonly QueryPair[],
  field: UrlencodedFieldDescriptor,
  fieldNames: readonly string[],
): readonly number[] {
  if (field.decoder === "json") {
    return matchingPairIndexes(pairs, (pair) => pair.name === field.name);
  }
  const helper = field.decoder === "text" ? "query-form-explode" : field.helper;
  if (helper === "query-deep-object" || helper === "query-deep-object-extended") {
    const prefix = `${field.name}[`;
    return matchingPairIndexes(
      pairs,
      (pair) =>
        pair.name === field.name || (pair.name.startsWith(prefix) && pair.name.endsWith("]")),
    );
  }
  if (helper !== "query-form-explode") {
    return matchingPairIndexes(pairs, (pair) => pair.name === field.name);
  }
  return matchingPairIndexes(pairs, (pair) =>
    formExplodePairBelongs(pair, field.name, field.shape, fieldNames),
  );
}

function formExplodePairBelongs(
  pair: QueryPair,
  fieldName: string,
  shape: ParameterShape,
  fieldNames: readonly string[],
): boolean {
  if (shape.kind === "nullable") {
    return formExplodePairBelongs(pair, fieldName, shape.value, fieldNames);
  }
  if (shape.kind === "union" || shape.kind === "intersection") {
    return shape.variants.some((variant) =>
      formExplodePairBelongs(pair, fieldName, variant, fieldNames),
    );
  }
  if (shape.kind !== "object") {
    return pair.name === fieldName;
  }
  return (
    Object.hasOwn(shape.properties, pair.name) ||
    (shape.additional !== false && !fieldNames.includes(pair.name))
  );
}

function matchingPairIndexes(
  pairs: readonly QueryPair[],
  matches: (pair: QueryPair) => boolean,
): readonly number[] {
  return pairs.flatMap((pair, index) => (matches(pair) ? [index] : []));
}

function bodyQueryPairs(body: string): readonly QueryPair[] {
  if (body === "") {
    return [];
  }
  return body.split("&").map((pair) => {
    const equals = pair.indexOf("=");
    if (equals < 0) {
      throw new TypeError("form field lacks an equals sign");
    }
    return {
      name: decodeComponent(pair.slice(0, equals)),
      rawValue: pair.slice(equals + 1),
    };
  });
}

function decodeMultipartBody(
  bytes: Uint8Array,
  contentType: ParsedBodyMediaType,
  fields: readonly MultipartFieldDescriptor[],
): Readonly<Record<string, unknown>> {
  const boundary = contentType.parameters.find(([name]) => name === "boundary")?.[1];
  if (boundary === undefined || !validMultipartBoundary(boundary)) {
    throw new TypeError("multipart Content-Type has no valid boundary");
  }
  const parts = parseMultipartParts(bytes, boundary);
  const buckets = new Map<string, unknown[]>();
  for (const part of parts) {
    const field = fields.find((candidate) => candidate.name === part.name);
    if (field === undefined) {
      throw new TypeError(`multipart part ${part.name} is not declared`);
    }
    const bucket = buckets.get(part.name) ?? [];
    if (!field.repeated && bucket.length !== 0) {
      throw new TypeError(`multipart part ${part.name} repeats`);
    }
    bucket.push(decodeMultipartPart(part, field));
    buckets.set(part.name, bucket);
  }

  const decoded: Record<string, unknown> = {};
  for (const field of fields) {
    const bucket = buckets.get(field.name);
    if (bucket === undefined) {
      if (field.required) {
        throw new TypeError(`required multipart part ${field.name} is absent`);
      }
      continue;
    }
    define(decoded, field.name, field.repeated ? bucket : bucket[0]);
  }
  return decoded;
}

function validMultipartBoundary(boundary: string): boolean {
  return (
    boundary.length > 0 &&
    boundary.length <= 70 &&
    /^[0-9A-Za-z'()+_,\-./:=? ]+$/u.test(boundary) &&
    !boundary.endsWith(" ")
  );
}

function parseMultipartParts(bytes: Uint8Array, boundary: string): readonly MultipartPart[] {
  const opening = new TextEncoder().encode(`--${boundary}`);
  if (!bodyBytesMatchAt(bytes, opening, 0)) {
    throw new TypeError("multipart body does not start with its boundary");
  }
  let cursor = opening.length;
  if (bodyBytesMatchAt(bytes, Uint8Array.of(45, 45), cursor)) {
    if (cursor + 2 !== bytes.length) {
      throw new TypeError("multipart closing boundary has trailing bytes");
    }
    return [];
  }
  cursor = consumeMultipartCrlf(bytes, cursor);
  const delimiter = new TextEncoder().encode(`\r\n--${boundary}`);
  const parts: MultipartPart[] = [];
  for (;;) {
    const next = findBodyBytes(bytes, delimiter, cursor);
    if (next < 0) {
      throw new TypeError("multipart body has no closing boundary");
    }
    parts.push(parseMultipartPart(bytes.subarray(cursor, next)));
    cursor = next + delimiter.length;
    if (bodyBytesMatchAt(bytes, Uint8Array.of(45, 45), cursor)) {
      if (cursor + 2 !== bytes.length) {
        throw new TypeError("multipart closing boundary has trailing bytes");
      }
      return parts;
    }
    cursor = consumeMultipartCrlf(bytes, cursor);
  }
}

function consumeMultipartCrlf(bytes: Uint8Array, index: number): number {
  if (bytes[index] !== 13 || bytes[index + 1] !== 10) {
    throw new TypeError("multipart boundary is not followed by CRLF");
  }
  return index + 2;
}

function findBodyBytes(haystack: Uint8Array, needle: Uint8Array, from: number): number {
  for (let index = from; index + needle.length <= haystack.length; index += 1) {
    if (bodyBytesMatchAt(haystack, needle, index)) {
      return index;
    }
  }
  return -1;
}

function bodyBytesMatchAt(haystack: Uint8Array, needle: Uint8Array, start: number): boolean {
  if (start + needle.length > haystack.length) {
    return false;
  }
  for (let offset = 0; offset < needle.length; offset += 1) {
    if (haystack[start + offset] !== needle[offset]) {
      return false;
    }
  }
  return true;
}

function parseMultipartPart(encapsulation: Uint8Array): MultipartPart {
  const separator = findBodyBytes(encapsulation, Uint8Array.of(13, 10, 13, 10), 0);
  if (separator < 0) {
    throw new TypeError("multipart part has no header terminator");
  }
  const headerText = BODY_UTF8_DECODER.decode(encapsulation.subarray(0, separator));
  const headers = new Map<string, string>();
  for (const line of headerText.split("\r\n")) {
    const colon = line.indexOf(":");
    const name = line.slice(0, colon).trim().toLowerCase();
    if (colon <= 0 || !BODY_TOKEN_PATTERN.test(name)) {
      throw new TypeError("multipart part header is malformed");
    }
    if (headers.has(name)) {
      throw new TypeError(`multipart part repeats header ${name}`);
    }
    if (name !== "content-disposition" && name !== "content-type") {
      throw new TypeError(`multipart part carries unsupported header ${name}`);
    }
    headers.set(name, line.slice(colon + 1).trim());
  }
  const disposition = parseMultipartDisposition(headers.get("content-disposition"));
  return {
    name: disposition.name,
    filename: disposition.filename,
    contentType: headers.get("content-type"),
    body: Uint8Array.from(encapsulation.subarray(separator + 4)),
  };
}

function parseMultipartDisposition(value: string | undefined): {
  readonly name: string;
  readonly filename: string | undefined;
} {
  if (value === undefined) {
    throw new TypeError("multipart part has no Content-Disposition header");
  }
  const segments = splitBodyQuoted(value, ";");
  if (segments[0]?.trim().toLowerCase() !== "form-data") {
    throw new TypeError("multipart part is not form-data");
  }
  const parameters = new Map<string, string>();
  for (const segment of segments.slice(1)) {
    const equals = segment.indexOf("=");
    const name = segment.slice(0, equals).trim().toLowerCase();
    if (equals <= 0 || (name !== "name" && name !== "filename") || parameters.has(name)) {
      throw new TypeError("multipart Content-Disposition parameter is malformed");
    }
    parameters.set(name, decodeDispositionValue(segment.slice(equals + 1).trim()));
  }
  const name = parameters.get("name");
  if (name === undefined) {
    throw new TypeError("multipart Content-Disposition has no name");
  }
  return { name, filename: parameters.get("filename") };
}

function splitBodyQuoted(input: string, separator: string): readonly string[] {
  const segments: string[] = [];
  let start = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < input.length; index += 1) {
    const character = input[index];
    if (escaped) {
      escaped = false;
    } else if (quoted && character === "\\") {
      escaped = true;
    } else if (character === '"') {
      quoted = !quoted;
    } else if (!quoted && character === separator) {
      segments.push(input.slice(start, index));
      start = index + 1;
    }
  }
  if (quoted || escaped) {
    throw new TypeError("quoted header value is unterminated");
  }
  segments.push(input.slice(start));
  return segments;
}

function decodeDispositionValue(value: string): string {
  if (!value.startsWith('"')) {
    if (!BODY_TOKEN_PATTERN.test(value)) {
      throw new TypeError("multipart disposition value is malformed");
    }
    return value;
  }
  if (!value.endsWith('"')) {
    throw new TypeError("multipart disposition value is unterminated");
  }
  let decoded = "";
  let escaped = false;
  for (const character of value.slice(1, -1)) {
    if (escaped) {
      decoded += character;
      escaped = false;
    } else if (character === "\\") {
      escaped = true;
    } else if (character === '"' || character.charCodeAt(0) < 0x20) {
      throw new TypeError("multipart disposition value is malformed");
    } else {
      decoded += character;
    }
  }
  return decoded;
}

function decodeMultipartPart(part: MultipartPart, field: MultipartFieldDescriptor): unknown {
  if (!field.filename && part.filename !== undefined) {
    throw new TypeError(`multipart part ${field.name} carries an unexpected filename`);
  }
  const payload = multipartPayload(field, part.contentType);
  if (payload === "binary") {
    return part.body;
  }
  const text = BODY_UTF8_DECODER.decode(part.body);
  return payload === "json" ? JSON.parse(text) : text;
}

function multipartPayload(
  field: MultipartFieldDescriptor,
  contentType: string | undefined,
): "json" | "text" | "binary" {
  if (field.contentType.kind === "none") {
    if (contentType !== undefined) {
      throw new TypeError(`multipart part ${field.name} carries an unexpected Content-Type`);
    }
    return field.payload;
  }
  if (contentType === undefined) {
    throw new TypeError(`multipart part ${field.name} has no Content-Type`);
  }
  if (field.contentType.kind === "fixed") {
    const actual = parseBodyMediaType(contentType);
    const declared = parseBodyMediaType(field.contentType.value);
    if (actual === null || declared === null || requestMediaScore(declared, actual, false) !== 2) {
      throw new TypeError(`multipart part ${field.name} has the wrong Content-Type`);
    }
    return field.payload;
  }
  const selected = selectPartMedia(contentType, field.contentType.admitted);
  const payload = field.payloads?.[selected];
  if (payload === undefined) {
    throw new TypeError(`multipart part ${field.name} has no payload decoder`);
  }
  return payload;
}

function selectPartMedia(contentType: string, admitted: readonly string[]): number {
  const actual = parseBodyMediaType(contentType);
  if (actual === null || actual.type === "*" || actual.subtype === "*") {
    throw new TypeError("multipart part Content-Type is not concrete");
  }
  let selected = -1;
  let selectedScore = -1;
  for (const [index, value] of admitted.entries()) {
    const declared = parseBodyMediaType(value);
    if (declared === null) {
      continue;
    }
    const score = requestMediaScore(declared, actual, false);
    if (score > selectedScore) {
      selected = index;
      selectedScore = score;
    }
  }
  if (selected < 0) {
    throw new TypeError("multipart part Content-Type matches no declared media type");
  }
  return selected;
}

function parseBodyMediaType(input: string): ParsedBodyMediaType | null {
  const typeEnd = consumeBodyToken(input, 0);
  if (typeEnd === 0 || input[typeEnd] !== "/") {
    return null;
  }
  const subtypeStart = typeEnd + 1;
  const subtypeEnd = consumeBodyToken(input, subtypeStart);
  if (subtypeEnd === subtypeStart) {
    return null;
  }

  const parameters: [string, string][] = [];
  const parameterNames = new Set<string>();
  let index = subtypeEnd;
  while (index < input.length) {
    index = consumeBodyOws(input, index);
    if (index === input.length || input[index] !== ";") {
      return null;
    }
    index = consumeBodyOws(input, index + 1);
    const nameStart = index;
    index = consumeBodyToken(input, index);
    if (index === nameStart || input[index] !== "=") {
      return null;
    }
    const name = input.slice(nameStart, index).toLowerCase();
    index += 1;
    let value = "";
    const tokenEnd = consumeBodyToken(input, index);
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
          if (escaped === undefined || !BODY_QUOTED_PAIR_PATTERN.test(escaped)) {
            return null;
          }
          value += escaped;
          index += 1;
        } else {
          if (!BODY_QDTEXT_PATTERN.test(character)) {
            return null;
          }
          value += character;
          index += 1;
        }
      }
      if (!closed) {
        return null;
      }
    }
    if (!BODY_SAFE_PARAMETER_VALUE_PATTERN.test(value) || parameterNames.has(name)) {
      return null;
    }
    parameterNames.add(name);
    parameters.push([name, name === "charset" ? value.toLowerCase() : value]);
  }
  parameters.sort(([left], [right]) => compareBodyAscii(left, right));
  return {
    type: input.slice(0, typeEnd).toLowerCase(),
    subtype: input.slice(subtypeStart, subtypeEnd).toLowerCase(),
    parameters,
  };
}

function consumeBodyToken(input: string, start: number): number {
  let index = start;
  while (index < input.length && BODY_TCHAR.includes(input[index])) {
    index += 1;
  }
  return index;
}

function consumeBodyOws(input: string, start: number): number {
  let index = start;
  while (input[index] === " " || input[index] === "\t") {
    index += 1;
  }
  return index;
}

function compareBodyAscii(left: string, right: string): number {
  const sharedLength = Math.min(left.length, right.length);
  for (let index = 0; index < sharedLength; index += 1) {
    const difference = left.charCodeAt(index) - right.charCodeAt(index);
    if (difference !== 0) {
      return difference;
    }
  }
  return left.length - right.length;
}

function serializeBodyMediaType(parsed: ParsedBodyMediaType): string {
  let serialized = `${parsed.type}/${parsed.subtype}`;
  for (const [name, value] of parsed.parameters) {
    const emitted = BODY_TOKEN_PATTERN.test(value)
      ? value
      : `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
    serialized += `;${name}=${emitted}`;
  }
  return serialized;
}

export type PathTemplatePart = { readonly literal: string } | { readonly parameter: string };

export type ProjectionContext = {
  readonly request: Request;
  readonly baseUrl: string;
  readonly pathTemplate: readonly (readonly PathTemplatePart[])[];
  readonly cookies?: Readonly<Record<string, string>>;
};

type ParameterDescriptor<S extends ParameterShape = ParameterShape> = {
  readonly location: "path" | "query" | "header" | "cookie";
  readonly name: string;
  readonly helper: ParameterHelper;
  readonly required: boolean;
  readonly allowReserved?: boolean;
  readonly shape: S;
  readonly sourcePointer: SourcePointer;
  readonly applicationPath: ApplicationPath;
  readonly queryParameterNames: readonly string[];
};

type RequiredParameterDescriptor<S extends ParameterShape> = ParameterDescriptor<S> & {
  readonly required: true;
};

type OptionalParameterDescriptor<S extends ParameterShape> = ParameterDescriptor<S> & {
  readonly required: false;
};

export function projectParameter<const S extends ParameterShape>(
  context: ProjectionContext,
  descriptor: RequiredParameterDescriptor<S>,
): ProjectedValue<S>;
export function projectParameter<const S extends ParameterShape>(
  context: ProjectionContext,
  descriptor: OptionalParameterDescriptor<S>,
): ProjectedValue<S> | undefined;
export function projectParameter(
  context: ProjectionContext,
  descriptor: ParameterDescriptor,
): unknown {
  try {
    const projected = projectWireValue(context, descriptor);
    if (projected === MISSING) {
      if (descriptor.required) {
        throw new TypeError(`required ${descriptor.location} parameter is absent`);
      }
      return undefined;
    }
    return projected;
  } catch (cause) {
    throw new OastsHandlerError({
      code: "parameter-decode",
      sourcePointer: descriptor.sourcePointer,
      applicationPath: descriptor.applicationPath,
      cause,
    });
  }
}

const MISSING = Symbol("missing parameter");

type QueryPair = {
  readonly name: string;
  readonly rawValue: string;
};

function projectWireValue(context: ProjectionContext, descriptor: ParameterDescriptor): unknown {
  if (descriptor.location === "query" && descriptor.allowReserved === true) {
    throw new TypeError("allowReserved query serialization cannot preserve parameter boundaries");
  }
  if (descriptor.helper === "content-json-path") {
    const raw = rawPathParameter(context, descriptor.name);
    return raw === MISSING ? MISSING : decodeJson(decodeComponent(raw), descriptor.shape);
  }
  if (descriptor.helper === "content-json-query") {
    if (descriptor.location === "cookie") {
      const raw = cookieValue(context, descriptor.name);
      return raw === MISSING ? MISSING : decodeJson(decodeComponent(raw), descriptor.shape);
    }
    const raw = singleQueryValue(queryPairs(context.request.url), descriptor.name);
    return raw === MISSING ? MISSING : decodeJson(decodeComponent(raw), descriptor.shape);
  }
  if (descriptor.helper === "content-json-header") {
    const raw = context.request.headers.get(descriptor.name);
    return raw === null ? MISSING : decodeJson(raw, descriptor.shape);
  }
  if (descriptor.location === "path") {
    const raw = rawPathParameter(context, descriptor.name);
    return raw === MISSING
      ? MISSING
      : decodePathValue(raw, descriptor.name, descriptor.helper, descriptor.shape);
  }
  if (descriptor.location === "query") {
    return decodeQueryValue(queryPairs(context.request.url), descriptor);
  }
  if (descriptor.location === "cookie") {
    const raw = cookieValue(context, descriptor.name);
    if (raw === MISSING) {
      return MISSING;
    }
    if (descriptor.helper !== "query-form") {
      throw new TypeError(`helper ${descriptor.helper} cannot decode a cookie parameter`);
    }
    return decodeSimple(raw, false, descriptor.shape, ",");
  }
  const raw = context.request.headers.get(descriptor.name);
  return raw === null ? MISSING : decodeHeaderValue(raw, descriptor.helper, descriptor.shape);
}

function cookieValue(context: ProjectionContext, name: string): string | typeof MISSING {
  if (context.cookies === undefined || !Object.hasOwn(context.cookies, name)) {
    return MISSING;
  }
  return context.cookies[name];
}

function rawPathParameter(
  context: ProjectionContext,
  parameterName: string,
): string | typeof MISSING {
  const requestUrl = new URL(context.request.url);
  const baseUrl = new URL(context.baseUrl, requestUrl);
  let pattern = escapeRegex(baseUrl.pathname.replace(/\/$/u, ""));
  const names: string[] = [];
  for (const segment of context.pathTemplate) {
    pattern += "/";
    for (const part of segment) {
      if ("literal" in part) {
        pattern += escapeRegex(part.literal);
      } else {
        pattern += "([^/]*)";
        names.push(part.parameter);
      }
    }
  }
  if (context.pathTemplate.length === 0 && pattern === "") {
    pattern = "/";
  }
  const match = new RegExp(`^${pattern}/?$`, "u").exec(requestUrl.pathname);
  if (match === null) {
    throw new TypeError("request URL does not match the operation path template");
  }
  for (const [index, value] of match.slice(1).entries()) {
    if (names[index] === parameterName) {
      return value;
    }
  }
  return MISSING;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function queryPairs(url: string): readonly QueryPair[] {
  const query = new URL(url).search.slice(1);
  if (query === "") {
    return [];
  }
  return query.split("&").map((pair) => {
    const equals = pair.indexOf("=");
    const rawName = equals < 0 ? pair : pair.slice(0, equals);
    return {
      name: decodeComponent(rawName),
      rawValue: equals < 0 ? "" : pair.slice(equals + 1),
    };
  });
}

function singleQueryValue(pairs: readonly QueryPair[], name: string): string | typeof MISSING {
  const matching = pairs.filter((pair) => pair.name === name);
  if (matching.length === 0) {
    return MISSING;
  }
  if (matching.length !== 1) {
    throw new TypeError(`query parameter ${name} occurs more than once`);
  }
  return matching[0].rawValue;
}

function decodePathValue(
  raw: string,
  name: string,
  helper: ParameterHelper,
  shape: ParameterShape,
): unknown {
  if (helper === "path-simple" || helper === "path-simple-explode") {
    return decodeSimple(raw, helper.endsWith("explode"), shape, ",");
  }
  if (helper === "path-label") {
    return decodeSimple(stripPrefix(raw, "."), false, shape, ",");
  }
  if (helper === "path-label-explode") {
    if (shapeAdmitsCollection(shape)) {
      throw new TypeError("exploded label serialization cannot preserve collection boundaries");
    }
    return decodeSimple(stripPrefix(raw, "."), true, shape, ".");
  }
  if (helper === "path-matrix") {
    return decodeSimple(stripPrefix(raw, `;${encodeName(name)}=`), false, shape, ",");
  }
  if (helper === "path-matrix-explode") {
    return decodeMatrixExplode(raw, name, shape);
  }
  throw new TypeError(`helper ${helper} cannot decode a path parameter`);
}

function shapeAdmitsCollection(shape: ParameterShape): boolean {
  if (shape.kind === "array" || shape.kind === "object") {
    return true;
  }
  if (shape.kind === "nullable") {
    return shapeAdmitsCollection(shape.value);
  }
  if (shape.kind === "union" || shape.kind === "intersection") {
    return shape.variants.some(shapeAdmitsCollection);
  }
  return false;
}

function decodeHeaderValue(raw: string, helper: ParameterHelper, shape: ParameterShape): unknown {
  if (helper !== "header-simple" && helper !== "header-simple-explode") {
    throw new TypeError(`helper ${helper} cannot decode a header parameter`);
  }
  return decodeSimple(raw, helper === "header-simple-explode", shape, ",", false);
}

function decodeQueryValue(pairs: readonly QueryPair[], descriptor: ParameterDescriptor): unknown {
  const { helper, name, shape } = descriptor;
  if (helper === "query-form") {
    const raw = singleQueryValue(pairs, name);
    return raw === MISSING ? MISSING : decodeSimple(raw, false, shape, ",");
  }
  if (helper === "query-form-explode") {
    return decodeQueryFormExplode(pairs, descriptor);
  }
  if (
    helper === "query-space-delimited" ||
    helper === "query-space-delimited-object" ||
    helper === "query-pipe-delimited" ||
    helper === "query-pipe-delimited-object"
  ) {
    const raw = singleQueryValue(pairs, name);
    if (raw === MISSING) {
      return MISSING;
    }
    const separator = helper.startsWith("query-space") ? "%20" : "%7C";
    return decodeDelimited(raw, separator, shape);
  }
  if (helper === "query-deep-object" || helper === "query-deep-object-extended") {
    return decodeDeepObject(pairs, name, shape, helper === "query-deep-object-extended");
  }
  throw new TypeError(`helper ${helper} cannot decode a query parameter`);
}

function decodeQueryFormExplode(
  pairs: readonly QueryPair[],
  descriptor: ParameterDescriptor,
): unknown {
  const direct = pairs.filter((pair) => pair.name === descriptor.name);
  return decodeComposedShape(
    descriptor.shape,
    direct.length === 1 && direct[0].rawValue === "null",
    (shape) => {
      if (shape.kind === "array") {
        return direct.length === 0
          ? MISSING
          : direct.map((pair) => decodeComponentValue(pair.rawValue, shape.items));
      }
      if (shape.kind === "object") {
        const claimed = pairs.filter(
          (pair) =>
            Object.hasOwn(shape.properties, pair.name) ||
            (shape.additional !== false && !descriptor.queryParameterNames.includes(pair.name)),
        );
        return claimed.length === 0
          ? MISSING
          : decodeObjectPairs(claimed, shape, decodeComponentValue);
      }
      const raw = singleQueryValue(pairs, descriptor.name);
      return raw === MISSING ? MISSING : decodeComponentValue(raw, shape);
    },
  );
}

function decodeDelimited(raw: string, separator: "%20" | "%7C", shape: ParameterShape): unknown {
  const parts = raw === "" ? [] : raw.split(separator);
  return decodeComposedShape(shape, raw === "null", (structural) => {
    if (structural.kind === "array") {
      return parts.map((part) => decodeComponentValue(part, structural.items));
    }
    if (structural.kind === "object") {
      return decodeAlternatingObject(parts, structural, decodeComponent, decodeComponentValue);
    }
    throw new TypeError("delimited query serialization requires an array or object schema");
  });
}

function decodeDeepObject(
  pairs: readonly QueryPair[],
  name: string,
  shape: ParameterShape,
  extended: boolean,
): unknown {
  const direct = pairs.filter((pair) => pair.name === name);
  const prefix = `${name}[`;
  const nested = pairs.flatMap((pair) =>
    pair.name.startsWith(prefix) && pair.name.endsWith("]")
      ? [{ name: pair.name.slice(prefix.length, -1), rawValue: pair.rawValue }]
      : [],
  );
  return decodeComposedShape(
    shape,
    direct.length === 1 && direct[0].rawValue === "null",
    (structural) => {
      if (extended && structural.kind === "array") {
        if (nested.length === 0) {
          return MISSING;
        }
        const indexed = nested.map((pair) => ({ index: parseIndex(pair.name), pair }));
        indexed.sort((left, right) => left.index - right.index);
        indexed.forEach((entry, index) => {
          if (entry.index !== index) {
            throw new TypeError("deep-object array indices must be contiguous from zero");
          }
        });
        return indexed.map((entry) => decodeComponentValue(entry.pair.rawValue, structural.items));
      }
      if (structural.kind === "object") {
        return nested.length === 0
          ? MISSING
          : decodeObjectPairs(nested, structural, decodeComponentValue);
      }
      if (extended) {
        const raw = direct.length === 0 ? MISSING : singleQueryValue(direct, name);
        return raw === MISSING ? MISSING : decodeComponentValue(raw, structural);
      }
      throw new TypeError("deep-object serialization requires an object schema");
    },
  );
}

function parseIndex(value: string): number {
  const index = Number(value);
  if (!Number.isSafeInteger(index) || index < 0 || String(index) !== value) {
    throw new TypeError("deep-object array index is malformed");
  }
  return index;
}

function decodeMatrixExplode(raw: string, name: string, shape: ParameterShape): unknown {
  const entries = raw === "" ? [] : matrixEntries(raw);
  return decodeComposedShape(
    shape,
    entries.length === 1 && entries[0].name === name && entries[0].rawValue === "null",
    (structural) => {
      if (raw === "") {
        if (structural.kind === "array") {
          return [];
        }
        if (structural.kind === "object") {
          return decodeObjectPairs(entries, structural, decodeComponentValue);
        }
        throw new TypeError("empty matrix serialization requires a collection schema");
      }
      if (structural.kind === "array") {
        if (entries.some((entry) => entry.name !== name)) {
          throw new TypeError("matrix array entry has the wrong parameter name");
        }
        return entries.map((entry) => decodeComponentValue(entry.rawValue, structural.items));
      }
      if (structural.kind === "object") {
        return decodeObjectPairs(entries, structural, decodeComponentValue);
      }
      if (entries.length !== 1 || entries[0].name !== name) {
        throw new TypeError("matrix primitive has malformed framing");
      }
      return decodeComponentValue(entries[0].rawValue, structural);
    },
  );
}

function matrixEntries(raw: string): readonly QueryPair[] {
  if (!raw.startsWith(";")) {
    throw new TypeError("matrix parameter lacks its semicolon prefix");
  }
  return raw
    .slice(1)
    .split(";")
    .map((entry) => {
      const equals = entry.indexOf("=");
      if (equals < 0) {
        throw new TypeError("matrix parameter entry lacks an equals sign");
      }
      return {
        name: decodeComponent(entry.slice(0, equals)),
        rawValue: entry.slice(equals + 1),
      };
    });
}

function decodeSimple(
  raw: string,
  explode: boolean,
  shape: ParameterShape,
  explodedSeparator: "," | ".",
  percentEncoded = true,
): unknown {
  const decodeName = percentEncoded ? decodeComponent : (value: string) => value;
  const decodeValue = percentEncoded ? decodeComponentValue : decodeScalar;
  return decodeComposedShape(shape, raw === "null", (structural) => {
    if (structural.kind === "array") {
      const separator = explode ? explodedSeparator : ",";
      return raw === ""
        ? []
        : raw.split(separator).map((part) => decodeValue(part, structural.items));
    }
    if (structural.kind === "object") {
      if (explode && !percentEncoded) {
        return decodeHeaderExplodedObject(raw, structural);
      }
      const parts = raw === "" ? [] : raw.split(explode ? explodedSeparator : ",");
      if (explode) {
        return decodeExplodedObject(parts, structural, decodeName, decodeValue);
      }
      return decodeAlternatingObject(parts, structural, decodeName, decodeValue);
    }
    return decodeValue(raw, structural);
  });
}

function decodeHeaderExplodedObject(raw: string, shape: ObjectShape): unknown {
  const pairs: QueryPair[] = [];
  for (const part of raw === "" ? [] : raw.split(",")) {
    const equals = part.indexOf("=");
    const name = equals < 0 ? "" : part.slice(0, equals);
    const startsEntry =
      equals >= 0 &&
      (pairs.length === 0 || Object.hasOwn(shape.properties, name) || shape.additional !== false);
    if (startsEntry) {
      pairs.push({ name, rawValue: part.slice(equals + 1) });
      continue;
    }
    const previous = pairs.pop();
    if (previous === undefined) {
      throw new TypeError("exploded object entry lacks an equals sign");
    }
    pairs.push({ name: previous.name, rawValue: `${previous.rawValue},${part}` });
  }
  return decodeObjectPairs(pairs, shape, decodeScalar);
}

function decodeExplodedObject(
  parts: readonly string[],
  shape: ObjectShape,
  decodeName: (raw: string) => string,
  decodeValue: (raw: string, shape: ParameterShape) => unknown,
): unknown {
  const pairs = parts.map((part) => {
    const equals = part.indexOf("=");
    if (equals < 0) {
      throw new TypeError("exploded object entry lacks an equals sign");
    }
    return {
      name: decodeName(part.slice(0, equals)),
      rawValue: part.slice(equals + 1),
    };
  });
  return decodeObjectPairs(pairs, shape, decodeValue);
}

function decodeAlternatingObject(
  parts: readonly string[],
  shape: ObjectShape,
  decodeName: (raw: string) => string,
  decodeValue: (raw: string, shape: ParameterShape) => unknown,
): unknown {
  if (parts.length % 2 !== 0) {
    throw new TypeError("non-exploded object has an odd number of components");
  }
  const pairs: QueryPair[] = [];
  for (let index = 0; index < parts.length; index += 2) {
    pairs.push({ name: decodeName(parts[index]), rawValue: parts[index + 1] });
  }
  return decodeObjectPairs(pairs, shape, decodeValue);
}

function decodeObjectPairs(
  pairs: readonly QueryPair[],
  shape: ObjectShape,
  decodeValue: (raw: string, shape: ParameterShape) => unknown,
): unknown {
  const decoded: Record<string, unknown> = {};
  for (const pair of pairs) {
    if (Object.hasOwn(decoded, pair.name)) {
      throw new TypeError(`object property ${pair.name} occurs more than once`);
    }
    const property = Object.entries(shape.properties).find(([name]) => name === pair.name)?.[1];
    let propertyShape: ParameterShape | false;
    if (property !== undefined) {
      propertyShape = property.shape;
    } else if (shape.additional === true) {
      propertyShape = UNKNOWN_SHAPE;
    } else {
      propertyShape = shape.additional;
    }
    if (propertyShape === false) {
      throw new TypeError(`object property ${pair.name} is not declared`);
    }
    define(decoded, pair.name, decodeValue(pair.rawValue, propertyShape));
  }
  for (const [name, property] of Object.entries(shape.properties)) {
    if (property.required && !Object.hasOwn(decoded, name)) {
      throw new TypeError(`required object property ${name} is absent`);
    }
  }
  return decoded;
}

const UNKNOWN_SHAPE: ParameterShape = { kind: "unknown" };

function decodeComponentValue(raw: string, shape: ParameterShape): unknown {
  return decodeScalar(decodeComponent(raw), shape);
}

function decodeScalar(value: string, shape: ParameterShape): unknown {
  if (shape.kind === "nullable") {
    return value === "null" ? null : decodeScalar(value, shape.value);
  }
  if (shape.kind === "union") {
    return decodeSingleCandidate(shape.variants, (variant) => decodeScalar(value, variant));
  }
  if (shape.kind === "intersection") {
    return decodeIntersection(shape.variants, (variant) => decodeScalar(value, variant));
  }
  if (shape.kind === "literal") {
    const candidates = shape.values.filter(
      (candidate) =>
        candidate === null ||
        typeof candidate === "string" ||
        typeof candidate === "number" ||
        typeof candidate === "boolean",
    );
    return decodeSingleCandidate(candidates, (candidate) => {
      if (String(candidate) !== value) {
        throw new TypeError("literal does not match");
      }
      return candidate;
    });
  }
  if (shape.kind === "unknown") {
    return value;
  }
  if (shape.kind === "string") {
    return validateScalarEnum(value, shape);
  }
  if (shape.kind === "boolean") {
    if (value === "true") {
      return validateScalarEnum(true, shape);
    }
    if (value === "false") {
      return validateScalarEnum(false, shape);
    }
    throw new TypeError("boolean parameter is neither true nor false");
  }
  if (shape.kind === "number" || shape.kind === "integer") {
    const decoded = Number(value);
    if (!Number.isFinite(decoded) || String(decoded) !== value) {
      throw new TypeError("number parameter is not in canonical finite form");
    }
    if (shape.kind === "integer" && !Number.isInteger(decoded)) {
      throw new TypeError("integer parameter has a fractional value");
    }
    return validateScalarEnum(decoded, shape);
  }
  if (shape.kind === "null") {
    if (value === "null") {
      return validateScalarEnum(null, shape);
    }
    throw new TypeError("null parameter is not the string null");
  }
  if (shape.kind === "never") {
    throw new TypeError("no value inhabits the parameter schema");
  }
  throw new TypeError(`a ${shape.kind} schema cannot decode one scalar component`);
}

function validateScalarEnum(value: unknown, shape: ScalarShape): unknown {
  if (shape.enum !== undefined && !shape.enum.some((candidate) => jsonEqual(candidate, value))) {
    throw new TypeError("parameter is outside the declared enum");
  }
  return value;
}

function decodeComposedShape(
  shape: ParameterShape,
  nullWireValue: boolean,
  decode: (structural: ParameterShape) => unknown,
): unknown {
  if (shape.kind === "nullable") {
    return decodeSingleCandidate([NULL_SHAPE, shape.value], (candidate) => {
      if (candidate.kind !== "null") {
        return decodeComposedShape(candidate, nullWireValue, decode);
      }
      if (!nullWireValue) {
        throw new TypeError("wire value is not null");
      }
      return null;
    });
  }
  if (shape.kind === "union") {
    return decodeSingleCandidate(shape.variants, (variant) =>
      decodeComposedShape(variant, nullWireValue, decode),
    );
  }
  if (shape.kind === "intersection") {
    return decodeIntersection(shape.variants, (variant) =>
      decodeComposedShape(variant, nullWireValue, decode),
    );
  }
  return decode(shape);
}

const NULL_SHAPE: ParameterShape = { kind: "null" };

function decodeJson(text: string, shape: ParameterShape): unknown {
  return validateJson(JSON.parse(text), shape);
}

function validateJson(value: unknown, shape: ParameterShape): unknown {
  if (shape.kind === "nullable") {
    return value === null ? null : validateJson(value, shape.value);
  }
  if (shape.kind === "union") {
    return decodeSingleCandidate(shape.variants, (variant) => validateJson(value, variant));
  }
  if (shape.kind === "intersection") {
    return decodeIntersection(shape.variants, (variant) => validateJson(value, variant));
  }
  if (shape.kind === "literal") {
    return decodeSingleCandidate(shape.values, (candidate) => {
      if (!jsonEqual(candidate, value)) {
        throw new TypeError("JSON literal does not match");
      }
      return value;
    });
  }
  if (shape.kind === "unknown") {
    return value;
  }
  if (shape.kind === "never") {
    throw new TypeError("no value inhabits the parameter schema");
  }
  if (shape.kind === "null") {
    if (value !== null) {
      throw new TypeError("JSON parameter is not null");
    }
    return validateScalarEnum(value, shape);
  }
  if (shape.kind === "string" || shape.kind === "boolean") {
    if (typeof value !== shape.kind) {
      throw new TypeError(`JSON parameter is not a ${shape.kind}`);
    }
    return validateScalarEnum(value, shape);
  }
  if (shape.kind === "number" || shape.kind === "integer") {
    if (typeof value !== "number" || !Number.isFinite(value)) {
      throw new TypeError("JSON parameter is not a finite number");
    }
    if (shape.kind === "integer" && !Number.isInteger(value)) {
      throw new TypeError("JSON parameter is not an integer");
    }
    return validateScalarEnum(value, shape);
  }
  if (shape.kind === "array") {
    if (!Array.isArray(value)) {
      throw new TypeError("JSON parameter is not an array");
    }
    return value.map((item) => validateJson(item, shape.items));
  }
  if (!isRecord(value)) {
    throw new TypeError("JSON parameter is not an object");
  }
  const decoded: Record<string, unknown> = {};
  for (const [name, property] of Object.entries(shape.properties)) {
    if (Object.hasOwn(value, name)) {
      define(decoded, name, validateJson(value[name], property.shape));
    } else if (property.required) {
      throw new TypeError(`required JSON object property ${name} is absent`);
    }
  }
  for (const [name, item] of Object.entries(value)) {
    if (Object.hasOwn(shape.properties, name)) {
      continue;
    }
    const additionalShape = shape.additional === true ? UNKNOWN_SHAPE : shape.additional;
    if (additionalShape === false) {
      throw new TypeError(`JSON object property ${name} is not declared`);
    }
    define(decoded, name, validateJson(item, additionalShape));
  }
  return decoded;
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function decodeSingleCandidate<T, R>(candidates: readonly T[], decode: (candidate: T) => R): R {
  const decoded: R[] = [];
  for (const candidate of candidates) {
    try {
      decoded.push(decode(candidate));
    } catch {
      continue;
    }
  }
  if (decoded.length === 0) {
    throw new TypeError("parameter matches no declared schema branch");
  }
  const first = decoded[0];
  if (decoded.some((candidate) => !jsonEqual(candidate, first))) {
    throw new TypeError("parameter has more than one distinct declared decoding");
  }
  return first;
}

function decodeIntersection(
  candidates: readonly ParameterShape[],
  decode: (candidate: ParameterShape) => unknown,
): unknown {
  if (candidates.length === 0) {
    throw new TypeError("an empty intersection has no projection plan");
  }
  const decoded = candidates.map(decode);
  const first = decoded[0];
  if (decoded.some((candidate) => !jsonEqual(candidate, first))) {
    throw new TypeError("intersection branches produced distinct values");
  }
  return first;
}

function jsonEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) {
    return true;
  }
  if (Array.isArray(left) && Array.isArray(right)) {
    return (
      left.length === right.length && left.every((value, index) => jsonEqual(value, right[index]))
    );
  }
  if (!isRecord(left) || !isRecord(right)) {
    return false;
  }
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every((key) => Object.hasOwn(right, key) && jsonEqual(left[key], right[key]))
  );
}

function stripPrefix(value: string, prefix: string): string {
  if (!value.startsWith(prefix)) {
    throw new TypeError(`parameter lacks the ${prefix} prefix`);
  }
  return value.slice(prefix.length);
}

function decodeComponent(value: string): string {
  return decodeURIComponent(value);
}

function encodeName(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/gu,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function define(target: Record<string, unknown>, name: string, value: unknown): void {
  Object.defineProperty(target, name, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}
