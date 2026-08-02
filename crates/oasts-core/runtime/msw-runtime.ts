// MSW handler kernel.
//
// Handlers mock the server side, so this module deliberately imports nothing from the client
// runtime — not the transport, not the result model, not a validation engine. `SourcePointer` and
// `ApplicationPath` are therefore re-declared here rather than imported from `result.ts`, and a
// drift test pins the two declarations structurally identical. The duplication is the price of
// letting the MSW artifact be consumed on its own, without the client artifact in the tree.

import { HttpResponse } from "msw";

export type SourcePointer = { readonly logicalSourceId: string; readonly jsonPointer: string };
export type ApplicationPath = readonly (string | number)[]; // empty array = the root value

type MediaKey = "contentType" | "body";
type CarriesMediaKey<T> = [Extract<keyof T, MediaKey>] extends [never] ? false : true;
export type NoPayloadGuard<T, NoPayloadMatch> = T extends { match: NoPayloadMatch }
  ? CarriesMediaKey<T> extends true
    ? { readonly __noPayloadResponseTakesNoContentTypeOrBody: never }
    : unknown
  : unknown;

/** How a declared response media is written to the wire, as decided at generation time. */
export type ResponsePayloadKind = "json" | "text" | "binary";

/**
 * Builds the response a resolver asked for.
 *
 * `payloads` maps each of the operation's declared content types onto how it is written. The kernel
 * is *told* rather than asked on purpose: it used to classify the content type itself, and its rule
 * disagreed with the compiler's on `text/json` — which this compiler counts as JSON, being the
 * de-facto alias. A body typed as its declared schema was then written with `String(...)` and
 * reached the wire as `[object Object]`. Two copies of one rule is the defect; deleting the copy
 * is the fix.
 */
export function respondWith(
  status: number,
  contentType: string | null,
  body: unknown,
  payloads: Readonly<Record<string, ResponsePayloadKind>>,
): HttpResponse<never>;
export function respondWith(
  status: number,
  contentType: string | null,
  body: unknown,
  payloads: Readonly<Record<string, ResponsePayloadKind>>,
) {
  if (contentType === undefined || (contentType === null && body !== null)) {
    throw new TypeError("a no-payload response cannot carry contentType or body");
  }
  if (contentType === null) {
    return new HttpResponse(null, { status });
  }

  const payload = Object.hasOwn(payloads, contentType) ? payloads[contentType] : undefined;
  if (payload === undefined) {
    // Unreachable through the typed surface, which admits only declared content types. Untyped
    // JavaScript can still get here, and guessing would put the wrong bytes on the wire.
    throw new TypeError(`content type ${contentType} is not declared for this response`);
  }
  const responseBody =
    payload === "json"
      ? (JSON.stringify(body) ?? null)
      : payload === "binary"
        ? bytesOf(body)
        : String(body);
  return new HttpResponse(responseBody, {
    status,
    headers: { "Content-Type": contentType },
  });
}

// No declared return type: a narrowed `Uint8Array` carries an `ArrayBufferLike` buffer, which is
// wider than the `BodyInit` annotation would admit even though every value returned here is one
// the Response constructor accepts. Inference keeps it honest without an assertion.
function bytesOf(body: unknown) {
  if (body instanceof Uint8Array || body instanceof ArrayBuffer) {
    return body;
  }
  if (body === null || body === undefined) {
    return null;
  }
  throw new TypeError("a binary response body must be bytes");
}

/**
 * The ways a real `Request` can fail to project onto the declared operation input.
 *
 * Each value names one class: an undecodable path, query, header or cookie value; a missing or
 * mismatched `Content-Type`; a malformed JSON, text or binary body; malformed multipart framing or
 * parts; and an absent body where the document requires one.
 */
export type HandlerErrorCode =
  | "parameter-decode"
  | "content-type-mismatch"
  | "body-decode"
  | "multipart-decode"
  | "body-missing";

/**
 * Raised when a request cannot be projected onto the operation's typed input.
 *
 * It never synthesizes an HTTP response. A handler that answered a malformed request with a
 * plausible-looking mock would hide the defect precisely where a test is meant to reveal it, so the
 * handler invocation rejects instead and the typed resolver is never called.
 */
export class OastsHandlerError extends Error {
  override readonly name: "OastsHandlerError" = "OastsHandlerError";
  readonly code: HandlerErrorCode;
  readonly sourcePointer: SourcePointer;
  /** Null when no value path exists, as for a content-type mismatch. */
  readonly applicationPath: ApplicationPath | null;
  override readonly cause: unknown;

  constructor(fields: {
    code: HandlerErrorCode;
    sourcePointer: SourcePointer;
    applicationPath: ApplicationPath | null;
    cause: unknown;
  }) {
    super();
    this.code = fields.code;
    this.sourcePointer = fields.sourcePointer;
    this.applicationPath = fields.applicationPath;
    this.cause = fields.cause;
  }
}
