// Response media-essence classifier and UnknownHttpError mapping vectors gating the client conformance
// gate for the oasts client artifact. NEVER regenerate these from implementation output.
//
// Classifier vectors are derived from the frozen contract's normative, exhaustive, ORDERED
// clause list: "(1) `text/event-stream` and streaming-marked types -> the streaming
// branch ... checked first so a streaming-marked `+json` type ... is never silently buffered;
// (2) `application/json` and any media type whose subtype ends in `+json` -> JSON
// decoding; (3) `application/xml`, `text/xml`, and any `+xml` suffix with a structurally projected
// schema -> generation diagnostic; schema-absent and string-projected XML-family media are binary;
// (4) `multipart/*` response bodies -> generation diagnostic; (5)
// `application/x-www-form-urlencoded` and all other `text/*` -> text decoding; (6) everything
// else -> `ArrayBuffer`." The `expectedClass` values below name each clause's outcome:
// 'streaming', 'json', 'xml-diagnostic', 'multipart-diagnostic', 'text', 'binary' (clause 6's
// ArrayBuffer outcome).
//
// UnknownHttpError mapping vectors are derived from the frozen contract's unmatched-response
// algorithm ("bodyless handling first; an actual `application/json`/`+json` type decodes as
// `unknown`; `text/*` and `application/x-www-form-urlencoded` decode as text; every other or
// missing content type yields `ArrayBuffer`") and the frozen contract's frozen `UnknownHttpError`
// union, which the frozen contract states follows that algorithm "one-to-one" (bodyless -> `empty`;
// JSON/`+json` -> `json`; `text/*` (including the unregistered `text/json`) and form-urlencoded ->
// `text`; every other or missing
// content type -> `binary`).

export type ClassifierClass =
  | "streaming"
  | "json"
  | "xml-diagnostic"
  | "multipart-diagnostic"
  | "text"
  | "binary";

export type ClassifierVector = {
  readonly cite: string;
  readonly description: string;
  readonly mediaType: string;
  /** The `x-oasts-streaming: true` Media Type Object extension. */
  readonly streamingMarked?: boolean;
  /** The schema projection relevant to XML-family response classification; absent means no schema. */
  readonly schemaProjection?: "string" | "object";
  readonly expectedClass: ClassifierClass;
};

export const CLASSIFIER_VECTORS: readonly ClassifierVector[] = [
  // Clause 1: streaming, checked first.
  {
    cite: "frozen contract clause 1",
    description: "text/event-stream is always a streaming branch.",
    mediaType: "text/event-stream",
    expectedClass: "streaming",
  },
  {
    cite: "frozen contract clause 1",
    description:
      "A non-SSE +json type explicitly marked x-oasts-streaming: true is still routed to " +
      "streaming, because clause 1 is checked before clause 2 — a streaming-marked +json " +
      "type must never be silently buffered as JSON.",
    mediaType: "application/stream+json",
    streamingMarked: true,
    expectedClass: "streaming",
  },
  // Clause 2: JSON, exact and +json suffix.
  {
    cite: "frozen contract clause 2",
    description: "application/json decodes as JSON.",
    mediaType: "application/json",
    expectedClass: "json",
  },
  {
    cite: "frozen contract clause 2",
    description: "A +json suffix subtype decodes as JSON.",
    mediaType: "application/vnd.api+json",
    expectedClass: "json",
  },
  // Clause 3: structural XML is a diagnostic; opaque XML is binary.
  {
    cite: "frozen contract clause 3",
    description: "application/xml with an object schema is a generation diagnostic.",
    mediaType: "application/xml",
    schemaProjection: "object",
    expectedClass: "xml-diagnostic",
  },
  {
    cite: "frozen contract clause 3",
    description: "text/xml with an object schema is a generation diagnostic.",
    mediaType: "text/xml",
    schemaProjection: "object",
    expectedClass: "xml-diagnostic",
  },
  {
    cite: "frozen contract clause 3",
    description: "A +xml suffix subtype with an object schema is a generation diagnostic.",
    mediaType: "application/atom+xml",
    schemaProjection: "object",
    expectedClass: "xml-diagnostic",
  },
  {
    cite: "frozen contract clause 3",
    description: "Schemaless application/xml is an opaque binary response.",
    mediaType: "application/xml",
    expectedClass: "binary",
  },
  {
    cite: "frozen contract clause 3",
    description: "String-projected text/xml is an opaque binary response.",
    mediaType: "text/xml",
    schemaProjection: "string",
    expectedClass: "binary",
  },
  {
    cite: "frozen contract clause 3",
    description: "Schemaless image/svg+xml is an opaque binary response.",
    mediaType: "image/svg+xml",
    expectedClass: "binary",
  },
  // Clause 4: multipart, generation diagnostic.
  {
    cite: "frozen contract clause 4",
    description: "multipart/mixed response bodies are a generation diagnostic (not decoded).",
    mediaType: "multipart/mixed",
    expectedClass: "multipart-diagnostic",
  },
  // Clause 5: text.
  {
    cite: "frozen contract clause 5",
    description: "application/x-www-form-urlencoded decodes as raw text.",
    mediaType: "application/x-www-form-urlencoded",
    expectedClass: "text",
  },
  {
    cite: "frozen contract clause 5",
    description: "text/plain decodes as text.",
    mediaType: "text/plain",
    expectedClass: "text",
  },
  {
    cite: "frozen contract clause 5",
    description:
      "text/json is unregistered — RFC 8259 registers application/json — so clause 2 does not " +
      "claim it and it decodes as the text/* it declares.",
    mediaType: "text/json",
    expectedClass: "text",
  },
  {
    cite: "frozen contract clause 5",
    description: "text/html decodes as text.",
    mediaType: "text/html",
    expectedClass: "text",
  },
  // Clause 6: everything else -> ArrayBuffer.
  {
    cite: "frozen contract clause 6",
    description: "application/octet-stream falls through to the binary (ArrayBuffer) branch.",
    mediaType: "application/octet-stream",
    expectedClass: "binary",
  },
  {
    cite: "frozen contract clause 6",
    description: "image/png falls through to the binary branch.",
    mediaType: "image/png",
    expectedClass: "binary",
  },
  {
    cite: "frozen contract clause 6",
    description: "application/pdf falls through to the binary branch.",
    mediaType: "application/pdf",
    expectedClass: "binary",
  },
];

export type UnknownHttpErrorKind = "empty" | "json" | "text" | "binary";

export type UnknownHttpErrorVector = {
  readonly cite: string;
  readonly description: string;
  readonly contentType: string | null;
  readonly bodyPresent: boolean;
  /**
   * True when the response arrives on a status Fetch itself fixes to a null body (HEAD,
   * 204/205/304) — documentation only, since the algorithm's actual discriminant is body
   * presence, not the reason a body is absent (see the two 'empty' vectors below).
   */
  readonly bodylessStatus?: boolean;
  readonly expectedKind: UnknownHttpErrorKind;
};

export const UNKNOWN_HTTP_ERROR_VECTORS: readonly UnknownHttpErrorVector[] = [
  {
    cite: "frozen contract",
    description:
      "A Fetch-bodyless status (e.g. 204) with no body: bodyless handling runs first and " +
      "produces `empty` regardless of the declared/absent Content-Type.",
    contentType: null,
    bodyPresent: false,
    bodylessStatus: true,
    expectedKind: "empty",
  },
  {
    cite: "frozen contract",
    description:
      "An ordinary 200 status with a zero-byte body and an application/json Content-Type: " +
      "bodyless handling still runs first and wins over the JSON content-type rule, proving " +
      'the algorithm\'s stated clause order ("bodyless handling first") rather than ' +
      "content-type dispatch alone.",
    contentType: "application/json",
    bodyPresent: false,
    bodylessStatus: false,
    expectedKind: "empty",
  },
  {
    cite: "frozen contract",
    description: "application/json with a body decodes as json.",
    contentType: "application/json",
    bodyPresent: true,
    expectedKind: "json",
  },
  {
    cite: "frozen contract",
    description: "A +json suffix subtype (application/problem+json) with a body decodes as json.",
    contentType: "application/problem+json",
    bodyPresent: true,
    expectedKind: "json",
  },
  {
    cite: "frozen contract",
    description: "text/json with a body decodes as text.",
    contentType: "text/json",
    bodyPresent: true,
    expectedKind: "text",
  },
  {
    cite: "frozen contract",
    description: "text/plain with a body decodes as text.",
    contentType: "text/plain",
    bodyPresent: true,
    expectedKind: "text",
  },
  {
    cite: "frozen contract",
    description: "application/x-www-form-urlencoded with a body decodes as text.",
    contentType: "application/x-www-form-urlencoded",
    bodyPresent: true,
    expectedKind: "text",
  },
  {
    cite: "frozen contract",
    description: "application/octet-stream with a body yields binary (ArrayBuffer).",
    contentType: "application/octet-stream",
    bodyPresent: true,
    expectedKind: "binary",
  },
  {
    cite: "frozen contract",
    description:
      "A missing Content-Type with a body yields binary — Oasts never guesses the sole declared type.",
    contentType: null,
    bodyPresent: true,
    expectedKind: "binary",
  },
];
