// Relative `.ts` import suffixes are contractual: the Rust embedding engine rewrites them to the configured emit extension.
import type * as StandardSchemaV1 from './standard-schema.ts';

export type ResponseMeta = {
  readonly url: string;      // provenance URL: fetchedResponse.url || finalRequest.url, captured
                             // before response middleware — never a replacement's empty url
  readonly status: number;
  readonly headers: Headers; // a decoupled snapshot, never the live Response headers
};

export type RequestPhaseFailure =
  | { outcome: 'auth'; ok: false; message: string; triedAlternatives: readonly (readonly string[])[]; cause?: unknown }
  | { outcome: 'aborted'; ok: false; reason: unknown }
  | { outcome: 'timeout'; ok: false; reason: unknown }
  | { outcome: 'network'; ok: false; cause: TypeError }
  | { outcome: 'request-encode'; ok: false; message: string; cause?: unknown }
  | { outcome: 'request-validation'; ok: false; issues: readonly StandardSchemaV1.Issue[] }
  | { outcome: 'request-transform'; ok: false; error: TransformError }
  | { outcome: 'request-middleware'; ok: false; cause: unknown }
  | { outcome: 'cookie-params-unsendable'; ok: false; names: readonly string[] };

export type ResponsePhaseFailure<Match extends string | number> =
  | { outcome: 'response-aborted'; ok: false; match: Match | null; status: number; reason: unknown; meta: ResponseMeta }
  | { outcome: 'response-timeout'; ok: false; match: Match | null; status: number; reason: unknown; meta: ResponseMeta }
  | { outcome: 'response-decode'; ok: false; match: Match | null; status: number; message: string; cause?: unknown; meta: ResponseMeta }
  | { outcome: 'response-validation'; ok: false; match: Match | null; status: number; issues: readonly StandardSchemaV1.Issue[]; meta: ResponseMeta }
  | { outcome: 'response-transform'; ok: false; match: Match | null; status: number; error: TransformError; meta: ResponseMeta }
  | { outcome: 'response-middleware'; ok: false; match: Match | null; status: number; cause: unknown; meta: ResponseMeta };

export type UnknownHttpError =
  | { kind: 'empty';  contentType: string | null; body: undefined }
  | { kind: 'json';   contentType: string;        body: unknown }
  | { kind: 'text';   contentType: string;        body: string }
  | { kind: 'binary'; contentType: string | null; body: ArrayBuffer };

// Distributive over R (the type parameter is naked), so a union of success arms yields one
// envelope per arm. Per-arm meta typing — plain ResponseMeta, or the TypedHeaders intersection
// when that arm declares response headers — therefore falls out without being restated.
export type SuccessEnvelope<R> = R extends { readonly ok: true; readonly data: infer D; readonly meta: infer M }
  ? { data: D; meta: M }
  : never;

// One dispatched server-sent event. `data` is the event's data buffer after JSON decoding — the
// declared schema describes that decoded value, never the raw field text — and the three optional
// members carry the SSE fields the standard makes available to a dispatched event.
export type SseEvent<TData> = {
  data: TData;
  event?: string;
  id?: string;
  retry?: number;
};

export type StreamFailure =
  | { kind: 'sse'; eventsYielded: number; cause: unknown }
  | { kind: 'raw'; bytesRead: number; cause: unknown };

export type SourcePointer = { readonly logicalSourceId: string; readonly jsonPointer: string };
export type ApplicationPath = readonly (string | number)[]; // empty array = the root value

export class TransformError extends Error {
  override readonly name: 'TransformError' = 'TransformError';
  readonly direction: 'request' | 'response';
  readonly code: 'temporal-unavailable' | 'invalid-wire-value' | 'invalid-application-value';
  readonly sourcePointer: SourcePointer;
  readonly applicationPath: ApplicationPath;
  // `Error` declares an optional `cause`; this narrows it to always-present, which is an override.
  override readonly cause: unknown;
  constructor(fields: {
    direction: 'request' | 'response';
    code: 'temporal-unavailable' | 'invalid-wire-value' | 'invalid-application-value';
    sourcePointer: SourcePointer;
    applicationPath: ApplicationPath;
    cause: unknown;
  }) {
    super();
    this.direction = fields.direction;
    this.code = fields.code;
    this.sourcePointer = fields.sourcePointer;
    this.applicationPath = fields.applicationPath;
    this.cause = fields.cause;
  }
}

export class ApiError<Failed> extends Error {
  override readonly name: 'ApiError' = 'ApiError';
  readonly result: Failed; // the complete failed result branch, preserved by identity
  constructor(result: Failed) {
    super('Oasts API call failed');
    this.result = result;
  }
}

export function unwrap<R extends { readonly ok: boolean }>(result: R): SuccessEnvelope<R>;
export function unwrap(
  result: { readonly ok: true; readonly data: unknown; readonly meta: unknown } | {
    readonly ok: false;
  },
): unknown {
  if (result.ok) {
    return { data: result.data, meta: result.meta };
  }
  throw new ApiError(result);
}
