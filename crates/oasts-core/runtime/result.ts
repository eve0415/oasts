// Relative `.ts` import suffixes are contractual: the Rust embedding engine rewrites them to the configured emit extension.
import type * as StandardSchemaV1 from './standard-schema.ts';

export type ResponseMeta = {
  readonly url: string;      // provenance URL: fetchedResponse.url || finalRequest.url, captured
                             // before response middleware — never a replacement's empty url
  readonly status: number;
  readonly headers: Headers; // a decoupled snapshot, never the live Response headers
};

export type RequestFailure =
  | { kind: 'auth'; message: string; triedAlternatives: readonly (readonly string[])[]; cause?: unknown }
  | { kind: 'aborted'; reason: unknown }
  | { kind: 'network'; cause: unknown }
  | { kind: 'request-encode'; message: string; cause?: unknown }
  | { kind: 'request-validation'; issues: readonly StandardSchemaV1.Issue[] }
  | { kind: 'request-transform'; error: TransformError }
  | { kind: 'request-middleware'; cause: unknown };

export type ResponseFailure =
  | { kind: 'aborted'; reason: unknown }
  | { kind: 'response-decode'; message: string; cause?: unknown }
  | { kind: 'response-validation'; issues: readonly StandardSchemaV1.Issue[] }
  | { kind: 'response-transform'; error: TransformError }
  | { kind: 'response-middleware'; cause: unknown };

export type UnknownHttpError =
  | { kind: 'empty';  contentType: string | null; body: undefined }
  | { kind: 'json';   contentType: string;        body: unknown }
  | { kind: 'text';   contentType: string;        body: string }
  | { kind: 'binary'; contentType: string | null; body: ArrayBuffer };

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
  readonly cause: unknown;
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

export function unwrap<R extends { readonly ok: boolean }>(
  result: R,
): R extends { readonly ok: true; readonly data: infer D } ? D : never;
export function unwrap(
  result: { readonly ok: true; readonly data: unknown } | { readonly ok: false },
): unknown {
  if (result.ok) {
    return result.data;
  }
  throw new ApiError(result);
}
