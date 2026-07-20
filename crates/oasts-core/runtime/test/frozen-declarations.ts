// Frozen client declaration snapshots, hand-copied verbatim from the frozen client contract
// (the normative spec). These constants are the expected values for byte-exact
// assertions over the emitted runtime modules — they must never be regenerated
// from implementation output. Each constant names its source contract.

// TransportConfig<S> + OperationContext, spec text (optional baseUrl?).
export const FROZEN_TRANSPORT_CONFIG_AND_OPERATION_CONTEXT = `export type TransportConfig<S extends string = never> = {
  baseUrl?: string;                                   // generated as REQUIRED when config client.baseUrl.source is "runtime"
  serverVariables?: Readonly<Record<string, string>>;
  auth?: AuthProviders<S>;                            // generated scheme-name-keyed provider map
  headers?: HeadersInit;                              // transport default headers
  fetch?: (request: Request, extensions?: Readonly<Record<string, unknown>>) => Promise<Response>;  // injection seam: final Request + platform-extension sidecar
  middleware?: readonly Middleware[];                 // registration order
  credentials?: RequestCredentials;
};

export type OperationContext = {
  readonly operationId: string;
  readonly method: string;
  readonly url: URL;                                  // the resolved request URL
  readonly selectedAuth: readonly string[] | null;    // scheme names of the selected security alternative; null before selection or for anonymous — never a secret value
};`;

// TransportConfig<S> alone, spec text (optional baseUrl?).
export const FROZEN_TRANSPORT_CONFIG_OPTIONAL = `export type TransportConfig<S extends string = never> = {
  baseUrl?: string;                                   // generated as REQUIRED when config client.baseUrl.source is "runtime"
  serverVariables?: Readonly<Record<string, string>>;
  auth?: AuthProviders<S>;                            // generated scheme-name-keyed provider map
  headers?: HeadersInit;                              // transport default headers
  fetch?: (request: Request, extensions?: Readonly<Record<string, unknown>>) => Promise<Response>;  // injection seam: final Request + platform-extension sidecar
  middleware?: readonly Middleware[];                 // registration order
  credentials?: RequestCredentials;
};`;

// Conditional requiredness applied: baseUrl is REQUIRED when config client.baseUrl.source is "runtime" (the ? is dropped; all other bytes identical).
export const FROZEN_TRANSPORT_CONFIG_BASEURL_REQUIRED = `export type TransportConfig<S extends string = never> = {
  baseUrl: string;                                   // generated as REQUIRED when config client.baseUrl.source is "runtime"
  serverVariables?: Readonly<Record<string, string>>;
  auth?: AuthProviders<S>;                            // generated scheme-name-keyed provider map
  headers?: HeadersInit;                              // transport default headers
  fetch?: (request: Request, extensions?: Readonly<Record<string, unknown>>) => Promise<Response>;  // injection seam: final Request + platform-extension sidecar
  middleware?: readonly Middleware[];                 // registration order
  credentials?: RequestCredentials;
};`;

// CallOptions.
export const FROZEN_CALL_OPTIONS = `export type CallOptions = {
  auth?: AuthOverrides;
  headers?: HeadersInit;
  signal?: AbortSignal;
  fetchOptions?: Omit<RequestInit, 'method' | 'body' | 'headers' | 'signal'> & Record<string, unknown>;
};`;

// Middleware.
export const FROZEN_MIDDLEWARE = `export type Middleware = {
  onRequest?: (request: Request, context: OperationContext) => Request | void | Promise<Request | void>;
  onResponse?: (response: Response, context: OperationContext) => Response | void | Promise<Response | void>;
};`;

// StreamFailure (declaration frozen ahead of its implementation).
export const FROZEN_STREAM_FAILURE = `export type StreamFailure =
  | { kind: 'sse'; eventsYielded: number; cause: unknown }
  | { kind: 'raw'; bytesRead: number; cause: unknown };`;

// ResponseMeta, RequestFailure, ResponseFailure, UnknownHttpError, ApiError. Snapshot keeps the declare-class spelling from the spec; runtime ships a real export class with this exact declaration surface (the frozen contract).
export const FROZEN_FAILURE_MODEL = `export type ResponseMeta = {
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

export declare class ApiError<Failed> extends Error {
  readonly name: 'ApiError';
  readonly result: Failed; // the complete failed result branch, preserved by identity
  constructor(result: Failed); // calls super('Oasts API call failed'); orThrow uses exactly this constructor
}`;

// SourcePointer, ApplicationPath, TransformError (declaration frozen ahead of its implementation).
export const FROZEN_TRANSFORM_ERROR = `export type SourcePointer = { readonly logicalSourceId: string; readonly jsonPointer: string };
export type ApplicationPath = readonly (string | number)[]; // empty array = the root value

export declare class TransformError extends Error {
  readonly name: 'TransformError';
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
  });
}`;
