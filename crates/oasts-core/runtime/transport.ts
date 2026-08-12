// Relative `.ts` import suffixes are contractual: the Rust embedding engine rewrites them to the configured emit extension.
import {
  unwrap,
  type RequestPhaseFailure,
  type ResponseMeta,
  type ResponsePhaseFailure,
  type SseEvent,
  type SuccessEnvelope,
  type UnknownHttpError,
} from './result.ts';
import {
  encodeFormUrlencodedBody,
  encodeMultipart,
  parseMediaType,
  serializeMediaType,
  serializeQueryFormExplode,
  type MultipartPart,
  type MultipartResponsePlan,
  type ParamPrimitive,
  type ParamValue,
  type ParsedMediaType,
  type UrlencodedField,
  type UrlencodedStyleField,
} from './serialize.ts';

//#region oxs:auth
export type AuthContext<Scope extends string = string> = { readonly operationId: string; readonly scheme: string; readonly scopes: readonly Scope[]; readonly url: string };
export type BasicCredential = { readonly username: string; readonly password: string };
export type HttpSchemeCredential = { readonly credentials: string };
export const AmbientCookieCredential: unique symbol = Symbol('AmbientCookieCredential');
// TLS happens below HTTP; Node users thread client cert/key through a custom fetch/dispatcher via the transport fetch/init override.
export const AmbientClientCertificate: unique symbol = Symbol('AmbientClientCertificate');
export type AuthCredential = string | BasicCredential | HttpSchemeCredential | typeof AmbientCookieCredential | typeof AmbientClientCertificate;
export type AuthProvider<Scope extends string = string> = (context: AuthContext<Scope>) => AuthCredential | null | Promise<AuthCredential | null>;
export type AuthProviders<S extends string = never> = Readonly<Record<S, AuthProvider>>;
export type AuthOverrides = 'anonymous' | Readonly<Record<string, AuthCredential>>;
//#endregion

export type TransportConfig<S extends string = never> = {
  baseUrl?: string;                                   // generated as REQUIRED when runtime URL resolution needs it
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
};

export type CallOptions = {
  auth?: AuthOverrides;
  headers?: HeadersInit;
  signal?: AbortSignal;
  fetchOptions?: Omit<RequestInit, 'method' | 'body' | 'headers' | 'signal'> & Record<string, unknown>;
};

export type Middleware = {
  onRequest?: (request: Request, context: OperationContext) => Request | void | Promise<Request | void>;
  onResponse?: (response: Response, context: OperationContext) => Response | void | Promise<Response | void>;
};

export type Transport<S extends string = never> = Readonly<{
  baseUrl: string | undefined;
  serverVariables: Readonly<Record<string, string>> | undefined;
  auth: AuthProviders<S> | undefined;
  headers: readonly (readonly [string, string])[];
  fetch: TransportConfig<S>['fetch'];
  middleware: readonly Middleware[];
  credentials: RequestCredentials | undefined;
}>;

function freezeRecord<Key extends string, Value>(
  value: Readonly<Record<Key, Value>> | undefined,
): Readonly<Record<Key, Value>> | undefined {
  if (value === undefined) {
    return undefined;
  }
  return Object.freeze({ ...value });
}

function normalizeBaseUrl(baseUrl: string | undefined): string | undefined {
  if (baseUrl === undefined) {
    return undefined;
  }
  if (!URL.canParse(baseUrl)) {
    throw new TypeError('baseUrl must be an absolute URL');
  }
  return baseUrl;
}

function normalizeHeaders(headers: HeadersInit | undefined): readonly (readonly [string, string])[] {
  const normalized = new Headers(headers);
  return Object.freeze(
    Array.from(normalized, ([name, value]) => Object.freeze([name, value] as const)),
  );
}

export function createTransport<S extends string = never>(config: TransportConfig<S>): Transport<S> {
  return Object.freeze({
    baseUrl: normalizeBaseUrl(config.baseUrl),
    serverVariables: freezeRecord(config.serverVariables),
    auth: freezeRecord(config.auth),
    headers: normalizeHeaders(config.headers),
    fetch: config.fetch,
    middleware: Object.freeze([...(config.middleware ?? [])]),
    credentials: config.credentials,
  });
}

export type PathPart =
  | { readonly kind: 'literal'; readonly text: string }
  | { readonly kind: 'param'; readonly name: string };

type ParamSerializer = {
  bivarianceHack(name: string, value: ParamValue, allowReserved: boolean): string;
}['bivarianceHack'];

// A content JSON serializer receives the raw typed value (any JSON) rather than a flat `ParamValue`,
// so it takes `unknown` and stringifies internally. The bivariance hack keeps it interchangeable
// with `ParamSerializer` at assignment.
type ContentParamSerializer = {
  bivarianceHack(name: string, value: unknown, allowReserved: boolean): string;
}['bivarianceHack'];

type ParamPlanBase = {
  readonly name: string;
  readonly location: 'path' | 'query' | 'header' | 'cookie';
  readonly required: boolean;
  readonly allowReserved: boolean;
};

// Discriminated by the presence of `content` (like `UrlencodedFieldPlan`): the flag ships only on
// content JSON parameters, keeping every other param descriptor byte-identical. Its serializer takes
// the raw typed value, so the transport forwards it without the `ParamValue` guard.
export type ParamPlan =
  | (ParamPlanBase & { readonly serialize: ParamSerializer })
  | (ParamPlanBase & { readonly serialize: ContentParamSerializer; readonly content: true });

// Discriminated by property presence (`'payloads' in field`) rather than a `kind` tag like every
// other descriptor union: a tag string would ship in the descriptor bytes of every generated
// client, and these urlencoded field descriptors are emitted per field. Size over the tagging
// convention, on purpose. `UrlencodedField` in serialize.ts makes the same tradeoff (`"json" in`).
// The style member derives from serialize.ts's field so the union is spelled once.
export type UrlencodedFieldPlan =
  | {
      readonly name: string;
      readonly required: boolean;
      readonly style?: UrlencodedStyleField['style'];
      readonly explode?: boolean;
      readonly allowReserved?: boolean;
    }
  | {
      readonly name: string;
      readonly required: boolean;
      readonly payloads: readonly ('json' | 'text')[];
      readonly contentType?: { readonly kind: 'selected'; readonly admitted: readonly string[] };
    };

export type MultipartContentTypePolicy =
  | { readonly kind: 'none' }
  | { readonly kind: 'fixed'; readonly value: string }
  | { readonly kind: 'selected'; readonly admitted: readonly string[] };

export type MultipartFieldPlan = {
  readonly name: string;
  readonly required: boolean;
  readonly repeated: boolean;
  readonly wrapper: boolean;
  readonly payload: 'json' | 'text' | 'binary';
  // Per-admitted-media payload kinds, index-for-index with contentType.admitted. Emitted for wrapped
  // fields whose caller may pick any admitted media: the selected index chooses the payload kind so
  // the part Content-Type and body serialization agree. Absent for style/fixed single-media fields,
  // which have exactly one payload kind (`payload`).
  readonly payloads?: readonly ('json' | 'text' | 'binary')[];
  readonly contentType: MultipartContentTypePolicy;
  readonly filename: boolean;
};

// A request body ships its encoder rather than a `kind` tag, for the same reason a multipart
// response entry ships its decoder (see `MultipartResponseDecoder`): a tag would force `execute` to
// name every branch statically, so every generated client — JSON body, no body at all — would carry
// the multipart and urlencoded encoders. Reached only through the descriptor, an operation links the
// one encoder it declares and a bodyless operation links none.
export type BodyEncoder = (input: unknown) => Promise<SerializedBody>;

// The non-exact half of the response-key space, statically known to the runtime. Keeping it a
// literal space rather than plain `string` is what keeps an `outcome` check narrowing: no failure
// tag and no `'unmatched'` is assignable to it, so testing for one eliminates the HTTP arms.
export type ResponseRangeKey = `${number}XX` | 'default';

// A multipart response entry ships its decoder alongside its plan instead of a tag string, so the
// decoder is reachable only from the descriptors that declare one. A tag would force the transport
// to import it statically, and every generated client — multipart response or not — would carry the
// parser. `decode` is always `decodeMultipartResponse`; keeping it a descriptor field rather than a
// transport import is the whole point.
export type MultipartResponseDecoder = {
  readonly decode: (
    bytes: Uint8Array,
    parameters: ParsedMediaType['parameters'],
    plan: MultipartResponsePlan,
  ) => Readonly<Record<string, unknown>>;
  readonly plan: MultipartResponsePlan;
};

// A streaming response entry ships its reader for the same reason a multipart one ships its
// decoder, and is discriminated by the property it carries rather than by a tag: adding a tag to
// `MultipartResponseDecoder` would churn every already-emitted client for a distinction only these
// two new arms need. `sse` is always `decodeSseStream` and `raw` always `readRawStream`; both stay
// descriptor fields so a client with no streaming response links neither.
// The per-event hook's declaration lives on a method, so its parameter is compared bivariantly:
// what the parser hands the hook is one `JSON.parse` result, which is `unknown`, while a hook that
// converts names the wire type its schema declares. That is the same claim `execute<…ResultWire>`
// already makes about a buffered body, made in the one place the two surfaces meet — and the hook's
// own validator is what checks it whenever response validation is on.
type SseEventHookHost = {
  hook(data: unknown): unknown;
};

export type SseEventHook = SseEventHookHost['hook'];

export type SseResponseDecoder = {
  readonly sse: (
    body: ReadableStream<Uint8Array>,
    signal: AbortSignal,
    onEvent: SseEventHook | null,
  ) => AsyncIterable<SseEvent<unknown>>;
  // The generated per-event validate-then-convert pipeline, or null when the operation declares
  // neither. It rides the descriptor because the parser knows nothing of schemas.
  readonly onEvent: SseEventHook | null;
};

export type RawResponseDecoder = {
  readonly raw: (
    body: ReadableStream<Uint8Array>,
    signal: AbortSignal,
  ) => ReadableStream<Uint8Array>;
};

// Like an SSE event hook, a generated reviver names the wire type its schema declares while the
// transport crosses that boundary with a JSON.parse result. The method extraction keeps that
// schema-specific parameter bivariant without weakening either side to an unchecked cast.
type LosslessJsonReviverHost = {
  revive(value: unknown, lossless: unknown): unknown;
};

type LosslessJsonReviver = LosslessJsonReviverHost['revive'];

export type LosslessJsonResponseDecoder = {
  readonly json: 'int64';
  readonly revive: LosslessJsonReviver;
};

export type ResponseMediaDecoder =
  | 'json'
  | 'text'
  | 'binary'
  | LosslessJsonResponseDecoder
  | MultipartResponseDecoder
  | SseResponseDecoder
  | RawResponseDecoder;

// The decoders that need the whole body in hand. Naming the complement as its own type is what lets
// the streaming check narrow in both directions, so the buffered path below stays exactly as it was.
type BufferedResponseDecoder =
  | 'json'
  | 'text'
  | 'binary'
  | LosslessJsonResponseDecoder
  | MultipartResponseDecoder;

function isStreamingResponseDecoder(
  decoder: ResponseMediaDecoder,
): decoder is SseResponseDecoder | RawResponseDecoder {
  return typeof decoder !== 'string' && ('sse' in decoder || 'raw' in decoder);
}

export type ResponsePlan = {
  readonly match: string;
  readonly kind: 'exact' | 'range' | 'default';
  readonly status: number | null;
  readonly bodyless: boolean;
  readonly media: readonly (readonly [string, ResponseMediaDecoder])[];
  readonly hasContentTypeDiscriminant: boolean;
};

export type ServerTemplate = {
  readonly url: string;
  readonly variables: readonly (readonly [string, string])[];
};

export type OperationDescriptor = {
  readonly operationId: string;
  readonly method: string;
  readonly path: readonly (readonly PathPart[])[];
  readonly params: readonly ParamPlan[];
  readonly body: BodyEncoder | null;
  readonly accept: string | null;
  readonly credentialHeaders: readonly string[];
  readonly security: AuthResolver | null;
  readonly responses: readonly ResponsePlan[];
  readonly baseUrl:
    | { readonly kind: 'runtime' }
    | { readonly kind: 'literal'; readonly value: string }
    | {
        readonly kind: 'server';
        readonly index: number;
        readonly servers: readonly ServerTemplate[];
      };
  readonly fetchDefaults: Readonly<Record<string, unknown>>;
};

// The erased mirror of a generated operation's result union: same arms, with each operation's
// declared-key literals widened to `number | string` and its payloads to `unknown`. The precise
// shape lives in the generated module, which passes it through the `execute<Result>` overload.
export type ExecutionResult =
  | {
      readonly outcome: number | ResponseRangeKey;
      readonly ok: true;
      readonly status: number;
      readonly data: unknown;
      readonly contentType?: string;
      readonly meta: ResponseMeta;
    }
  | {
      readonly outcome: number | ResponseRangeKey;
      readonly ok: false;
      readonly status: number;
      readonly error: unknown;
      readonly contentType?: string;
      readonly meta: ResponseMeta;
    }
  | {
      readonly outcome: 'unmatched';
      readonly ok: false;
      readonly status: number;
      readonly error: UnknownHttpError;
      readonly meta: ResponseMeta;
    }
  | ResponsePhaseFailure<number | ResponseRangeKey>
  | RequestPhaseFailure;

// The `outcome` a matched branch is keyed on: the wire status for an exact declared key (the one
// plan kind carrying one), the declared key itself otherwise. A range key is rebuilt from its
// leading digit rather than passed through, because `plan.match` is a plain string and rebuilding
// is what establishes the literal type — no assertion involved.
function responseOutcome(plan: ResponsePlan): number | ResponseRangeKey {
  if (plan.status !== null) {
    return plan.status;
  }
  return plan.kind === 'range' ? `${Number(plan.match[0])}XX` : 'default';
}

// A fired `AbortSignal.timeout(ms)` rejects with a DOMException named TimeoutError; every other
// abort — including `controller.abort(reason)` with an arbitrary reason — is a cancellation. The
// test reads the reason's shape, never which API produced the signal, so a manually constructed
// TimeoutError classifies as a timeout and a polyfill throwing a plain Error does not.
function isTimeoutReason(reason: unknown): boolean {
  return reason instanceof DOMException && reason.name === 'TimeoutError';
}

export type SerializedBody = {
  readonly body: BodyInit | null;
  readonly contentType: string | null;
  // Set only by a streaming body. Fetch requires `duplex` exactly when the body is a stream, so it
  // travels with the body that needs it rather than being something a caller has to know to pass.
  readonly duplex?: 'half';
};

type MultipartWrapper = {
  readonly body: unknown;
  readonly contentType: unknown;
  readonly filename: unknown;
};

const UTF8_ENCODER = new TextEncoder();
const STANDARD_FETCH_OPTIONS = new Set([
  'cache',
  'credentials',
  'integrity',
  'keepalive',
  'mode',
  'redirect',
  'referrer',
  'referrerPolicy',
  'priority',
  'duplex',
]);
const FORBIDDEN_HEADER_NAMES = new Set([
  'accept-charset',
  'accept-encoding',
  'access-control-request-headers',
  'access-control-request-method',
  'connection',
  'content-length',
  'cookie',
  'cookie2',
  'date',
  'dnt',
  'expect',
  'host',
  'keep-alive',
  'origin',
  'referer',
  'set-cookie',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'via',
]);
const METHOD_OVERRIDE_HEADERS = new Set([
  'x-http-method',
  'x-http-method-override',
  'x-method-override',
]);
const FORBIDDEN_OVERRIDE_VALUES = new Set(['connect', 'trace', 'track']);

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// A security requirement member carries its own credential serializer instead of a scheme-kind tag,
// for the same reason the body carries its encoder: a tag would make `serializeSelectedAuth` name
// every scheme statically, so a bearer-only client would still link RFC 7617 basic encoding, the
// query-key percent encoder and the ambient-credential sentinels. `param` is the declared API key
// parameter name and `scheme` the generic HTTP auth-scheme token; each applier reads the one it needs.
export type SecurityUse = {
  readonly name: string;
  readonly scopes: readonly string[];
  readonly apply: CredentialApplier;
  readonly param?: string;
  readonly scheme?: string;
};

/** What one credential puts on the request. An ambiently delivered credential contributes neither. */
export type AppliedCredential = {
  readonly headers?: readonly (readonly [string, string])[];
  // [declared parameter name, already-percent-encoded `name=value` component]
  readonly query?: readonly (readonly [string, string])[];
};

/** Validates one credential and says what it contributes, or returns the failure message. */
export type CredentialApplier = (
  use: SecurityUse,
  credential: unknown,
) => AppliedCredential | string;

// What `execute` needs back from an operation's security requirement: the credential headers to
// merge, and the scheme names the selected alternative used (null when the call went out
// anonymous) for the middleware context. A failure short-circuits the whole request.
export type AuthResolution =
  | {
      readonly kind: 'resolved';
      readonly headers: readonly (readonly [string, string])[];
      readonly selected: readonly string[] | null;
    }
  | { readonly kind: 'failure'; readonly result: RequestPhaseFailure };

// An operation's security requirement ships as a resolver rather than the alternatives table, for
// the same reason its body ships as an encoder: selection and credential serialization would
// otherwise be named statically by `execute`, so an operation with no security requirement at all
// would still link provider selection, RFC 6750 token validation, RFC 7617 basic encoding and the
// rest. `descriptor.security` is null for such an operation and nothing above is reachable.
export type AuthResolver = (
  transport: Transport,
  operationId: string,
  options: CallOptions | undefined,
  url: URL,
) => Promise<AuthResolution>;

/** Resolves a credential for the first satisfiable alternative, in declared order. */
export function authAlternatives(
  alternatives: readonly (readonly SecurityUse[])[],
): AuthResolver {
  return async (transport, operationId, options, url) => {
    const selection = await selectAuth(transport, alternatives, operationId, options, url);
    if (selection.kind === 'failure') {
      return selection;
    }
    const members = selection.kind === 'selected' ? selection.members : [];
    const serialized = serializeSelectedAuth(url, members);
    if (typeof serialized === 'string') {
      return {
        kind: 'failure',
        result: authFailureResult(serialized, selection.triedAlternatives),
      };
    }
    return {
      kind: 'resolved',
      headers: serialized.headers,
      selected: selection.kind === 'selected'
        ? selection.members.map((member) => member.use.name)
        : null,
    };
  };
}

type SelectedAuthMember = {
  readonly use: SecurityUse;
  readonly credential: unknown;
};

type AuthSelection =
  | {
      readonly kind: 'selected';
      readonly members: readonly SelectedAuthMember[];
      readonly triedAlternatives: readonly (readonly string[])[];
    }
  | {
      readonly kind: 'anonymous';
      readonly triedAlternatives: readonly (readonly string[])[];
    }
  | {
      readonly kind: 'failure';
      readonly result: RequestPhaseFailure;
    };

type AuthSource =
  | { readonly kind: 'per-call'; readonly use: SecurityUse; readonly credential: unknown }
  | { readonly kind: 'provider'; readonly use: SecurityUse; readonly provider: unknown }
  | { readonly kind: 'missing'; readonly use: SecurityUse };

type AvailableAuthSource = Exclude<AuthSource, { readonly kind: 'missing' }>;

function authFailureResult(
  message: string,
  triedAlternatives: readonly (readonly string[])[],
): RequestPhaseFailure {
  return { outcome: 'auth', ok: false, message, triedAlternatives };
}

function providerAuthFailureResult(
  message: string,
  triedAlternatives: readonly (readonly string[])[],
  cause: unknown,
): RequestPhaseFailure {
  return { outcome: 'auth', ok: false, message, triedAlternatives, cause };
}

function isAuthProvider(value: unknown): value is AuthProvider {
  return typeof value === 'function';
}

function configuredProvider<S extends string>(
  providers: AuthProviders<S> | undefined,
  name: string,
): { readonly found: false } | { readonly found: true; readonly provider: unknown } {
  if (providers === undefined || !Object.hasOwn(providers, name)) {
    return { found: false };
  }
  return { found: true, provider: Reflect.get(providers, name) };
}

function perCallAuth(options: CallOptions | undefined): Readonly<Record<string, unknown>> | undefined {
  return isRecord(options?.auth) ? options.auth : undefined;
}

function alternativeNames(alternative: readonly SecurityUse[]): readonly string[] {
  return alternative.map((use) => use.name);
}

function authSource<S extends string>(
  transport: Transport<S>,
  perCall: Readonly<Record<string, unknown>> | undefined,
  use: SecurityUse,
): AuthSource {
  if (perCall !== undefined && Object.hasOwn(perCall, use.name)) {
    return { kind: 'per-call', use, credential: perCall[use.name] };
  }
  const provider = configuredProvider(transport.auth, use.name);
  return !provider.found
    ? { kind: 'missing', use }
    : { kind: 'provider', use, provider: provider.provider };
}

async function selectAuth(
  transport: Transport,
  security: readonly (readonly SecurityUse[])[],
  operationId: string,
  options: CallOptions | undefined,
  url: URL,
): Promise<AuthSelection> {
  const perCall = perCallAuth(options);
  for (const [index, alternative] of security.entries()) {
    if (
      alternative.length !== 0 &&
      perCall !== undefined &&
      alternative.every((use) => Object.hasOwn(perCall, use.name))
    ) {
      return {
        kind: 'selected',
        members: alternative.map((use) => ({ use, credential: perCall[use.name] })),
        triedAlternatives: security
          .slice(0, index + 1)
          .filter((candidate) => candidate.length !== 0)
          .map(alternativeNames),
      };
    }
  }

  const triedAlternatives: (readonly string[])[] = [];
  // The anonymous fallback needs to know whether ANY member of ANY credentialed alternative had
  // a source — including members after a missing one — so a missing member marks the alternative
  // ineligible without ending the presence scan.
  let sawAnySource = false;
  for (const alternative of security) {
    if (alternative.length === 0) {
      continue;
    }
    triedAlternatives.push(alternativeNames(alternative));
    const sources: AvailableAuthSource[] = [];
    let eligible = true;
    for (const use of alternative) {
      const source = authSource(transport, perCall, use);
      if (source.kind === 'missing') {
        eligible = false;
        continue;
      }
      sawAnySource = true;
      sources.push(source);
    }
    if (!eligible) {
      continue;
    }
    const members: SelectedAuthMember[] = [];
    let satisfied = true;
    for (const source of sources) {
      if (source.kind === 'per-call') {
        members.push({ use: source.use, credential: source.credential });
        continue;
      }
      if (!isAuthProvider(source.provider)) {
        return {
          kind: 'failure',
          result: authFailureResult(
            `Authentication provider for ${source.use.name} is not callable`,
            triedAlternatives,
          ),
        };
      }
      const context: AuthContext = Object.freeze({
        operationId,
        scheme: source.use.name,
        scopes: source.use.scopes,
        url: url.toString(),
      });
      let credential: unknown;
      try {
        credential = await source.provider(context);
      } catch (cause) {
        return {
          kind: 'failure',
          result: providerAuthFailureResult(
            `Authentication provider for ${source.use.name} failed`,
            triedAlternatives,
            cause,
          ),
        };
      }
      if (credential === null) {
        satisfied = false;
        break;
      }
      members.push({ use: source.use, credential });
    }
    if (satisfied) {
      return { kind: 'selected', members, triedAlternatives };
    }
  }

  const anonymousCount = security.filter(
    (alternative) => alternative.length === 0,
  ).length;
  if (anonymousCount > 0 && (!sawAnySource || options?.auth === 'anonymous')) {
    return { kind: 'anonymous', triedAlternatives };
  }
  return {
    kind: 'failure',
    result: authFailureResult('No security alternative could be satisfied', triedAlternatives),
  };
}

function isBasicCredential(value: unknown): value is BasicCredential {
  return isRecord(value) &&
    typeof value.username === 'string' &&
    typeof value.password === 'string';
}

function isHttpSchemeCredential(value: unknown): value is HttpSchemeCredential {
  return isRecord(value) && typeof value.credentials === 'string';
}

function utf8Base64(value: string): string {
  let bytes = '';
  for (const byte of UTF8_ENCODER.encode(value)) {
    bytes += String.fromCharCode(byte);
  }
  return btoa(bytes);
}

function containsBasicControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function containsHeaderControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0 || code === 0x0a || code === 0x0d) {
      return true;
    }
  }
  return false;
}

type SerializedAuth = {
  readonly headers: readonly (readonly [string, string])[];
};

/** RFC 6750 bearer tokens — HTTP bearer, OAuth 2.0 and OpenID Connect serialize identically. */
export function bearerCredential(use: SecurityUse, credential: unknown): AppliedCredential | string {
  if (typeof credential !== 'string' || !/^[A-Za-z0-9._~+/-]+=*$/u.test(credential)) {
    return `Authentication scheme ${use.name} requires an RFC 6750 b64token`;
  }
  return { headers: [['Authorization', `Bearer ${credential}`]] };
}

/** RFC 7617 basic credentials: NFC normalize, reject control characters and a colon, then Base64. */
export function basicCredential(use: SecurityUse, credential: unknown): AppliedCredential | string {
  if (!isBasicCredential(credential)) {
    return `Authentication scheme ${use.name} requires a basic username and password credential`;
  }
  const username = credential.username.normalize('NFC');
  const password = credential.password.normalize('NFC');
  if (containsBasicControl(username) || containsBasicControl(password)) {
    return `Authentication scheme ${use.name} basic credential contains a control character`;
  }
  if (username.includes(':')) {
    return `Authentication scheme ${use.name} basic username contains a colon`;
  }
  return { headers: [['Authorization', `Basic ${utf8Base64(`${username}:${password}`)}`]] };
}

/** A generic `Authorization: <scheme> <credentials>` for an HTTP scheme this client cannot compute. */
export function httpSchemeCredential(
  use: SecurityUse,
  credential: unknown,
): AppliedCredential | string {
  if (!isHttpSchemeCredential(credential)) {
    return `Authentication scheme ${use.name} requires a credentials string`;
  }
  if (use.scheme === undefined) {
    return `Authentication scheme ${use.name} has no declared auth-scheme token`;
  }
  if (containsHeaderControl(use.scheme) || containsHeaderControl(credential.credentials)) {
    return `Authentication scheme ${use.name} contains a control character`;
  }
  return { headers: [['Authorization', `${use.scheme} ${credential.credentials}`]] };
}

/** A header API key, checked against the Headers value contract before Request construction. */
export function headerKeyCredential(
  use: SecurityUse,
  credential: unknown,
): AppliedCredential | string {
  if (typeof credential !== 'string') {
    return `Authentication scheme ${use.name} header API key must be a string`;
  }
  if (containsHeaderControl(credential)) {
    return `Authentication scheme ${use.name} header API key contains a control character`;
  }
  for (let index = 0; index < credential.length; index += 1) {
    if (credential.charCodeAt(index) > 0xff) {
      return `Authentication scheme ${use.name} header API key violates ByteString`;
    }
  }
  if (/^[ \t]|[ \t]$/u.test(credential)) {
    return `Authentication scheme ${use.name} header API key has edge whitespace`;
  }
  if (use.param === undefined) {
    return `Authentication scheme ${use.name} has no declared header name`;
  }
  return { headers: [[use.param, credential]] };
}

/** A query API key, percent-encoded by the ordinary scalar form-style query encoder. */
export function queryKeyCredential(
  use: SecurityUse,
  credential: unknown,
): AppliedCredential | string {
  if (typeof credential !== 'string') {
    return `Authentication scheme ${use.name} query API key must be a string`;
  }
  if (use.param === undefined) {
    return `Authentication scheme ${use.name} has no declared query name`;
  }
  return { query: [[use.param, serializeQueryFormExplode(use.param, credential, false)]] };
}

/** A cookie API key: WHATWG Fetch forbids a `Cookie` request header, so the cookie store supplies it. */
export function cookieKeyCredential(
  use: SecurityUse,
  credential: unknown,
): AppliedCredential | string {
  if (credential !== AmbientCookieCredential) {
    return `Authentication scheme ${use.name} requires the ambient cookie credential`;
  }
  return {};
}

/** Mutual TLS: the certificate is threaded through a custom fetch, so nothing goes on the request. */
export function mutualTlsCredential(
  use: SecurityUse,
  credential: unknown,
): AppliedCredential | string {
  if (credential !== AmbientClientCertificate) {
    return `Authentication scheme ${use.name} requires the ambient client certificate credential`;
  }
  return {};
}

function serializeSelectedAuth(
  url: URL,
  members: readonly SelectedAuthMember[],
): SerializedAuth | string {
  const headers: (readonly [string, string])[] = [];
  const query: string[] = [];
  let occupiedQueryNames: Set<string> | undefined;
  for (const { use, credential } of members) {
    // A hand-built or drifted descriptor must fail closed rather than throw out of `execute` or
    // silently send the request without this member's credential.
    if (typeof use.apply !== 'function') {
      return `Authentication scheme ${use.name} has no credential serializer`;
    }
    const applied = use.apply(use, credential);
    if (typeof applied === 'string') {
      return applied;
    }
    if (applied.headers !== undefined) {
      headers.push(...applied.headers);
    }
    for (const [name, component] of applied.query ?? []) {
      occupiedQueryNames ??= new Set(url.searchParams.keys());
      if (occupiedQueryNames.has(name)) {
        return `Authentication query parameter ${name} is already present`;
      }
      query.push(component);
      occupiedQueryNames.add(name);
    }
  }
  if (query.length !== 0) {
    const prefix = url.search.length === 0 ? '' : `${url.search.slice(1)}&`;
    url.search = `${prefix}${query.join('&')}`;
  }
  return { headers };
}

function isParamPrimitive(value: unknown): value is ParamPrimitive {
  return typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean' ||
    typeof value === 'bigint';
}

function isParamValue(value: unknown): value is ParamValue {
  if (isParamPrimitive(value)) {
    return true;
  }
  if (Array.isArray(value)) {
    return value.every(isParamPrimitive);
  }
  return isRecord(value) && Object.values(value).every(isParamPrimitive);
}

function encodeFailure(cause: unknown): RequestPhaseFailure {
  const message = cause instanceof Error ? cause.message : 'request encoding failed';
  return { outcome: 'request-encode', ok: false, message, cause };
}

function requestMiddlewareFailure(cause: unknown): RequestPhaseFailure {
  return { outcome: 'request-middleware', ok: false, cause };
}

// Branches on the whole object literal, not on a computed `outcome` value: a conditional in the
// discriminant position widens it to `string` and stops the literal from selecting a union member.
function abortedRequest(reason: unknown): RequestPhaseFailure {
  return isTimeoutReason(reason)
    ? { outcome: 'timeout', ok: false, reason }
    : { outcome: 'aborted', ok: false, reason };
}

// A failed `fetch()` is guaranteed to reject with a TypeError, so the real thing passes through by
// identity. `transport.fetch` is an injection seam that can throw anything, so anything else is
// wrapped rather than asserted — establishing the declared type by construction.
function networkFailure(cause: unknown): RequestPhaseFailure {
  return {
    outcome: 'network',
    ok: false,
    cause: cause instanceof TypeError ? cause : new TypeError('fetch failed', { cause }),
  };
}

function absoluteBaseUrl(transport: Transport, descriptor: OperationDescriptor): string {
  if (descriptor.baseUrl.kind === 'server') {
    const server = descriptor.baseUrl.servers[descriptor.baseUrl.index];
    if (server === undefined) {
      throw new TypeError('the configured server index did not resolve');
    }
    let selected = server.url;
    for (const [name, declaredDefault] of server.variables) {
      const value = transport.serverVariables?.[name] ?? declaredDefault;
      selected = selected.replaceAll(`{${name}}`, value);
    }
    if (!URL.canParse(selected)) {
      if (transport.baseUrl === undefined) {
        throw new TypeError('no absolute base URL resolved for the operation');
      }
      return new URL(selected, transport.baseUrl).toString();
    }
    // A configured baseUrl wins and short-circuits: an unresolved `{placeholder}` in the server URL
    // is moot because the server URL is discarded. Only when nothing overrides it does an unresolved
    // variable make the operation URL unusable, so the throw follows the fallback rather than
    // preceding it.
    if (transport.baseUrl !== undefined) {
      return transport.baseUrl;
    }
    if (/\{[^{}]+\}/u.test(selected)) {
      throw new TypeError('a server variable is unresolved');
    }
    return selected;
  }
  let resolved = transport.baseUrl;
  if (resolved === undefined) {
    if (descriptor.baseUrl.kind === 'runtime') {
      throw new TypeError('no absolute base URL resolved for the operation');
    }
    resolved = descriptor.baseUrl.value;
  }
  if (!URL.canParse(resolved)) {
    throw new TypeError('the resolved base URL is not absolute');
  }
  return resolved;
}

function findParamPlan(
  descriptor: OperationDescriptor,
  location: ParamPlan['location'],
  name: string,
): ParamPlan {
  const plan = descriptor.params.find(
    (candidate) => candidate.location === location && candidate.name === name,
  );
  if (plan === undefined) {
    throw new TypeError(`parameter plan ${location}:${name} is missing`);
  }
  return plan;
}

function serializedParam(plan: ParamPlan, input: Readonly<Record<string, unknown>>): string | null {
  const group = input[plan.location];
  const value = isRecord(group) ? group[plan.name] : undefined;
  if (value === undefined) {
    if (plan.required) {
      throw new TypeError(`required parameter ${plan.name} is missing`);
    }
    return null;
  }
  if ('content' in plan) {
    // A content JSON parameter serializes the raw typed value; its serializer owns stringification,
    // so the flat-`ParamValue` guard does not apply.
    return plan.serialize(plan.name, value, plan.allowReserved);
  }
  if (!isParamValue(value)) {
    throw new TypeError(`parameter ${plan.name} has an unsupported value`);
  }
  return plan.serialize(plan.name, value, plan.allowReserved);
}

function operationUrl(
  transport: Transport,
  descriptor: OperationDescriptor,
  input: Readonly<Record<string, unknown>>,
): URL {
  let path = '';
  for (const group of descriptor.path) {
    for (const part of group) {
      if (part.kind === 'literal') {
        path += part.text;
      } else {
        const plan = findParamPlan(descriptor, 'path', part.name);
        const value = serializedParam(plan, input);
        if (value === null) {
          throw new TypeError(`path parameter ${part.name} is missing`);
        }
        path += value;
      }
    }
  }

  const base = absoluteBaseUrl(transport, descriptor);
  const baseWithSlash = base.endsWith('/') ? base : `${base}/`;
  const url = new URL(path.replace(/^\/+/, ''), baseWithSlash);
  const query: string[] = [];
  for (const plan of descriptor.params) {
    if (plan.location !== 'query') {
      continue;
    }
    const fragment = serializedParam(plan, input);
    if (fragment !== null && fragment.length !== 0) {
      query.push(fragment);
    }
  }
  if (query.length !== 0) {
    const prefix = url.search.length === 0 ? '' : `${url.search.slice(1)}&`;
    url.search = `${prefix}${query.join('&')}`;
  }
  return url;
}

function sameParameters(left: ParsedMediaType, right: ParsedMediaType): boolean {
  if (left.parameters.length !== right.parameters.length) {
    return false;
  }
  return left.parameters.every(
    ([name, value], index) =>
      right.parameters[index]?.[0] === name && right.parameters[index]?.[1] === value,
  );
}

// RFC 9110 §12.5.1 media-range specificity, used to classify a received response Content-Type
// against declared response keys: only the most specific applicable key is chosen. A concrete
// `type/subtype` whose parameters are all present in the received type outranks a bare
// `type/subtype`, which outranks a `type/*` range, which outranks `*/*`; among concrete keys, more
// matched parameters is more specific. This subset rule (declared parameters ⊆ received) is what
// lets a bare `application/json` still match a `application/json; charset=utf-8` response while
// `application/json;stream=watch` selects over it for a watch stream. Requests use exact matching
// instead (`selectedMediaType`): the caller picks the wire media type, so it must equal a declared
// key. Parameter names compare case-insensitively and values byte-for-byte — `parseMediaType`
// already lower-cases names (and the charset value), so the stored pairs compare directly. Returns a
// specificity score (higher = more specific) or -1 when the declared key does not apply.
function mediaSpecificity(declared: ParsedMediaType, actual: ParsedMediaType): number {
  if (declared.type === '*' && declared.subtype === '*') {
    return declared.parameters.length === 0 ? 0 : -1;
  }
  if (declared.subtype === '*') {
    return declared.type === actual.type && declared.parameters.length === 0 ? 1 : -1;
  }
  if (declared.type !== actual.type || declared.subtype !== actual.subtype) {
    return -1;
  }
  for (const [name, value] of declared.parameters) {
    const found = actual.parameters.find(([candidate]) => candidate === name);
    if (found === undefined || found[1] !== value) {
      return -1;
    }
  }
  // A concrete type/subtype outranks every range; a matched parameter makes it more specific still.
  return 2 + declared.parameters.length;
}

// Index of the most specific declared key applicable to `actual`, or -1 when none applies. Equal
// specificity breaks by canonical byte order (declared keys are ASCII canonical media types), so the
// choice is deterministic regardless of the order the keys were declared in.
function mostSpecificMedia(actual: ParsedMediaType, declared: readonly string[]): number {
  let best = -1;
  let bestScore = -1;
  for (const [index, key] of declared.entries()) {
    const parsed = parseMediaType(key);
    if (parsed === null) {
      continue;
    }
    const score = mediaSpecificity(parsed, actual);
    if (score < 0) {
      continue;
    }
    // Only meaningful once a key has been chosen, which a non-negative equal score implies.
    const incumbent = best < 0 ? undefined : declared[best];
    if (
      score > bestScore ||
      (score === bestScore && incumbent !== undefined && key < incumbent)
    ) {
      best = index;
      bestScore = score;
    }
  }
  return best;
}

/** Reads an admitted entry that is already the media string itself. */
const mediaItself = (entry: string): string => entry;

// Returns the matching entry alongside its index. Callers that key a parallel array by position
// take the index; the content-discriminated body takes the entry, which is how it reaches its
// encoder without indexing back into the array the index came from.
function selectedMediaType<T>(
  input: unknown,
  admitted: readonly T[],
  mediaOf: (entry: T) => string,
): {
  readonly declared: string;
  readonly concrete: string;
  readonly index: number;
  readonly entry: T;
} {
  if (typeof input !== 'string') {
    throw new TypeError('a concrete contentType selection is required');
  }
  const actual = parseMediaType(input);
  if (actual === null || actual.type === '*' || actual.subtype === '*') {
    throw new TypeError('contentType must be a well-formed concrete media type');
  }

  for (const tier of ['exact', 'range', 'any'] as const) {
    for (const [index, entry] of admitted.entries()) {
      const declared = mediaOf(entry);
      const parsed = parseMediaType(declared);
      if (parsed === null) {
        continue;
      }
      const exact =
        parsed.type === actual.type &&
        parsed.subtype === actual.subtype &&
        sameParameters(parsed, actual);
      const range =
        parsed.type === actual.type && parsed.subtype === '*' && parsed.parameters.length === 0;
      const any = parsed.type === '*' && parsed.subtype === '*' && parsed.parameters.length === 0;
      if (
        (tier === 'exact' && exact) ||
        (tier === 'range' && range) ||
        (tier === 'any' && any)
      ) {
        return { declared, concrete: serializeMediaType(actual), index, entry };
      }
    }
  }
  throw new TypeError('contentType does not match an admitted media type');
}

/** A `application/x-www-form-urlencoded` request body over the declared fields. */
export function urlencodedBody(
  contentType: string,
  fields: readonly UrlencodedFieldPlan[],
): BodyEncoder {
  return (input) => Promise.resolve(serializeUrlencoded(contentType, fields, input));
}

function serializeUrlencoded(
  contentType: string,
  plan: readonly UrlencodedFieldPlan[],
  input: unknown,
): SerializedBody {
  if (!isRecord(input)) {
    throw new TypeError('form-urlencoded body must be an object');
  }
  const fields: UrlencodedField[] = [];
  for (const field of plan) {
    const value = input[field.name];
    if (value === undefined) {
      if (field.required) {
        throw new TypeError(`required form field ${field.name} is missing`);
      }
      continue;
    }
    if ('payloads' in field) {
      // Content-based field: the OAS 3.1.1 Encoding Object contentType picks a payload kind, which
      // decides between JSON serialization and the form-style text serializer.
      let body: unknown;
      let kind: 'json' | 'text' | undefined;
      if (field.contentType === undefined) {
        body = value;
        kind = field.payloads[0];
      } else {
        const wrapper = urlencodedWrapper(value);
        const selected = selectedMediaType(wrapper.contentType, field.contentType.admitted, mediaItself);
        kind = field.payloads[selected.index];
        body = wrapper.body;
      }
      if (kind === undefined) {
        throw new TypeError(
          `form field ${field.name} has no payload kind for the selected media type`,
        );
      }
      if (kind === 'json') {
        fields.push({ name: field.name, json: body });
      } else {
        if (!isParamValue(body)) {
          throw new TypeError(`form field ${field.name} has an unsupported value`);
        }
        // Text delegates to the form-style serializer: byte-identical to plain strings and
        // preserving arrays as repeated pairs.
        fields.push({
          name: field.name,
          value: body,
          style: 'form',
          explode: true,
          allowReserved: false,
        });
      }
      continue;
    }
    if (!isParamValue(value)) {
      throw new TypeError(`form field ${field.name} has an unsupported value`);
    }
    // Spread rather than assign: a field that declares no style is not a field whose style is
    // undefined, and exactOptionalPropertyTypes makes a consumer's compiler say so.
    fields.push({
      name: field.name,
      value,
      ...(field.style === undefined ? {} : { style: field.style }),
      ...(field.explode === undefined ? {} : { explode: field.explode }),
      ...(field.allowReserved === undefined ? {} : { allowReserved: field.allowReserved }),
    });
  }
  return { body: encodeFormUrlencodedBody(fields), contentType };
}

function urlencodedWrapper(value: unknown): {
  readonly body: unknown;
  readonly contentType: unknown;
} {
  if (!isRecord(value)) {
    throw new TypeError('urlencoded content wrapper must be an object');
  }
  return { body: value.body, contentType: value.contentType };
}

function multipartWrapper(value: unknown): MultipartWrapper {
  if (!isRecord(value)) {
    throw new TypeError('multipart wrapper must be an object');
  }
  return {
    body: value.body,
    contentType: value.contentType,
    filename: value.filename,
  };
}

function blobFilename(value: unknown): string | undefined {
  if (value instanceof Blob && 'name' in value && typeof value.name === 'string') {
    return value.name;
  }
  return undefined;
}

async function multipartPayload(kind: MultipartFieldPlan['payload'], value: unknown): Promise<Uint8Array> {
  if (kind === 'binary') {
    if (value instanceof Uint8Array) {
      return value;
    }
    if (value instanceof Blob) {
      return new Uint8Array(await value.arrayBuffer());
    }
    throw new TypeError('binary multipart fields require Uint8Array, Blob, or File');
  }
  if (kind === 'text') {
    if (typeof value !== 'string' && typeof value !== 'bigint') {
      throw new TypeError('text multipart fields require a string or bigint');
    }
    return UTF8_ENCODER.encode(String(value));
  }
  const json = JSON.stringify(value);
  if (json === undefined) {
    throw new TypeError('JSON multipart field is not serializable');
  }
  return UTF8_ENCODER.encode(json);
}

// Resolves the part Content-Type and the body payload kind from one media selection so they can
// never disagree. A wrapped part admits caller media selection; the payload kind must follow the
// selected admitted index, not payloads[0] — otherwise a non-first selection stamps the selected
// media on a body serialized with the first kind.
function multipartMedia(
  plan: MultipartFieldPlan,
  selected: unknown,
): { readonly contentType: string | undefined; readonly payload: MultipartFieldPlan['payload'] } {
  if (plan.contentType.kind === 'none') {
    return { contentType: undefined, payload: plan.payload };
  }
  if (!plan.wrapper) {
    if (plan.contentType.kind === 'selected') {
      throw new TypeError('selected multipart media requires a wrapper');
    }
    return { contentType: plan.contentType.value, payload: plan.payload };
  }
  const admitted =
    plan.contentType.kind === 'fixed' ? [plan.contentType.value] : plan.contentType.admitted;
  const chosen = selectedMediaType(selected, admitted, mediaItself);
  // `payloads` is absent only for the fixed single-media wrapper case, which has one payload kind.
  const payload = plan.payloads === undefined ? plan.payload : plan.payloads[chosen.index];
  if (payload === undefined) {
    throw new TypeError(
      `multipart field ${plan.name} has no payload kind for the selected media type`,
    );
  }
  return { contentType: chosen.concrete, payload };
}

async function multipartPart(plan: MultipartFieldPlan, value: unknown): Promise<MultipartPart> {
  if (value === null) {
    throw new TypeError(`multipart field ${plan.name} cannot be null`);
  }
  const wrapper = plan.wrapper ? multipartWrapper(value) : undefined;
  const body = wrapper === undefined ? value : wrapper.body;
  if (body === null || body === undefined) {
    throw new TypeError(`multipart field ${plan.name} has no body`);
  }
  const selectedFilename = wrapper?.filename;
  if (selectedFilename !== undefined && typeof selectedFilename !== 'string') {
    throw new TypeError(`multipart field ${plan.name} filename must be a string`);
  }
  const media = multipartMedia(plan, wrapper?.contentType);
  const payload = await multipartPayload(media.payload, body);
  const filename = plan.filename ? selectedFilename ?? blobFilename(body) : undefined;
  return {
    name: plan.name,
    payload,
    ...(media.contentType === undefined ? {} : { contentType: media.contentType }),
    ...(filename === undefined ? {} : { filename }),
  };
}

/** A `multipart/form-data` request body over the declared fields. */
export function multipartBody(fields: readonly MultipartFieldPlan[]): BodyEncoder {
  return (input) => serializeMultipart(fields, input);
}

async function serializeMultipart(
  plan: readonly MultipartFieldPlan[],
  input: unknown,
): Promise<SerializedBody> {
  if (!isRecord(input)) {
    throw new TypeError('multipart body must be an object');
  }
  const parts: MultipartPart[] = [];
  for (const field of plan) {
    const value = input[field.name];
    if (value === undefined) {
      if (field.required) {
        throw new TypeError(`required multipart field ${field.name} is missing`);
      }
      continue;
    }
    if (value === null) {
      throw new TypeError(`multipart field ${field.name} cannot be null`);
    }
    if (field.repeated) {
      if (!Array.isArray(value)) {
        throw new TypeError(`repeated multipart field ${field.name} must be an array`);
      }
      for (const item of value) {
        parts.push(await multipartPart(field, item));
      }
    } else {
      parts.push(await multipartPart(field, value));
    }
  }
  const encoded = await encodeMultipart(parts);
  return { body: Uint8Array.from(encoded.body), contentType: encoded.contentTypeHeader };
}

/** A JSON request body under the declared media type. */
export function jsonBody(contentType: string): BodyEncoder {
  return (input) => {
    const body = JSON.stringify(input);
    if (body === undefined) {
      throw new TypeError('JSON body is not serializable');
    }
    return Promise.resolve({ body, contentType });
  };
}

/** A text request body under the declared media type. */
export function textBody(contentType: string): BodyEncoder {
  return (input) => {
    if (typeof input !== 'string') {
      throw new TypeError('text body must be a string');
    }
    return Promise.resolve({ body: input, contentType });
  };
}

// The bytes are passed to fetch untouched: a streaming body is never validated and never
// transformed, because both are whole-value operations over a value that does not exist yet at
// dispatch time, and a per-chunk check would have no branch to report into once the request has
// been sent. A stream that errors mid-flight surfaces as fetch's own rejection.
/** A streaming request body under the declared media type. */
export function streamBody(contentType: string): BodyEncoder {
  return (input) => {
    if (!(input instanceof ReadableStream)) {
      throw new TypeError('streaming body must be a ReadableStream');
    }
    return Promise.resolve({ body: input, contentType, duplex: 'half' });
  };
}

/** A binary request body under the declared media type. */
export function binaryBody(contentType: string): BodyEncoder {
  return (input) => {
    if (!(input instanceof Uint8Array)) {
      throw new TypeError('binary body must be a Uint8Array');
    }
    return Promise.resolve({ body: Uint8Array.from(input), contentType });
  };
}

// The caller picks the wire media type, so the arm encoders are the union of body kinds this one
// operation declares — an arm the document never names is still never linked.
/** A request body whose media type the caller selects from the declared arms. */
export function discriminatedBody(
  arms: readonly (readonly [string, BodyEncoder])[],
): BodyEncoder {
  return async (input) => {
    if (!isRecord(input)) {
      throw new TypeError('content-discriminated body requires a wrapper');
    }
    const selected = selectedMediaType(input.contentType, arms, ([contentType]) => contentType);
    const encoded = await selected.entry[1](input.body);
    // The selected concrete type replaces the arm's declared one, but everything else the arm
    // decided about the body — `duplex` for a streaming arm — has to survive the swap.
    return encoded.duplex === undefined
      ? { body: encoded.body, contentType: selected.concrete }
      : { body: encoded.body, contentType: selected.concrete, duplex: encoded.duplex };
  };
}

function headersFromPairs(pairs: readonly (readonly [string, string])[]): Headers {
  const headers = new Headers();
  for (const [name, value] of pairs) {
    headers.append(name, value);
  }
  return headers;
}

function declarativeHeaders(
  transport: Transport,
  descriptor: OperationDescriptor,
  options: CallOptions | undefined,
): { readonly defaults: Headers; readonly call: Headers } {
  const defaults = headersFromPairs(transport.headers);
  const call = new Headers(options?.headers);
  const credentialHeaders = new Set(descriptor.credentialHeaders.map((name) => name.toLowerCase()));
  for (const headers of [defaults, call]) {
    for (const [name] of headers) {
      if (
        name === 'content-type' ||
        (descriptor.accept !== null && name === 'accept') ||
        credentialHeaders.has(name)
      ) {
        throw new TypeError(`header ${name} is operation-owned`);
      }
    }
  }
  return { defaults, call };
}

function isForbiddenHeader(headers: Headers): boolean {
  for (const [rawName, rawValue] of headers) {
    const name = rawName.toLowerCase();
    if (
      FORBIDDEN_HEADER_NAMES.has(name) ||
      name.startsWith('proxy-') ||
      name.startsWith('sec-')
    ) {
      return true;
    }
    if (METHOD_OVERRIDE_HEADERS.has(name)) {
      for (const value of rawValue.split(',')) {
        if (FORBIDDEN_OVERRIDE_VALUES.has(value.trim().toLowerCase())) {
          return true;
        }
      }
    }
  }
  return false;
}

function assertAllowedHeaders(headers: Headers, message: string): void {
  if (isForbiddenHeader(headers)) {
    throw new TypeError(message);
  }
}

function mergedHeaders(
  transport: Transport,
  descriptor: OperationDescriptor,
  input: Readonly<Record<string, unknown>>,
  options: CallOptions | undefined,
  bodyContentType: string | null,
  authHeaders: readonly (readonly [string, string])[],
): Headers {
  const layers = declarativeHeaders(transport, descriptor, options);
  const headers = new Headers(layers.defaults);
  for (const [name, value] of layers.call) {
    headers.set(name, value);
  }
  for (const plan of descriptor.params) {
    if (plan.location !== 'header') {
      continue;
    }
    const value = serializedParam(plan, input);
    if (value !== null) {
      headers.set(plan.name, value);
    }
  }
  if (bodyContentType !== null) {
    headers.set('Content-Type', bodyContentType);
  }
  if (descriptor.accept !== null) {
    headers.set('Accept', descriptor.accept);
  }
  for (const [name, value] of authHeaders) {
    headers.set(name, value);
  }
  assertAllowedHeaders(headers, 'a generated request header is forbidden');
  return headers;
}

function fetchOptions(
  transport: Transport,
  descriptor: OperationDescriptor,
  options: CallOptions | undefined,
): {
  readonly standard: Readonly<Record<string, unknown>>;
  readonly sidecar: Readonly<Record<string, unknown>>;
} {
  const merged: Record<string, unknown> = { ...descriptor.fetchDefaults };
  if (transport.credentials !== undefined) {
    merged.credentials = transport.credentials;
  }
  Object.assign(merged, options?.fetchOptions);

  const standard: Record<string, unknown> = {};
  const extensions: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(merged)) {
    if (STANDARD_FETCH_OPTIONS.has(name)) {
      standard[name] = value;
    } else {
      extensions[name] = value;
    }
  }
  return {
    standard: Object.freeze(standard),
    sidecar: Object.freeze(extensions),
  };
}

function responseMeta(provenanceUrl: string, response: Response): ResponseMeta {
  return {
    url: provenanceUrl,
    status: response.status,
    headers: new Headers(response.headers),
  };
}

// The three fields every response-phase failure carries: which declared branch was selected (null
// when none was), the wire status, and the metadata snapshot. Spread into each tagged constructor
// so a new failure tag cannot silently omit one.
type ResponseFailureBase = {
  readonly match: number | ResponseRangeKey | null;
  readonly status: number;
  readonly meta: ResponseMeta;
};

function responseFailureBase(
  provenanceUrl: string,
  response: Response,
  match: number | ResponseRangeKey | null,
): ResponseFailureBase {
  return { match, status: response.status, meta: responseMeta(provenanceUrl, response) };
}

function responseMiddlewareFailure(
  provenanceUrl: string,
  response: Response,
  cause: unknown,
): ExecutionResult {
  // No branch was selected yet — middleware runs before status matching — so `match` is null.
  return { outcome: 'response-middleware', ok: false, ...responseFailureBase(provenanceUrl, response, null), cause };
}

// Branches on the whole object literal for the same reason `abortedRequest` does: a conditional in
// the discriminant position widens `outcome` to `string`.
function responseAbortFailure(
  provenanceUrl: string,
  response: Response,
  match: number | ResponseRangeKey | null,
  reason: unknown,
): ExecutionResult {
  const base = responseFailureBase(provenanceUrl, response, match);
  return isTimeoutReason(reason)
    ? { outcome: 'response-timeout', ok: false, ...base, reason }
    : { outcome: 'response-aborted', ok: false, ...base, reason };
}

function matchedResponsePlan(
  descriptor: OperationDescriptor,
  status: number,
): ResponsePlan | null {
  const exact = descriptor.responses.find(
    (plan) => plan.kind === 'exact' && plan.status === status,
  );
  if (exact !== undefined) {
    return exact;
  }
  const statusClass = String(Math.floor(status / 100));
  const range = descriptor.responses.find(
    (plan) =>
      plan.kind === 'range' &&
      plan.match.length === 3 &&
      plan.match[0] === statusClass &&
      plan.match.slice(1).toLowerCase() === 'xx',
  );
  if (range !== undefined) {
    return range;
  }
  return descriptor.responses.find((plan) => plan.kind === 'default') ?? null;
}

// The selected entry plus the parsed received media type, which the multipart branch needs for its
// `boundary` parameter — the boundary is never declared, it only ever arrives on the wire.
type SelectedResponseMedia = {
  readonly entry: readonly [string, ResponseMediaDecoder];
  readonly actual: ParsedMediaType;
};

type JsonParseContext = { readonly source?: unknown };

let jsonParseProbeContext: unknown;
JSON.parse('0', (_key: string, value: unknown, context?: JsonParseContext) => {
  jsonParseProbeContext = context;
  return value;
});
const jsonParseHasSource =
  isRecord(jsonParseProbeContext) && jsonParseProbeContext.source === '0';
const NONZERO_DIGIT = /[1-9]/u;
const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const MIN_SAFE_BIGINT = BigInt(Number.MIN_SAFE_INTEGER);

function jsonIntegerToken(source: string): bigint | null {
  // `context.source` for a numeric reviver value is always a valid JSON number token.
  const exponentIndex = source.search(/[eE]/u);
  const mantissa = exponentIndex === -1 ? source : source.slice(0, exponentIndex);
  const exponent = exponentIndex === -1 ? '0' : source.slice(exponentIndex + 1);
  const sign = mantissa.startsWith('-') ? '-' : '';
  const unsignedMantissa = sign === '' ? mantissa : mantissa.slice(1);
  const decimalIndex = unsignedMantissa.indexOf('.');
  const whole = decimalIndex === -1 ? unsignedMantissa : unsignedMantissa.slice(0, decimalIndex);
  const fraction = decimalIndex === -1 ? '' : unsignedMantissa.slice(decimalIndex + 1);
  const digits = `${whole}${fraction}`;
  const scale = BigInt(exponent) - BigInt(fraction.length);
  let magnitude: bigint;
  try {
    if (scale >= 0n) {
      magnitude = BigInt(digits) * 10n ** scale;
    } else {
      const decimalPlaces = -scale;
      if (decimalPlaces >= BigInt(digits.length)) {
        return NONZERO_DIGIT.test(digits) ? null : 0n;
      }
      const retainedLength = digits.length - Number(decimalPlaces);
      if (NONZERO_DIGIT.test(digits.slice(retainedLength))) {
        return null;
      }
      magnitude = BigInt(digits.slice(0, retainedLength));
    }
  } catch {
    return null;
  }
  return sign === '-' ? -magnitude : magnitude;
}

function losslessInt64Reviver(
  _key: string,
  value: unknown,
  context?: JsonParseContext,
): unknown {
  if (
    typeof value !== 'number' ||
    context === undefined ||
    typeof context.source !== 'string'
  ) {
    return value;
  }
  const integer = jsonIntegerToken(context.source);
  return integer !== null && (integer < MIN_SAFE_BIGINT || integer > MAX_SAFE_BIGINT)
    ? integer
    : value;
}

function selectedResponseMedia(
  rawContentType: string | null,
  media: ResponsePlan['media'],
): SelectedResponseMedia | null {
  if (rawContentType === null) {
    return null;
  }
  const actual = parseMediaType(rawContentType);
  if (actual === null || actual.type === '*' || actual.subtype === '*') {
    return null;
  }
  const index = mostSpecificMedia(
    actual,
    media.map((entry) => entry[0]),
  );
  const entry = index < 0 ? undefined : media[index];
  return entry === undefined ? null : { entry, actual };
}

async function decodedBody(
  bytes: ArrayBuffer,
  decoder: 'json' | 'text' | 'binary' | LosslessJsonResponseDecoder,
): Promise<unknown> {
  if (decoder === 'json') {
    return new Response(bytes).json();
  }
  if (typeof decoder !== 'string') {
    const text = await new Response(bytes).text();
    const value: unknown = JSON.parse(text);
    return jsonParseHasSource
      ? decoder.revive(value, JSON.parse(text, losslessInt64Reviver))
      : value;
  }
  if (decoder === 'text') {
    return new Response(bytes).text();
  }
  return bytes;
}


function isJsonMediaType(parsed: ParsedMediaType): boolean {
  return parsed.type === 'application' &&
    (parsed.subtype === 'json' || parsed.subtype.endsWith('+json'));
}

function isTextMediaType(parsed: ParsedMediaType): boolean {
  return parsed.type === 'text' ||
    (parsed.type === 'application' && parsed.subtype === 'x-www-form-urlencoded');
}

async function unknownHttpError(
  bytes: ArrayBuffer,
  rawContentType: string | null,
): Promise<UnknownHttpError> {
  if (bytes.byteLength === 0) {
    return { kind: 'empty', contentType: rawContentType, body: undefined };
  }
  const parsed = rawContentType === null ? null : parseMediaType(rawContentType);
  if (rawContentType !== null && parsed !== null && isJsonMediaType(parsed)) {
    return {
      kind: 'json',
      contentType: rawContentType,
      body: await decodedBody(bytes, 'json'),
    };
  }
  if (rawContentType !== null && parsed !== null && isTextMediaType(parsed)) {
    return {
      kind: 'text',
      contentType: rawContentType,
      body: await new Response(bytes).text(),
    };
  }
  return { kind: 'binary', contentType: rawContentType, body: bytes };
}

function matchedResponseResult(
  plan: ResponsePlan,
  status: number,
  payload: unknown,
  selectedContentType: string | null,
  meta: ResponseMeta,
): ExecutionResult {
  const outcome = responseOutcome(plan);
  const ok = status >= 200 && status <= 299;
  if (ok) {
    if (plan.hasContentTypeDiscriminant && selectedContentType !== null) {
      return { outcome, ok: true, status, data: payload, contentType: selectedContentType, meta };
    }
    return { outcome, ok: true, status, data: payload, meta };
  }
  if (plan.hasContentTypeDiscriminant && selectedContentType !== null) {
    return { outcome, ok: false, status, error: payload, contentType: selectedContentType, meta };
  }
  return { outcome, ok: false, status, error: payload, meta };
}

function decodeFailure(
  provenanceUrl: string,
  response: Response,
  match: number | ResponseRangeKey | null,
  message: string,
  cause?: unknown,
): ExecutionResult {
  const base = responseFailureBase(provenanceUrl, response, match);
  return cause === undefined
    ? { outcome: 'response-decode', ok: false, ...base, message }
    : { outcome: 'response-decode', ok: false, ...base, message, cause };
}

async function responseBytes(
  provenanceUrl: string,
  response: Response,
  match: number | ResponseRangeKey | null,
  signal: AbortSignal,
): Promise<ArrayBuffer | ExecutionResult> {
  if (response.body === null) {
    return new ArrayBuffer(0);
  }
  try {
    return await response.arrayBuffer();
  } catch (cause) {
    if (signal.aborted) {
      return responseAbortFailure(provenanceUrl, response, match, signal.reason);
    }
    return decodeFailure(provenanceUrl, response, match, 'response body read failed', cause);
  }
}

// What the pre-read media selection carries forward to the buffered decode: the declared media key
// the result reports, the received media parameters (the multipart boundary lives only there), and
// the decoder itself, already narrowed to the ones that need the whole body.
type BufferedSelection = {
  readonly media: string;
  readonly parameters: ParsedMediaType['parameters'];
  readonly decoder: BufferedResponseDecoder;
};

async function assembleResponse(
  provenanceUrl: string,
  response: Response,
  plan: ResponsePlan | null,
  signal: AbortSignal,
): Promise<ExecutionResult> {
  const match = plan === null ? null : responseOutcome(plan);
  const rawContentType = response.headers.get('Content-Type');
  // Media selection happens here, before a single body byte is read: a streaming branch has to
  // resolve at the response headers and hand the caller a body nothing has drained. Selection is
  // pure, so hoisting it changes no failure ordering — the buffered path below consumes what this
  // decided instead of deciding again, and every one of its failures still fires where it did.
  let buffered: BufferedSelection | null = null;
  if (plan !== null && !plan.bodyless && plan.media.length !== 0) {
    if (response.status === 204 || response.status === 205 || response.status === 304) {
      return decodeFailure(
        provenanceUrl,
        response,
        match,
        `bodyless status ${String(response.status)} cannot satisfy declared content for ${plan.match}`,
      );
    }
    const selected = selectedResponseMedia(rawContentType, plan.media);
    if (selected !== null) {
      const decoder = selected.entry[1];
      if (isStreamingResponseDecoder(decoder)) {
        if (response.body === null) {
          // A declared stream that carries no body at all is the same contract violation as a
          // declared payload with no bytes.
          return decodeFailure(
            provenanceUrl,
            response,
            match,
            `streaming response branch ${plan.match} received no body`,
          );
        }
        return matchedResponseResult(
          plan,
          response.status,
          'sse' in decoder
            ? decoder.sse(response.body, signal, decoder.onEvent)
            : decoder.raw(response.body, signal),
          selected.entry[0],
          responseMeta(provenanceUrl, response),
        );
      }
      buffered = {
        media: selected.entry[0],
        parameters: selected.actual.parameters,
        decoder,
      };
    }
  }

  const read = await responseBytes(provenanceUrl, response, match, signal);
  if (!(read instanceof ArrayBuffer)) {
    return read;
  }
  if (plan === null) {
    try {
      const error = await unknownHttpError(read, rawContentType);
      return {
        outcome: 'unmatched',
        ok: false,
        status: response.status,
        error,
        meta: responseMeta(provenanceUrl, response),
      };
    } catch (cause) {
      return decodeFailure(
        provenanceUrl,
        response,
        null,
        'unmatched response body decoding failed',
        cause,
      );
    }
  }

  if (plan.bodyless) {
    if (read.byteLength !== 0) {
      return decodeFailure(
        provenanceUrl,
        response,
        match,
        `bodyless response branch ${plan.match} received body bytes`,
      );
    }
    return matchedResponseResult(
      plan,
      response.status,
      undefined,
      null,
      responseMeta(provenanceUrl, response),
    );
  }
  if (plan.media.length === 0) {
    if (read.byteLength !== 0) {
      return decodeFailure(
        provenanceUrl,
        response,
        match,
        `no-payload response branch ${plan.match} received body bytes`,
      );
    }
    return matchedResponseResult(
      plan,
      response.status,
      undefined,
      null,
      responseMeta(provenanceUrl, response),
    );
  }

  if (buffered === null) {
    return decodeFailure(
      provenanceUrl,
      response,
      match,
      rawContentType === null
        ? 'response Content-Type is missing for a declared payload'
        : `response Content-Type ${rawContentType} does not match declared content`,
    );
  }
  try {
    // The multipart decoder is reached only through the descriptor, so a client with no multipart
    // response never links it. It takes the received media parameters because the boundary lives
    // there and nowhere else.
    const decoder = buffered.decoder;
    const payload = typeof decoder === 'string' || 'json' in decoder
      ? await decodedBody(read, decoder)
      : decoder.decode(new Uint8Array(read), buffered.parameters, decoder.plan);
    return matchedResponseResult(
      plan,
      response.status,
      payload,
      buffered.media,
      responseMeta(provenanceUrl, response),
    );
  } catch (cause) {
    return decodeFailure(
      provenanceUrl,
      response,
      match,
      `response body decoding failed for ${buffered.media}`,
      cause,
    );
  }
}

// Cookie parameters (OAS 3.1 §4.8, `in: cookie`) are operation-owned: each serializes to one
// `name=value` cookie-pair (RFC 6265 §4.1.1) and they join, in declared order, into a single Cookie
// header. They are assembled outside `mergedHeaders` — the caller-header validation path that
// forbids a caller/middleware-injected Cookie — so the operation's own Cookie stays exempt while a
// caller's stays rejected. `serialized` is the wire pair; `name` is the declared parameter name,
// surfaced in the unsendable failure.
type CookieParam = { readonly name: string; readonly serialized: string };

function operationCookieParams(
  descriptor: OperationDescriptor,
  input: Readonly<Record<string, unknown>>,
): readonly CookieParam[] {
  const cookies: CookieParam[] = [];
  for (const plan of descriptor.params) {
    if (plan.location !== 'cookie') {
      continue;
    }
    const serialized = serializedParam(plan, input);
    if (serialized !== null) {
      cookies.push({ name: plan.name, serialized });
    }
  }
  return cookies;
}

type CookieJar = { cookie: string };

function isCookieJar(value: unknown): value is CookieJar {
  return (
    typeof value === 'object' &&
    value !== null &&
    'cookie' in value &&
    typeof value.cookie === 'string'
  );
}

function readOrigin(value: unknown): string | null {
  if (
    typeof value === 'object' &&
    value !== null &&
    'origin' in value &&
    typeof value.origin === 'string'
  ) {
    return value.origin;
  }
  return null;
}

// Reflect.get returns `any`; the `unknown` return type contains it so no `any` escapes into the
// guards. `document`/`location` are absent from the Node lib typings, so they are read this way.
function ambientGlobal(key: string): unknown {
  return Reflect.get(globalThis, key);
}

function sameOriginCookieJar(requestUrl: string): CookieJar | null {
  const documentValue = ambientGlobal('document');
  if (!isCookieJar(documentValue)) {
    return null;
  }
  const origin = readOrigin(ambientGlobal('location'));
  if (origin === null || origin !== new URL(requestUrl).origin) {
    return null;
  }
  return documentValue;
}

function readCookieValue(jarText: string, name: string): string | null {
  const prefix = `${name}=`;
  for (const entry of jarText.split('; ')) {
    if (entry.startsWith(prefix)) {
      return entry.slice(prefix.length);
    }
  }
  return null;
}

// Writes each cookie-pair into the document jar and reads it back; a browser silently rejects a
// cookie it will not store (e.g. a disallowed name), so the round-trip is the only proof it took.
function writeVerifiedCookies(jar: CookieJar, cookies: readonly CookieParam[]): boolean {
  for (const cookie of cookies) {
    // Explicit `path=/` scopes the cookie to the whole origin. A bare `name=value` inherits the
    // document's default path (RFC 6265 §5.1.4), which can exclude the API route even though the
    // read-back below — resolved against the document URL — still verifies.
    jar.cookie = `${cookie.serialized}; path=/`;
    const separator = cookie.serialized.indexOf('=');
    const name = cookie.serialized.slice(0, separator);
    const value = cookie.serialized.slice(separator + 1);
    if (readCookieValue(jar.cookie, name) !== value) {
      return false;
    }
  }
  return true;
}

type CookieRequestPlan =
  | { readonly kind: 'request'; readonly request: Request }
  | {
      readonly kind: 'failure';
      readonly result: RequestPhaseFailure;
    };

function cookieUnsendableResult(names: readonly string[]): RequestPhaseFailure {
  return { outcome: 'cookie-params-unsendable', ok: false, names };
}

// Layered cookie-delivery guard. It never dispatches and never sniffs the user agent: it builds the
// actual Request, inspects it, and returns the request to send or a failure. Layer 1 — Node/undici
// keeps the Cookie header, so send the probe. Layer 2 — a browser strips
// it (WHATWG Fetch forbidden request-header), so a same-origin document jar carries the cookies, but
// only when the request's credentials mode lets the browser attach them: `omit` attaches nothing,
// so a jar read-back would falsely verify a cookie the browser will silently drop. Layer 3 — neither
// path can deliver the declared cookies, so fail loudly rather than drop API surface.
function prepareCookieRequest(request: Request, cookies: readonly CookieParam[]): CookieRequestPlan {
  const headers = new Headers(request.headers);
  headers.set('cookie', cookies.map((cookie) => cookie.serialized).join('; '));
  const probe = new Request(request, { headers });
  if (probe.headers.get('cookie') !== null) {
    return { kind: 'request', request: probe };
  }
  const jar = sameOriginCookieJar(request.url);
  if (jar !== null && request.credentials !== 'omit' && writeVerifiedCookies(jar, cookies)) {
    return { kind: 'request', request: probe };
  }
  return { kind: 'failure', result: cookieUnsendableResult(cookies.map((cookie) => cookie.name)) };
}

export function execute<Result extends ExecutionResult, S extends string = never>(
  transport: Transport<S>,
  descriptor: OperationDescriptor,
  input: Readonly<Record<string, unknown>>,
  options?: CallOptions,
): Promise<Result>;
export function execute<S extends string = never>(
  transport: Transport<S>,
  descriptor: OperationDescriptor,
  input: Readonly<Record<string, unknown>>,
  options?: CallOptions,
): Promise<ExecutionResult>;
export async function execute<S extends string = never>(
  transport: Transport<S>,
  descriptor: OperationDescriptor,
  input: Readonly<Record<string, unknown>>,
  options?: CallOptions,
): Promise<ExecutionResult> {
  let url: URL;
  try {
    url = operationUrl(transport, descriptor, input);
  } catch (cause) {
    return encodeFailure(cause);
  }

  // An operation with no security requirement carries no resolver, so nothing here reaches the
  // selection and credential-serialization machinery.
  let authHeaders: readonly (readonly [string, string])[] = [];
  let selectedAuth: readonly string[] | null = null;
  if (descriptor.security !== null) {
    const resolved = await descriptor.security(transport, descriptor.operationId, options, url);
    if (resolved.kind === 'failure') {
      return resolved.result;
    }
    authHeaders = resolved.headers;
    selectedAuth = resolved.selected;
  }

  let finalRequest: Request;
  let sidecar: Readonly<Record<string, unknown>>;
  let context: OperationContext;
  let cookies: readonly CookieParam[];
  try {
    const serialized: SerializedBody = descriptor.body === null
      ? { body: null, contentType: null }
      : await descriptor.body(input.body);
    const headers = mergedHeaders(
      transport,
      descriptor,
      input,
      options,
      serialized.contentType,
      authHeaders,
    );
    cookies = operationCookieParams(descriptor, input);
    const splitOptions = fetchOptions(transport, descriptor, options);
    sidecar = splitOptions.sidecar;
    finalRequest = new Request(url, {
      ...splitOptions.standard,
      method: descriptor.method,
      body: serialized.body,
      // After the caller's own fetch options, because a stream body without it is not constructible
      // at all — this is a requirement of the body, not a preference a caller can override.
      ...(serialized.duplex === undefined ? {} : { duplex: serialized.duplex }),
      headers,
      // `signal` is not a standard fetch option this transport forwards, so nothing below can be
      // overridden by omitting it — and omitting it is what an absent signal actually means.
      ...(options?.signal === undefined ? {} : { signal: options.signal }),
    });
    if (finalRequest.signal.aborted) {
      return abortedRequest(finalRequest.signal.reason);
    }
    context = Object.freeze({
      operationId: descriptor.operationId,
      method: descriptor.method,
      url: new URL(finalRequest.url),
      selectedAuth,
    });
  } catch (cause) {
    return encodeFailure(cause);
  }

  try {
    for (const middleware of transport.middleware) {
      if (middleware.onRequest === undefined) {
        continue;
      }
      const replacement = await middleware.onRequest(finalRequest, context);
      if (replacement !== undefined) {
        finalRequest = replacement;
      }
      assertAllowedHeaders(finalRequest.headers, 'request middleware produced a forbidden header');
    }
    assertAllowedHeaders(finalRequest.headers, 'request middleware produced a forbidden header');
  } catch (cause) {
    return requestMiddlewareFailure(cause);
  }

  if (finalRequest.signal.aborted) {
    return abortedRequest(finalRequest.signal.reason);
  }
  // The operation Cookie is attached here — after middleware header validation — so it is exempt
  // from the forbidden-header check while a caller-injected Cookie stays rejected. The guard builds
  // a fresh Request; probing it disturbs finalRequest's body, so the probe is what gets dispatched.
  let requestToDispatch = finalRequest;
  if (cookies.length !== 0) {
    let plan: CookieRequestPlan;
    try {
      plan = prepareCookieRequest(finalRequest, cookies);
    } catch (cause) {
      // prepareCookieRequest reconstructs the Request (a body-consuming middleware turns that into a
      // TypeError) and touches document.cookie (a hostile getter/setter throws SecurityError). Either
      // would escape the never-throws contract, so map it to the encode-failure shape like the
      // sibling body-serialization and middleware stages.
      return encodeFailure(cause);
    }
    if (plan.kind === 'failure') {
      return plan.result;
    }
    requestToDispatch = plan.request;
  }
  let fetchedResponse: Response;
  try {
    fetchedResponse = await (transport.fetch ?? globalThis.fetch)(requestToDispatch, sidecar);
  } catch (cause) {
    if (finalRequest.signal.aborted) {
      return abortedRequest(finalRequest.signal.reason);
    }
    return networkFailure(cause);
  }

  const provenanceUrl = fetchedResponse.url || finalRequest.url;
  let finalResponse = fetchedResponse;
  try {
    for (const middleware of transport.middleware) {
      if (middleware.onResponse === undefined) {
        continue;
      }
      const replacement = await middleware.onResponse(finalResponse, context);
      if (replacement !== undefined) {
        finalResponse = replacement;
      }
      if (finalResponse.bodyUsed) {
        throw new TypeError('response middleware consumed the response body');
      }
    }
  } catch (cause) {
    return responseMiddlewareFailure(provenanceUrl, finalResponse, cause);
  }

  const plan = matchedResponsePlan(descriptor, finalResponse.status);
  return assembleResponse(provenanceUrl, finalResponse, plan, finalRequest.signal);
}

export function executeOrThrow<Result extends ExecutionResult, S extends string = never>(
  transport: Transport<S>,
  descriptor: OperationDescriptor,
  input: Readonly<Record<string, unknown>>,
  options?: CallOptions,
): Promise<SuccessEnvelope<Result>>;
export function executeOrThrow<S extends string = never>(
  transport: Transport<S>,
  descriptor: OperationDescriptor,
  input: Readonly<Record<string, unknown>>,
  options?: CallOptions,
): Promise<unknown>;
export async function executeOrThrow<S extends string = never>(
  transport: Transport<S>,
  descriptor: OperationDescriptor,
  input: Readonly<Record<string, unknown>>,
  options?: CallOptions,
): Promise<unknown> {
  return unwrap(await execute(transport, descriptor, input, options));
}
