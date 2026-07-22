// Relative `.ts` import suffixes are contractual: the Rust embedding engine rewrites them to the configured emit extension.
import {
  unwrap,
  type RequestFailure,
  type ResponseFailure,
  type ResponseMeta,
  type UnknownHttpError,
} from './result.ts';
import {
  checkCteDomain,
  EncodeError,
  encodeFormUrlencodedBody,
  encodeMultipart,
  parseMediaType,
  serializeMediaType,
  serializeQueryFormExplode,
  type MultipartPart,
  type ParamPrimitive,
  type ParamValue,
  type ParsedMediaType,
  type UrlencodedField,
  type UrlencodedStyleField,
} from './serialize.ts';

//#region oxs:auth
export type AuthContext = { readonly operationId: string; readonly scheme: string; readonly scopes: readonly string[]; readonly url: string };
export type BasicCredential = { readonly username: string; readonly password: string };
export const AmbientCookieCredential: unique symbol = Symbol('AmbientCookieCredential');
export type AuthCredential = string | BasicCredential | typeof AmbientCookieCredential;
export type AuthProvider = (context: AuthContext) => AuthCredential | null | Promise<AuthCredential | null>;
export type AuthProviders<S extends string = never> = Readonly<Record<S, AuthProvider>>;
export type AuthOverrides = 'anonymous' | Readonly<Record<string, AuthCredential>>;
//#endregion

export type TransportConfig<S extends string = never> = {
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

export type ParamPlan = {
  readonly name: string;
  readonly location: 'path' | 'query' | 'header';
  readonly required: boolean;
  readonly serialize: ParamSerializer;
  readonly allowReserved: boolean;
};

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
  readonly contentType: MultipartContentTypePolicy;
  readonly filename: boolean;
  readonly cte?: MultipartPart['cte'];
};

export type BodyPlan =
  | { readonly kind: 'json'; readonly contentType: string }
  | { readonly kind: 'text'; readonly contentType: string }
  | { readonly kind: 'binary'; readonly contentType: string }
  | {
      readonly kind: 'form-urlencoded';
      readonly contentType: string;
      readonly fields: readonly UrlencodedFieldPlan[];
    }
  | { readonly kind: 'multipart'; readonly fields: readonly MultipartFieldPlan[] }
  | {
      readonly kind: 'content-discriminated';
      readonly arms: readonly (readonly [string, BodyPlan])[];
    };

export type ResponsePlan = {
  readonly match: string;
  readonly kind: 'exact' | 'range' | 'default';
  readonly status: number | null;
  readonly bodyless: boolean;
  readonly media: readonly (readonly [string, 'json' | 'text' | 'binary'])[];
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
  readonly body: BodyPlan | null;
  readonly accept: string | null;
  readonly credentialHeaders: readonly string[];
  readonly security: readonly (readonly {
    readonly name: string;
    readonly kind: 'basic' | 'bearer' | 'apiKeyHeader' | 'apiKeyQuery' | 'apiKeyCookie' | 'oauth2' | 'openIdConnect';
    readonly param?: string;
    readonly scopes: readonly string[];
  }[])[];
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

export type ExecutionResult =
  | {
      readonly kind: 'response';
      readonly ok: true;
      readonly match: string;
      readonly status: number;
      readonly data: unknown;
      readonly contentType?: string;
      readonly meta: ResponseMeta;
    }
  | {
      readonly kind: 'response';
      readonly ok: false;
      readonly match: string;
      readonly status: number;
      readonly error: unknown;
      readonly contentType?: string;
      readonly meta: ResponseMeta;
    }
  | {
      readonly kind: 'unmatched-response';
      readonly ok: false;
      readonly match: null;
      readonly status: number;
      readonly error: UnknownHttpError;
      readonly meta: ResponseMeta;
    }
  | {
      readonly kind: 'response-failure';
      readonly ok: false;
      readonly match: string | null;
      readonly status: number;
      readonly error: ResponseFailure;
      readonly meta: ResponseMeta;
    }
  | {
      readonly kind: 'request-failure';
      readonly ok: false;
      readonly match: null;
      readonly status: null;
      readonly error: RequestFailure;
    };

type SerializedBody = {
  readonly body: BodyInit | null;
  readonly contentType: string | null;
};

type MultipartWrapper = {
  readonly body: unknown;
  readonly contentType: unknown;
  readonly headers: unknown;
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

type SecurityUse = OperationDescriptor['security'][number][number];

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
      readonly result: Extract<ExecutionResult, { readonly kind: 'request-failure' }>;
    };

type AuthSource =
  | { readonly kind: 'per-call'; readonly use: SecurityUse; readonly credential: unknown }
  | { readonly kind: 'provider'; readonly use: SecurityUse; readonly provider: unknown }
  | { readonly kind: 'missing'; readonly use: SecurityUse };

type AvailableAuthSource = Exclude<AuthSource, { readonly kind: 'missing' }>;

function authFailureResult(
  message: string,
  triedAlternatives: readonly (readonly string[])[],
): Extract<ExecutionResult, { readonly kind: 'request-failure' }> {
  return {
    kind: 'request-failure',
    ok: false,
    match: null,
    status: null,
    error: { kind: 'auth', message, triedAlternatives },
  };
}

function providerAuthFailureResult(
  message: string,
  triedAlternatives: readonly (readonly string[])[],
  cause: unknown,
): Extract<ExecutionResult, { readonly kind: 'request-failure' }> {
  return {
    kind: 'request-failure',
    ok: false,
    match: null,
    status: null,
    error: { kind: 'auth', message, triedAlternatives, cause },
  };
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

async function selectAuth<S extends string>(
  transport: Transport<S>,
  descriptor: OperationDescriptor,
  options: CallOptions | undefined,
  url: URL,
): Promise<AuthSelection> {
  if (descriptor.security.length === 0) {
    return { kind: 'anonymous', triedAlternatives: [] };
  }

  const perCall = perCallAuth(options);
  for (const [index, alternative] of descriptor.security.entries()) {
    if (
      alternative.length !== 0 &&
      perCall !== undefined &&
      alternative.every((use) => Object.hasOwn(perCall, use.name))
    ) {
      return {
        kind: 'selected',
        members: alternative.map((use) => ({ use, credential: perCall[use.name] })),
        triedAlternatives: descriptor.security
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
  for (const alternative of descriptor.security) {
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
        operationId: descriptor.operationId,
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

  const anonymousCount = descriptor.security.filter(
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

function serializeSelectedAuth(
  url: URL,
  members: readonly SelectedAuthMember[],
): SerializedAuth | string {
  const headers: (readonly [string, string])[] = [];
  const query: string[] = [];
  let occupiedQueryNames: Set<string> | undefined;
  for (const { use, credential } of members) {
    if (use.kind === 'bearer' || use.kind === 'oauth2' || use.kind === 'openIdConnect') {
      if (
        typeof credential !== 'string' ||
        !/^[A-Za-z0-9._~+/-]+=*$/u.test(credential)
      ) {
        return `Authentication scheme ${use.name} requires an RFC 6750 b64token`;
      }
      headers.push(['Authorization', `Bearer ${credential}`]);
      continue;
    }
    if (use.kind === 'basic') {
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
      headers.push(['Authorization', `Basic ${utf8Base64(`${username}:${password}`)}`]);
      continue;
    }
    if (use.kind === 'apiKeyHeader') {
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
      headers.push([use.param, credential]);
      continue;
    }
    if (use.kind === 'apiKeyQuery') {
      if (typeof credential !== 'string') {
        return `Authentication scheme ${use.name} query API key must be a string`;
      }
      if (use.param === undefined) {
        return `Authentication scheme ${use.name} has no declared query name`;
      }
      occupiedQueryNames ??= new Set(url.searchParams.keys());
      if (occupiedQueryNames.has(use.param)) {
        return `Authentication query parameter ${use.param} is already present`;
      }
      query.push(serializeQueryFormExplode(use.param, credential, false));
      occupiedQueryNames.add(use.param);
      continue;
    }
    if (use.kind === 'apiKeyCookie') {
      if (credential !== AmbientCookieCredential) {
        return `Authentication scheme ${use.name} requires the ambient cookie credential`;
      }
      continue;
    }
    // The kind union is closed at generation time; a hand-built or drifted descriptor must
    // fail closed rather than silently send the request without this member's credential.
    return `Authentication scheme ${use.name} uses an unrecognized security scheme kind`;
  }
  if (query.length !== 0) {
    const prefix = url.search.length === 0 ? '' : `${url.search.slice(1)}&`;
    url.search = `${prefix}${query.join('&')}`;
  }
  return { headers };
}

function isParamPrimitive(value: unknown): value is ParamPrimitive {
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';
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

function encodeFailure(cause: unknown): ExecutionResult {
  const message = cause instanceof Error ? cause.message : 'request encoding failed';
  return {
    kind: 'request-failure',
    ok: false,
    match: null,
    status: null,
    error: { kind: 'request-encode', message, cause },
  };
}

function requestMiddlewareFailure(cause: unknown): ExecutionResult {
  return {
    kind: 'request-failure',
    ok: false,
    match: null,
    status: null,
    error: { kind: 'request-middleware', cause },
  };
}

function abortedRequest(reason: unknown): ExecutionResult {
  return {
    kind: 'request-failure',
    ok: false,
    match: null,
    status: null,
    error: { kind: 'aborted', reason },
  };
}

function networkFailure(cause: unknown): ExecutionResult {
  return {
    kind: 'request-failure',
    ok: false,
    match: null,
    status: null,
    error: { kind: 'network', cause },
  };
}

function absoluteBaseUrl(transport: Transport, descriptor: OperationDescriptor): string {
  let resolved = transport.baseUrl;
  if (resolved === undefined) {
    if (descriptor.baseUrl.kind === 'runtime') {
      throw new TypeError('no absolute base URL resolved for the operation');
    }
    if (descriptor.baseUrl.kind === 'literal') {
      resolved = descriptor.baseUrl.value;
    } else {
      const server = descriptor.baseUrl.servers[descriptor.baseUrl.index];
      if (server === undefined) {
        throw new TypeError('the configured server index did not resolve');
      }
      resolved = server.url;
      for (const [name, declaredDefault] of server.variables) {
        const value = transport.serverVariables?.[name] ?? declaredDefault;
        resolved = resolved.replaceAll(`{${name}}`, value);
      }
      if (/\{[^{}]+\}/u.test(resolved)) {
        throw new TypeError('a server variable is unresolved');
      }
    }
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
  const value = input[plan.name];
  if (value === undefined) {
    if (plan.required) {
      throw new TypeError(`required parameter ${plan.name} is missing`);
    }
    return null;
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

function selectedMediaType(
  input: unknown,
  admitted: readonly string[],
): { readonly declared: string; readonly concrete: string; readonly index: number } {
  if (typeof input !== 'string') {
    throw new TypeError('a concrete contentType selection is required');
  }
  const actual = parseMediaType(input);
  if (actual === null || actual.type === '*' || actual.subtype === '*') {
    throw new TypeError('contentType must be a well-formed concrete media type');
  }

  for (const tier of ['exact', 'range', 'any'] as const) {
    for (const [index, declared] of admitted.entries()) {
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
        return { declared, concrete: serializeMediaType(actual), index };
      }
    }
  }
  throw new TypeError('contentType does not match an admitted media type');
}

function urlencodedBody(
  plan: Extract<BodyPlan, { readonly kind: 'form-urlencoded' }>,
  input: unknown,
): SerializedBody {
  if (!isRecord(input)) {
    throw new TypeError('form-urlencoded body must be an object');
  }
  const fields: UrlencodedField[] = [];
  for (const field of plan.fields) {
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
        const selected = selectedMediaType(wrapper.contentType, field.contentType.admitted);
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
    fields.push({
      name: field.name,
      value,
      style: field.style,
      explode: field.explode,
      allowReserved: field.allowReserved,
    });
  }
  return { body: encodeFormUrlencodedBody(fields), contentType: plan.contentType };
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
    headers: value.headers,
    filename: value.filename,
  };
}

function multipartHeaders(value: unknown): readonly (readonly [string, string])[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value)) {
    throw new TypeError('multipart wrapper headers must be an object');
  }
  const headers: (readonly [string, string])[] = [];
  for (const [name, headerValue] of Object.entries(value)) {
    if (typeof headerValue !== 'string') {
      throw new TypeError(`multipart header ${name} must be a string`);
    }
    headers.push([name, headerValue]);
  }
  return headers;
}

function checkCallerCte(
  headers: readonly (readonly [string, string])[] | undefined,
  payload: Uint8Array,
): void {
  for (const [name, value] of headers ?? []) {
    if (name.toLowerCase() !== 'content-transfer-encoding') {
      continue;
    }
    if (value !== '7bit' && value !== '8bit' && value !== 'binary') {
      throw new EncodeError(`multipart Content-Transfer-Encoding ${value} is not admitted`);
    }
    if (!checkCteDomain(value, payload)) {
      throw new EncodeError(
        `multipart payload violates the ${value} Content-Transfer-Encoding domain`,
      );
    }
  }
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
    if (typeof value !== 'string') {
      throw new TypeError('text multipart fields require a string');
    }
    return UTF8_ENCODER.encode(value);
  }
  const json = JSON.stringify(value);
  if (json === undefined) {
    throw new TypeError('JSON multipart field is not serializable');
  }
  return UTF8_ENCODER.encode(json);
}

function multipartContentType(
  plan: MultipartFieldPlan,
  selected: unknown,
): string | undefined {
  if (plan.contentType.kind === 'none') {
    return undefined;
  }
  if (!plan.wrapper) {
    if (plan.contentType.kind === 'selected') {
      throw new TypeError('selected multipart media requires a wrapper');
    }
    return plan.contentType.value;
  }
  const admitted =
    plan.contentType.kind === 'fixed' ? [plan.contentType.value] : plan.contentType.admitted;
  return selectedMediaType(selected, admitted).concrete;
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
  const payload = await multipartPayload(plan.payload, body);
  const extraHeaders = multipartHeaders(wrapper?.headers);
  checkCallerCte(extraHeaders, payload);
  return {
    name: plan.name,
    payload,
    contentType: multipartContentType(plan, wrapper?.contentType),
    filename: plan.filename ? selectedFilename ?? blobFilename(body) : undefined,
    extraHeaders,
    cte: plan.cte,
  };
}

async function multipartBody(
  plan: Extract<BodyPlan, { readonly kind: 'multipart' }>,
  input: unknown,
): Promise<SerializedBody> {
  if (!isRecord(input)) {
    throw new TypeError('multipart body must be an object');
  }
  const parts: MultipartPart[] = [];
  for (const field of plan.fields) {
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

async function serializeBody(plan: BodyPlan | null, input: unknown): Promise<SerializedBody> {
  if (plan === null) {
    return { body: null, contentType: null };
  }
  if (plan.kind === 'content-discriminated') {
    if (!isRecord(input)) {
      throw new TypeError('content-discriminated body requires a wrapper');
    }
    const selected = selectedMediaType(
      input.contentType,
      plan.arms.map(([contentType]) => contentType),
    );
    const arm = plan.arms[selected.index];
    const encoded = await serializeBody(arm[1], input.body);
    return { body: encoded.body, contentType: selected.concrete };
  }
  if (plan.kind === 'form-urlencoded') {
    return urlencodedBody(plan, input);
  }
  if (plan.kind === 'multipart') {
    return multipartBody(plan, input);
  }
  if (plan.kind === 'json') {
    const body = JSON.stringify(input);
    if (body === undefined) {
      throw new TypeError('JSON body is not serializable');
    }
    return { body, contentType: plan.contentType };
  }
  if (plan.kind === 'text') {
    if (typeof input !== 'string') {
      throw new TypeError('text body must be a string');
    }
    return { body: input, contentType: plan.contentType };
  }
  if (!(input instanceof Uint8Array)) {
    throw new TypeError('binary body must be a Uint8Array');
  }
  return { body: Uint8Array.from(input), contentType: plan.contentType };
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

function responseFailureResult(
  provenanceUrl: string,
  response: Response,
  match: string | null,
  error: ResponseFailure,
): ExecutionResult {
  return {
    kind: 'response-failure',
    ok: false,
    match,
    status: response.status,
    error,
    meta: responseMeta(provenanceUrl, response),
  };
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

function selectedResponseMedia(
  rawContentType: string | null,
  media: ResponsePlan['media'],
): (readonly [string, 'json' | 'text' | 'binary']) | null {
  if (rawContentType === null) {
    return null;
  }
  const actual = parseMediaType(rawContentType);
  if (actual === null || actual.type === '*' || actual.subtype === '*') {
    return null;
  }
  for (const tier of ['exact', 'range', 'any'] as const) {
    for (const entry of media) {
      const declared = parseMediaType(entry[0]);
      if (declared === null) {
        continue;
      }
      const exact = declared.type === actual.type && declared.subtype === actual.subtype;
      const range = declared.type === actual.type && declared.subtype === '*';
      const any = declared.type === '*' && declared.subtype === '*';
      if (
        (tier === 'exact' && exact) ||
        (tier === 'range' && range) ||
        (tier === 'any' && any)
      ) {
        return entry;
      }
    }
  }
  return null;
}

async function decodedBody(
  bytes: ArrayBuffer,
  decoder: 'json' | 'text' | 'binary',
): Promise<unknown> {
  if (decoder === 'json') {
    return new Response(bytes).json();
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
  const ok = status >= 200 && status <= 299;
  if (ok) {
    if (plan.hasContentTypeDiscriminant && selectedContentType !== null) {
      return {
        kind: 'response',
        ok: true,
        match: plan.match,
        status,
        data: payload,
        contentType: selectedContentType,
        meta,
      };
    }
    return {
      kind: 'response',
      ok: true,
      match: plan.match,
      status,
      data: payload,
      meta,
    };
  }
  if (plan.hasContentTypeDiscriminant && selectedContentType !== null) {
    return {
      kind: 'response',
      ok: false,
      match: plan.match,
      status,
      error: payload,
      contentType: selectedContentType,
      meta,
    };
  }
  return {
    kind: 'response',
    ok: false,
    match: plan.match,
    status,
    error: payload,
    meta,
  };
}

function decodeFailure(
  provenanceUrl: string,
  response: Response,
  match: string | null,
  message: string,
  cause?: unknown,
): ExecutionResult {
  const error: ResponseFailure =
    cause === undefined
      ? { kind: 'response-decode', message }
      : { kind: 'response-decode', message, cause };
  return responseFailureResult(provenanceUrl, response, match, error);
}

async function responseBytes(
  provenanceUrl: string,
  response: Response,
  match: string | null,
  signal: AbortSignal,
): Promise<ArrayBuffer | ExecutionResult> {
  if (response.body === null) {
    return new ArrayBuffer(0);
  }
  try {
    return await response.arrayBuffer();
  } catch (cause) {
    if (signal.aborted) {
      return responseFailureResult(provenanceUrl, response, match, {
        kind: 'aborted',
        reason: signal.reason,
      });
    }
    return decodeFailure(provenanceUrl, response, match, 'response body read failed', cause);
  }
}

async function assembleResponse(
  provenanceUrl: string,
  response: Response,
  plan: ResponsePlan | null,
  signal: AbortSignal,
): Promise<ExecutionResult> {
  const match = plan?.match ?? null;
  const rawContentType = response.headers.get('Content-Type');
  if (
    plan !== null &&
    !plan.bodyless &&
    plan.media.length !== 0 &&
    (response.status === 204 || response.status === 205 || response.status === 304)
  ) {
    return decodeFailure(
      provenanceUrl,
      response,
      plan.match,
      `bodyless status ${String(response.status)} cannot satisfy declared content for ${plan.match}`,
    );
  }

  const read = await responseBytes(provenanceUrl, response, match, signal);
  if (!(read instanceof ArrayBuffer)) {
    return read;
  }
  if (plan === null) {
    try {
      const error = await unknownHttpError(read, rawContentType);
      return {
        kind: 'unmatched-response',
        ok: false,
        match: null,
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
        plan.match,
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
        plan.match,
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

  const selected = selectedResponseMedia(rawContentType, plan.media);
  if (selected === null) {
    return decodeFailure(
      provenanceUrl,
      response,
      plan.match,
      rawContentType === null
        ? 'response Content-Type is missing for a declared payload'
        : `response Content-Type ${rawContentType} does not match declared content`,
    );
  }
  try {
    const payload = await decodedBody(read, selected[1]);
    return matchedResponseResult(
      plan,
      response.status,
      payload,
      selected[0],
      responseMeta(provenanceUrl, response),
    );
  } catch (cause) {
    return decodeFailure(
      provenanceUrl,
      response,
      plan.match,
      `response body decoding failed for ${selected[0]}`,
      cause,
    );
  }
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

  const selection = await selectAuth(transport, descriptor, options, url);
  if (selection.kind === 'failure') {
    return selection.result;
  }
  const members = selection.kind === 'selected' ? selection.members : [];
  const serializedAuth = serializeSelectedAuth(url, members);
  if (typeof serializedAuth === 'string') {
    return authFailureResult(serializedAuth, selection.triedAlternatives);
  }

  let finalRequest: Request;
  let sidecar: Readonly<Record<string, unknown>>;
  let context: OperationContext;
  try {
    const serialized = await serializeBody(descriptor.body, input.body);
    const headers = mergedHeaders(
      transport,
      descriptor,
      input,
      options,
      serialized.contentType,
      serializedAuth.headers,
    );
    const splitOptions = fetchOptions(transport, descriptor, options);
    sidecar = splitOptions.sidecar;
    finalRequest = new Request(url, {
      ...splitOptions.standard,
      method: descriptor.method,
      body: serialized.body,
      headers,
      signal: options?.signal,
    });
    if (finalRequest.signal.aborted) {
      return abortedRequest(finalRequest.signal.reason);
    }
    context = Object.freeze({
      operationId: descriptor.operationId,
      method: descriptor.method,
      url: new URL(finalRequest.url),
      selectedAuth: selection.kind === 'selected'
        ? selection.members.map((member) => member.use.name)
        : null,
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
  let fetchedResponse: Response;
  try {
    fetchedResponse = await (transport.fetch ?? globalThis.fetch)(finalRequest, sidecar);
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
    return responseFailureResult(provenanceUrl, finalResponse, null, {
      kind: 'response-middleware',
      cause,
    });
  }

  const plan = matchedResponsePlan(descriptor, finalResponse.status);
  return assembleResponse(provenanceUrl, finalResponse, plan, finalRequest.signal);
}

type SuccessfulData<Result extends ExecutionResult> = Result extends {
  readonly ok: true;
  readonly data: infer Data;
}
  ? Data
  : never;

export function executeOrThrow<Result extends ExecutionResult, S extends string = never>(
  transport: Transport<S>,
  descriptor: OperationDescriptor,
  input: Readonly<Record<string, unknown>>,
  options?: CallOptions,
): Promise<SuccessfulData<Result>>;
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
