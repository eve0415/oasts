// Hand-derived security-alternative SELECTION vectors for the runtime auth resolver. These are
// authored BEFORE the resolver exists and are hash-frozen: the implementation is written to
// satisfy them. NEVER regenerate these from implementation output — every `expected` below is
// derived only from the frozen selection contract transcribed in this header, not observed from
// a running resolver. This file is DATA ONLY: it imports nothing and a later harness wires each
// field mechanically (see the field-by-field interpretation under "Harness wiring").
//
// Scope: this file pins WHICH security-requirement alternative a call selects and WHICH providers
// run, not how a chosen credential is serialized onto the wire. Credentials here are valid dummies
// of the correct shape purely so serialization can never fail and mask a selection result; the
// dummy bytes are never asserted.
//
// ── The frozen selection contract (transcribed; the sole source of every `expected`) ───────────
//
// An operation carries an ordered list of security alternatives (OR across the list, AND within
// one alternative). Each alternative is a list of scheme uses; the EMPTY alternative is the
// anonymous `{}` alternative. Per-call values take precedence over transport providers, per
// scheme. Every alternative is evaluated against the UNION of per-call values and transport
// providers: an AND alternative is ELIGIBLE when each of its member schemes has at least one
// source — a per-call value or a configured provider. Selection is deterministic and fail-closed:
//
//   Rule 1 (per-call short-circuit). The FIRST (document order) non-empty alternative fully
//     satisfied by per-call auth ALONE wins. Only that alternative's credentials are serialized;
//     surplus per-call credentials for other schemes are ignored; NO providers are invoked at all.
//     This full-document scan runs BEFORE Rule 2, so a later per-call-satisfied alternative beats
//     an earlier alternative that only a provider could have satisfied.
//
//   Rule 2 (provider fill). Otherwise, eligible non-empty alternatives are tried in document
//     order. Per-call values cover their schemes; providers are invoked only for the remaining
//     member schemes, in the alternative's member order. A provider returning null marks its
//     containing alternative unsatisfiable, and selection proceeds to the next non-anonymous
//     eligible alternative. A per-call-covered scheme's provider is NEVER invoked (per-scheme
//     precedence), even when one is configured.
//
//   Rule 3 (anonymous). The anonymous (empty) alternative is entered ONLY when it is the sole
//     remaining alternative AND either (a) no credentialed alternative was configured at all — no
//     member of any credentialed alternative had any source — or (b) the caller opted in per call
//     with the literal 'anonymous'. Null-fallthrough from a configured credentialed alternative
//     NEVER silently downgrades to anonymous: without the opt-in it is an auth failure. The
//     'anonymous' opt-in is PERMISSION for the anonymous fallback, not a command that skips
//     credentialed alternatives — credentialed alternatives are still evaluated first, and their
//     providers still run, before the fallback is taken.
//
//   Rule 4 (failure). When no alternative remains, the request is not sent and the operation
//     returns an auth failure naming the alternatives tried.
//
// Pinned edge interpretations (read literally, not re-derived):
//
//   • `triedAlternatives` lists EVERY non-anonymous alternative evaluated, in document order,
//     whether it was skipped as ineligible (a member scheme had no source) or found unsatisfiable
//     (a provider returned null) — each as its scheme-name array in document order. The anonymous
//     alternative NEVER appears in `triedAlternatives`.
//
//   • A thrown provider error ends the call immediately as an auth failure: no further
//     alternatives are tried, the thrown value is preserved as the failure's `cause`, and
//     `triedAlternatives` covers the alternatives evaluated up to AND INCLUDING the throwing one.
//
//   • An AND alternative serializes ALL member schemes on success. Its providers are invoked in
//     member order and evaluation STOPS at the first null member — a member listed after the null
//     one is never invoked, even if its provider is configured. One null member kills the whole
//     alternative; selection proceeds to the next.
//
//   • Providers are called only for tried alternatives and are never cached. The provider context
//     is { operationId, scheme, scopes, url }: the scheme NAME (not its kind) distinguishes two
//     schemes of the same kind, and `scopes` comes from the security requirement — the selected
//     alternative's own entry for that scheme (absent scopes ⇒ the empty list).
//
// ── Harness wiring (how a later harness turns each field into a call, mechanically) ────────────
//
//   alternatives : the operation's security alternatives in document order. Each inner array is
//                  one alternative; an EMPTY inner array is the anonymous `{}` alternative. Each
//                  entry is a scheme use { scheme, kind, param?, scopes? }; `param` is the declared
//                  header/query/cookie name for the apiKey kinds. A given scheme NAME uses one
//                  consistent kind/param everywhere it appears.
//
//   configured   : transport-level providers, keyed by scheme name. A scheme absent from this list
//                  has NO transport provider. behavior:
//                    'value' — the provider returns a valid dummy credential of the scheme's kind,
//                              synthesized by the harness from the kind found in `alternatives`:
//                              an RFC 6750 b64token string for bearer / oauth2 / openIdConnect,
//                              { username, password } for basic, a plain ASCII string for
//                              apiKeyHeader / apiKeyQuery, and the AmbientCookieCredential sentinel
//                              for apiKeyCookie.
//                    'null'  — the provider returns null.
//                    'throw' — the provider throws a sentinel error; that thrown value must be
//                              preserved as the auth failure's `cause`.
//
//   perCall      : absent  — no per-call auth was supplied.
//                  'anonymous' — the caller opted in to the anonymous fallback (Rule 3b).
//                  a record scheme-name → DummyCredential — a per-call value supplied for that
//                  scheme; its `type` MUST match that scheme's kind in `alternatives`. The harness
//                  passes it as the per-call auth for that scheme.
//
//   expected     : discriminate on `'failure' in expected`.
//                  Success ⇒ { selected, providerCalls?, providerContext? }:
//                    selected         — the winning alternative's scheme names in member order, or
//                                       null when the anonymous alternative was selected.
//                    providerCalls    — the exact ordered scheme names whose providers were
//                                       invoked, in invocation order (a per-call-covered scheme
//                                       never appears). Present — possibly empty — exactly when the
//                                       scenario turns on which providers ran.
//                    providerContext  — asserts the context passed to one named scheme's provider
//                                       carried exactly these `scopes` (and this `scheme` name).
//                  Failure ⇒ { failure: 'auth', triedAlternatives, causePreserved?, messageIncludes? }:
//                    triedAlternatives — see the pinned interpretation above.
//                    causePreserved    — when true, the thrown provider value is exposed as the
//                                        failure's `cause`.
//                    messageIncludes   — when present, a substring the failure message must contain
//                                        (a harness may assert it; no scenario here over-pins wording).

export type SchemeKind =
  | "basic"
  | "bearer"
  | "apiKeyHeader"
  | "apiKeyQuery"
  | "apiKeyCookie"
  | "oauth2"
  | "openIdConnect";

/** One scheme use inside an alternative. `param` is the declared name for the apiKey kinds. */
export type SchemeUse = {
  readonly scheme: string;
  readonly kind: SchemeKind;
  readonly param?: string;
  readonly scopes?: readonly string[];
};

/** An operation's security alternative. The EMPTY array is the anonymous `{}` alternative. */
export type Alternative = readonly SchemeUse[];

/**
 * A concrete, valid dummy credential shaped to its scheme's kind so serialization never fails and
 * cannot interfere with a selection assertion. The `type` discriminant MUST agree with the
 * matching scheme's `kind` in `alternatives`:
 *   "token"         ↔ bearer / oauth2 / openIdConnect (RFC 6750 b64token string)
 *   "basic"         ↔ basic
 *   "apiKey"        ↔ apiKeyHeader / apiKeyQuery
 *   "ambientCookie" ↔ apiKeyCookie (the AmbientCookieCredential sentinel; carries no string)
 * A `configured` provider with behavior "value" returns a credential of exactly this shape,
 * synthesized by the harness from the scheme's kind; a `perCall` entry supplies one explicitly.
 */
export type DummyCredential =
  | { readonly type: "token"; readonly token: string }
  | { readonly type: "basic"; readonly username: string; readonly password: string }
  | { readonly type: "apiKey"; readonly value: string }
  | { readonly type: "ambientCookie" };

export type ProviderBehavior = "value" | "null" | "throw";

/** A transport-level provider for one scheme. Schemes not listed have no provider. */
export type ConfiguredProvider = {
  readonly scheme: string;
  readonly behavior: ProviderBehavior;
};

/** Per-call auth: absent (no auth supplied), the anonymous opt-in, or per-scheme dummy values. */
export type PerCall = "anonymous" | Readonly<Record<string, DummyCredential>>;

/** Assertion that one scheme's provider context carried exactly these scopes. */
export type ProviderContextAssertion = {
  readonly scheme: string;
  readonly scopes: readonly string[];
};

export type ExpectedSuccess = {
  /** Winning alternative's scheme names in member order, or null when anonymous was selected. */
  readonly selected: readonly string[] | null;
  /** Exact ordered scheme names whose providers were invoked; present when the point turns on it. */
  readonly providerCalls?: readonly string[];
  readonly providerContext?: ProviderContextAssertion;
};

export type ExpectedFailure = {
  readonly failure: "auth";
  /** Every non-anonymous alternative evaluated, in document order, as scheme-name arrays. */
  readonly triedAlternatives: readonly (readonly string[])[];
  readonly causePreserved?: true;
  readonly messageIncludes?: string;
};

export type Expected = ExpectedSuccess | ExpectedFailure;

export type AuthSelectionScenario = {
  readonly name: string;
  readonly alternatives: readonly Alternative[];
  readonly configured: readonly ConfiguredProvider[];
  readonly perCall?: PerCall;
  readonly expected: Expected;
};

// Reused dummy per-call credentials. Values are readable, not meaningful; only their PRESENCE and
// their `type` (which must match the scheme's kind) matter to selection.
const PC_BEARER_A: DummyCredential = { type: "token", token: "percallBearerA" };
const PC_APIKEY_B: DummyCredential = { type: "apiKey", value: "percallApiKeyB" };

export const AUTH_SELECTION_SCENARIOS: readonly AuthSelectionScenario[] = [
  // 1. Rule 1: the FIRST non-empty alternative fully satisfied per-call wins; the surplus per-call
  //    credential for apiKeyB (a scheme in the losing alt1) is ignored; and because Rule 1 fires,
  //    NO providers run even though both are configured — providerCalls is empty.
  {
    name: "rule1: first per-call-satisfied alternative wins, surplus ignored, no providers run",
    alternatives: [
      [{ scheme: "bearerA", kind: "bearer" }],
      [{ scheme: "apiKeyB", kind: "apiKeyHeader", param: "X-Api-Key-B" }],
    ],
    configured: [
      { scheme: "bearerA", behavior: "value" },
      { scheme: "apiKeyB", behavior: "value" },
    ],
    perCall: { bearerA: PC_BEARER_A, apiKeyB: PC_APIKEY_B },
    expected: { selected: ["bearerA"], providerCalls: [] },
  },

  // 2. Rule 1 runs before Rule 2: a LATER alternative fully satisfied per-call (alt1) beats an
  //    EARLIER alternative (alt0) that only its provider could satisfy. Per-call supplies apiKeyB
  //    but not bearerA; alt0 has a provider but no per-call value, so the first per-call-satisfied
  //    alternative is alt1. Rule 1 selects it and bearerA's provider is never touched.
  {
    name: "rule1 before rule2: later per-call-satisfied alt beats earlier provider-only alt",
    alternatives: [
      [{ scheme: "bearerA", kind: "bearer" }],
      [{ scheme: "apiKeyB", kind: "apiKeyHeader", param: "X-Api-Key-B" }],
    ],
    configured: [{ scheme: "bearerA", behavior: "value" }],
    perCall: { apiKeyB: PC_APIKEY_B },
    expected: { selected: ["apiKeyB"], providerCalls: [] },
  },

  // 3. Rule 2 with no per-call values: alternatives are tried in document order; alt0's provider
  //    returns a value and wins, so alt1's provider is never reached.
  {
    name: "rule2: first provider-satisfied alternative selected in document order",
    alternatives: [
      [{ scheme: "bearerA", kind: "bearer" }],
      [{ scheme: "apiKeyB", kind: "apiKeyHeader", param: "X-Api-Key-B" }],
    ],
    configured: [
      { scheme: "bearerA", behavior: "value" },
      { scheme: "apiKeyB", behavior: "value" },
    ],
    expected: { selected: ["bearerA"], providerCalls: ["bearerA"] },
  },

  // 4. Rule 2 null-fallthrough: alt0's provider returns null (unsatisfiable), selection proceeds to
  //    alt1 whose provider returns a value. providerCalls shows both invocations, in order.
  {
    name: "rule2: null provider makes alt unsatisfiable, next eligible alt selected",
    alternatives: [
      [{ scheme: "bearerA", kind: "bearer" }],
      [{ scheme: "apiKeyB", kind: "apiKeyHeader", param: "X-Api-Key-B" }],
    ],
    configured: [
      { scheme: "bearerA", behavior: "null" },
      { scheme: "apiKeyB", behavior: "value" },
    ],
    expected: { selected: ["apiKeyB"], providerCalls: ["bearerA", "apiKeyB"] },
  },

  // 5. Rule 3a: anonymous entered as the sole remaining alternative because NO credentialed
  //    alternative was configured at all — bearerA has neither a provider nor a per-call value, so
  //    alt0 is ineligible. selected is null; no providers exist to run.
  {
    name: "rule3a: anonymous entered when sole remaining and nothing credentialed configured",
    alternatives: [[{ scheme: "bearerA", kind: "bearer" }], []],
    configured: [],
    expected: { selected: null, providerCalls: [] },
  },

  // 6. Rule 3 fail-closed: alt0 IS configured (provider) but returns null. Anonymous is present but
  //    the caller did not opt in, so null-fallthrough does NOT downgrade to anonymous — it is an
  //    auth failure. The anonymous alternative never appears in triedAlternatives.
  {
    name: "rule3: null-fallthrough without opt-in is auth failure, not silent anonymous",
    alternatives: [[{ scheme: "bearerA", kind: "bearer" }], []],
    configured: [{ scheme: "bearerA", behavior: "null" }],
    expected: { failure: "auth", triedAlternatives: [["bearerA"]] },
  },

  // 7. Rule 3b: same shape as 6 but the caller opts in with 'anonymous'. The opt-in is a
  //    permission, not a skip: alt0 is still evaluated FIRST (bearerA's provider runs and returns
  //    null), THEN the anonymous fallback is taken. providerCalls proves bearerA ran.
  {
    name: "rule3b: anonymous opt-in permits fallback but credentialed alt is still evaluated first",
    alternatives: [[{ scheme: "bearerA", kind: "bearer" }], []],
    configured: [{ scheme: "bearerA", behavior: "null" }],
    perCall: "anonymous",
    expected: { selected: null, providerCalls: ["bearerA"] },
  },

  // 8. Thrown provider ends the call immediately: alt0's provider throws, alt1 is never tried
  //    (apiKeyB's provider never runs), the thrown value is preserved as cause, and
  //    triedAlternatives stops at the throwing alternative.
  {
    name: "throw: provider error is immediate auth failure, no further alternatives tried",
    alternatives: [
      [{ scheme: "bearerA", kind: "bearer" }],
      [{ scheme: "apiKeyB", kind: "apiKeyHeader", param: "X-Api-Key-B" }],
    ],
    configured: [
      { scheme: "bearerA", behavior: "throw" },
      { scheme: "apiKeyB", behavior: "value" },
    ],
    expected: { failure: "auth", triedAlternatives: [["bearerA"]], causePreserved: true },
  },

  // 9. Rule 4: no alternative remains → auth failure naming every evaluated alternative in document
  //    order. alt0 is INELIGIBLE (bearerA has no source); alt1 is NULL-FAILED (apiKeyB returns
  //    null). Both appear in triedAlternatives, in document order; there is no anonymous alt.
  {
    name: "rule4: no alt remains; triedAlternatives lists ineligible then null-failed, in order",
    alternatives: [
      [{ scheme: "bearerA", kind: "bearer" }],
      [{ scheme: "apiKeyB", kind: "apiKeyHeader", param: "X-Api-Key-B" }],
    ],
    configured: [{ scheme: "apiKeyB", behavior: "null" }],
    expected: { failure: "auth", triedAlternatives: [["bearerA"], ["apiKeyB"]] },
  },

  // 10. AND alternative fully satisfied: both members' providers return values, both are serialized,
  //     and `selected` lists all members in member order. providerCalls follows member order.
  {
    name: "and: all members satisfied, all serialized, selected lists every member",
    alternatives: [
      [
        { scheme: "basicA", kind: "basic" },
        { scheme: "bearerB", kind: "bearer" },
      ],
    ],
    configured: [
      { scheme: "basicA", behavior: "value" },
      { scheme: "bearerB", behavior: "value" },
    ],
    expected: { selected: ["basicA", "bearerB"], providerCalls: ["basicA", "bearerB"] },
  },

  // 11. AND alternative, one null member: providers are invoked in member order and evaluation STOPS
  //     at the first null. apiKeyB (value) then apiKeyC (null) run; bearerB, listed AFTER the null,
  //     is never invoked though it is configured 'value'. alt0 is killed; alt1 (apiKeyD) wins.
  {
    name: "and: one null member kills the alt; evaluation stops at first null; selection proceeds",
    alternatives: [
      [
        { scheme: "apiKeyB", kind: "apiKeyHeader", param: "X-Api-Key-B" },
        { scheme: "apiKeyC", kind: "apiKeyHeader", param: "X-Api-Key-C" },
        { scheme: "bearerB", kind: "bearer" },
      ],
      [{ scheme: "apiKeyD", kind: "apiKeyHeader", param: "X-Api-Key-D" }],
    ],
    configured: [
      { scheme: "apiKeyB", behavior: "value" },
      { scheme: "apiKeyC", behavior: "null" },
      { scheme: "bearerB", behavior: "value" },
      { scheme: "apiKeyD", behavior: "value" },
    ],
    expected: { selected: ["apiKeyD"], providerCalls: ["apiKeyB", "apiKeyC", "apiKeyD"] },
  },

  // 12. Same-kind, distinct names: two bearer-kind schemes distinguished by scheme NAME. bearerA
  //     returns null, bearerB returns a value; selection names bearerB, and the winning provider's
  //     context carries the bearerB name (with no scopes, hence the empty list).
  {
    name: "same-kind: two bearer schemes distinguished by name in selection and context",
    alternatives: [
      [{ scheme: "bearerA", kind: "bearer" }],
      [{ scheme: "bearerB", kind: "bearer" }],
    ],
    configured: [
      { scheme: "bearerA", behavior: "null" },
      { scheme: "bearerB", behavior: "value" },
    ],
    expected: {
      selected: ["bearerB"],
      providerCalls: ["bearerA", "bearerB"],
      providerContext: { scheme: "bearerB", scopes: [] },
    },
  },

  // 13. Scopes flow to the provider context: the oauth2 requirement carries two scopes, and the
  //     provider context for oauthA receives EXACTLY those scopes, in requirement order.
  {
    name: "scopes: oauth2 requirement scopes reach the provider context unchanged",
    alternatives: [[{ scheme: "oauthA", kind: "oauth2", scopes: ["read:items", "write:items"] }]],
    configured: [{ scheme: "oauthA", behavior: "value" }],
    expected: {
      selected: ["oauthA"],
      providerCalls: ["oauthA"],
      providerContext: { scheme: "oauthA", scopes: ["read:items", "write:items"] },
    },
  },

  // ── Edge scenarios (each isolates one further facet of the same rules) ─────────────────────────

  // E1. Rule 3a degenerate: the anonymous alternative is the only alternative. It is entered
  //     directly; selected is null and no providers exist.
  {
    name: "edge: anonymous-only operation selects anonymous",
    alternatives: [[]],
    configured: [],
    expected: { selected: null, providerCalls: [] },
  },

  // E2. Rule 2 mixed-source AND: alt0's members draw from different sources — bearerA from a
  //     per-call value (it has no provider), apiKeyB from a provider. The alternative is eligible;
  //     only apiKeyB's provider runs; both members are serialized.
  {
    name: "edge: AND alt eligible via mixed per-call and provider sources; only the gap provider runs",
    alternatives: [
      [
        { scheme: "bearerA", kind: "bearer" },
        { scheme: "apiKeyB", kind: "apiKeyHeader", param: "X-Api-Key-B" },
      ],
    ],
    configured: [{ scheme: "apiKeyB", behavior: "value" }],
    perCall: { bearerA: PC_BEARER_A },
    expected: { selected: ["bearerA", "apiKeyB"], providerCalls: ["apiKeyB"] },
  },

  // E3. Per-scheme precedence is decisive: bearerA has a per-call value AND a 'throw' provider.
  //     Because per-call covers bearerA, its provider is never invoked, so the throw never happens
  //     and the call succeeds; only apiKeyB's provider runs.
  {
    name: "edge: per-call precedence keeps a throwing provider from ever running",
    alternatives: [
      [
        { scheme: "bearerA", kind: "bearer" },
        { scheme: "apiKeyB", kind: "apiKeyHeader", param: "X-Api-Key-B" },
      ],
    ],
    configured: [
      { scheme: "bearerA", behavior: "throw" },
      { scheme: "apiKeyB", behavior: "value" },
    ],
    perCall: { bearerA: PC_BEARER_A },
    expected: { selected: ["bearerA", "apiKeyB"], providerCalls: ["apiKeyB"] },
  },

  // E4. Rule 1 over an AND alternative: per-call fully covers both members, so Rule 1 fires and NO
  //     providers run even though both are configured 'value'.
  {
    name: "edge: rule1 fully covers an AND alt per-call; no providers run",
    alternatives: [
      [
        { scheme: "bearerA", kind: "bearer" },
        { scheme: "apiKeyB", kind: "apiKeyHeader", param: "X-Api-Key-B" },
      ],
    ],
    configured: [
      { scheme: "bearerA", behavior: "value" },
      { scheme: "apiKeyB", behavior: "value" },
    ],
    perCall: { bearerA: PC_BEARER_A, apiKeyB: PC_APIKEY_B },
    expected: { selected: ["bearerA", "apiKeyB"], providerCalls: [] },
  },

  // E5. Throw after a prior null: alt0 returns null (tried), alt1 throws (immediate failure), alt2
  //     is never reached. triedAlternatives covers alt0 and the throwing alt1, in order; cause is
  //     preserved.
  {
    name: "edge: throw after a null-failed alt; triedAlternatives covers up to the throwing alt",
    alternatives: [
      [{ scheme: "bearerA", kind: "bearer" }],
      [{ scheme: "apiKeyB", kind: "apiKeyHeader", param: "X-Api-Key-B" }],
      [{ scheme: "apiKeyC", kind: "apiKeyHeader", param: "X-Api-Key-C" }],
    ],
    configured: [
      { scheme: "bearerA", behavior: "null" },
      { scheme: "apiKeyB", behavior: "throw" },
      { scheme: "apiKeyC", behavior: "value" },
    ],
    expected: {
      failure: "auth",
      triedAlternatives: [["bearerA"], ["apiKeyB"]],
      causePreserved: true,
    },
  },

  // E6. apiKeyCookie: the provider's 'value' is the AmbientCookieCredential sentinel, which
  //     satisfies the alternative; the cookie scheme is selected like any other.
  {
    name: "edge: apiKeyCookie provider (ambient sentinel) satisfies and is selected",
    alternatives: [[{ scheme: "cookieA", kind: "apiKeyCookie", param: "session" }]],
    configured: [{ scheme: "cookieA", behavior: "value" }],
    expected: { selected: ["cookieA"], providerCalls: ["cookieA"] },
  },
];
