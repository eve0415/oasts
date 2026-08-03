// TanStack descriptor runtime.
//
// Relative `.ts` import suffixes are contractual: the Rust embedding engine rewrites them to the
// configured emit extension. Every export here is part of the generated-tanstack ABI — emitted
// operation modules import it by name, so a rename is a breaking change to generated code.
//
// This module holds the one thing a descriptor needs that the client runtime does not provide, and
// deliberately nothing else. It imports no TanStack package, exactly as emitted tanstack code does.

import type { Middleware, Transport } from "./transport.ts";

/**
 * Returns a copy of `transport` whose in-flight request is also aborted by `signal`.
 *
 * A query descriptor is handed a per-fetch `AbortSignal` by whichever adapter drives it, and the
 * caller may independently have supplied one of their own in `CallOptions`. Neither may be dropped,
 * so the two are combined with `AbortSignal.any`.
 *
 * **Why the signal arrives through the transport rather than through `CallOptions`.** An
 * operation's generated `CallArgs<S>` is a deferred conditional tuple whenever the operation is
 * secured, and TypeScript accepts nothing as assignable to a deferred conditional except a value of
 * identically that type — so a descriptor cannot construct a replacement options object without an
 * unchecked cast. Wrapping the transport sidesteps that entirely: the descriptor spreads `args`
 * through unchanged, and the auth proof survives by identity.
 *
 * **Why a middleware rather than a `fetch` wrapper.** The transport adopts a middleware's
 * replacement request as the request it then reasons about, so the merged signal reaches the
 * pre-dispatch abort check, the abort-versus-network-failure discrimination on a rejected fetch,
 * and the response-body read. A `fetch` wrapper is downstream of all three: an abort would surface
 * as a decode failure rather than an abort.
 *
 * The replacement request is built with `new Request(request, ...)`, which marks the original's
 * body consumed. That is safe here because descriptors wrap reads only — `GET` and `HEAD`, which
 * Fetch forbids from carrying a body — and mutations are never wrapped, because TanStack supplies
 * no signal to a mutation function.
 */
export function withRequestSignal<S extends string>(
  transport: Transport<S>,
  signal: AbortSignal,
): Transport<S> {
  const merge: Middleware = {
    onRequest: (request) =>
      new Request(request, {
        signal: AbortSignal.any([request.signal, signal]),
        // Fetch resets a request's referrer and referrer policy whenever the constructor's init is
        // non-empty, so both are carried across explicitly. Without this a query would silently
        // fall back to the browser default while the same operation called through the client kept
        // whatever `client.fetchOptions.referrerPolicy` configured.
        referrer: request.referrer,
        referrerPolicy: request.referrerPolicy,
      }),
  };
  return { ...transport, middleware: [...transport.middleware, merge] };
}

/**
 * Appends an operation's non-path input to its path key, or leaves the key alone when the caller
 * supplied none of it.
 *
 * Whether an operation *declares* query, header or cookie parameters is known at generation time;
 * whether the caller *supplied* any is not. Appending unconditionally would leave an operation that
 * declares only optional parameters with a trailing `{}` element on every key — one that
 * `hashKey` cannot drop, because it drops undefined-valued properties and not empty-object
 * elements. That element makes the query's key one longer than its own path key, so a mutation's
 * invalidation entry could never match it with `exact: true` — prefix invalidation would still
 * work, but the exact form the invalidation list exists to offer would silently miss.
 *
 * A section that is present but empty is still a supplied section and is kept: `{ query: {} }` is a
 * caller who passed an object, and it stays distinct from a caller who passed nothing.
 */
export function withInput<Key extends readonly unknown[], Input extends object>(
  key: Key,
  input: Input,
): Key | readonly [...Key, Input] {
  return Object.values(input).some((value) => value !== undefined) ? [...key, input] : key;
}
