// Compile-time assertions for the server-variable literal-union `serverVariables` property.
//
// The server declares `version` (enum: v1, v2) and `region` (no enum). The generated
// TransportConfig narrows serverVariables from `Readonly<Record<string, string>>` to a
// per-variable object type: an enum'd name becomes a literal union, a name without an enum stays
// a plain string, and every property is optional because every server variable has a default.
//
// Typechecked after the emitter generates the sibling `../generated` tree.

import { createTransport } from "../generated/runtime/transport.js";
import type { DocumentAuthProviders } from "../generated/client/auth.js";

// A declared enum member typechecks.
export function enumMemberTypechecks(): void {
  createTransport({ serverVariables: { version: "v2" } });
}

// The document declares one oauth2 scheme (docOauth) with scopes read/write. Its generated
// DocumentAuthProviders property narrows AuthContext.scopes to the declared union, so a provider
// implementation reads a typed scope array rather than `readonly string[]`.
export function scopedProviderNarrowsScopes(): void {
  const providers: DocumentAuthProviders = {
    docOauth: (context) => {
      const scopes: readonly ("read" | "write")[] = context.scopes;
      void scopes;
      return "token";
    },
  };
  void providers;
}

// A provider keyed by a scheme name the document does not declare is rejected: the interface has a
// property only per client-usable scheme.
export function undeclaredSchemeRejected(): void {
  const providers: DocumentAuthProviders = {
    docOauth: () => "token",
    // @ts-expect-error 'ghost' is not a DocumentAuthProviders member.
    ghost: () => "token",
  };
  void providers;
}

// A value outside the declared enum is rejected.
export function enumNonMemberRejected(): void {
  // @ts-expect-error version is a "v1" | "v2" literal union; "v9" is not a member.
  createTransport({ serverVariables: { version: "v9" } });
}

// region has no enum, so it stays a plain string: any string value typechecks.
export function plainVariableTypechecks(): void {
  createTransport({ serverVariables: { region: "anything" } });
}
