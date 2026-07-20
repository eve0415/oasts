// Generated Accept header construction vectors gating the client conformance gate for the oasts
// client artifact. NEVER regenerate these from implementation output — expected values are
// derived from the frozen contract : "The generated `Accept` is constructed deterministically:
// the normalized, deduplicated union of every declared response media range across the
// operation's exact, range, and `default` response entries — concrete types in lexical order,
// then `type/*` ranges, then `*/*`, with no quality weights. When no response entry declares
// content, no `Accept` header is emitted."
//
// This vector file PINS the join bytes as the frozen exact-header fixture: entries are joined
// with ", " — a single comma followed by a single space — because the frozen contract does not spell
// out the join delimiter itself; ", " is the conventional HTTP list-value separator (RFC 9110
// RFC 9110 §5.6.1's `#`-rule uses OWS "," OWS between members, and ", " is its canonical rendering) and
// is the byte sequence this fixture commits the implementation to.
//
// `declaredMedia` inputs are given in an arbitrary, non-normalized, duplicate-containing
// document order on purpose — the whole point of these vectors is to prove the algorithm
// sorts, tiers, and deduplicates regardless of input order, never simply echoing declaration
// order. Every input string is already canonical (parameter-free, lowercase — canonicalization
// itself is a separate concern covered by vectors-media.ts and the frozen contract) so these vectors
// isolate exactly the ordering/tiering/dedup/join algorithm the frozen contract defines.

export type AcceptVector = {
  readonly cite: string;
  readonly description: string;
  /** Canonical media types/ranges declared across the operation's response entries, in an arbitrary (non-normalized) order. */
  readonly declaredMedia: readonly string[];
  readonly expected: string | null;
};

export const ACCEPT_VECTORS: readonly AcceptVector[] = [
  {
    cite: "frozen contract",
    description:
      "Concrete types only, declared out of lexical order: sorted lexically (application/json < application/xml < text/plain).",
    declaredMedia: ["application/xml", "application/json", "text/plain"],
    expected: "application/json, application/xml, text/plain",
  },
  {
    cite: "frozen contract",
    description:
      "Mixed concrete + type/* ranges + */*, declared out of tier order: one concrete type, " +
      "two type/* ranges (lexically ordered among themselves: image/* < text/*), then */* last.",
    declaredMedia: ["*/*", "text/*", "application/json", "image/*"],
    expected: "application/json, image/*, text/*, */*",
  },
  {
    cite: "frozen contract",
    description:
      "Duplicates across response entries (e.g. the same media type declared on both a 200 " +
      "and a 404 branch, and */* declared on both a range and the default branch) are " +
      "deduplicated across every tier before joining.",
    declaredMedia: ["application/json", "application/json", "text/plain", "*/*", "*/*"],
    expected: "application/json, text/plain, */*",
  },
  {
    cite: "frozen contract",
    description:
      "No response entry anywhere declares a content map: no Accept header is emitted at all.",
    declaredMedia: [],
    expected: null,
  },
];
