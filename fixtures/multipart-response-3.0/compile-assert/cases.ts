import type { GetBundleResult } from "../generated/client/operations/getbundle.js";
import type { GetMixedMediaResult } from "../generated/client/operations/getmixedmedia.js";
import type { GetSnippetContentResult } from "../generated/client/operations/getsnippetcontent.js";
import type { GetBundleResponse200 } from "../generated/types/operations/getbundle.js";
import type { Manifest } from "../generated/types/components/manifest.js";

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

type Ok<Result, Outcome> = Extract<Result, { outcome: Outcome; ok: true }>;

// One declared property per part shape. Binary is the only kind that overrides its schema type;
// `format: byte` stays the base64 string the wire carries, and an unconstrained part stays unknown.
type AssertBundleShape = Expect<
  Equal<
    Ok<GetBundleResult, 200>["data"],
    {
      manifest: Manifest;
      readme: string;
      archive: Uint8Array;
      thumbnails?: Uint8Array[];
      labels?: string[];
      encoded?: string;
      extra?: unknown;
    }
  >
>;

// `additionalProperties: false` leaves the object closed, so no index signature is emitted even
// though the decoder still keeps an undeclared part.
type AssertBundleIsClosed = Expect<Equal<keyof Ok<GetBundleResult, 200>["data"] & string, keyof {
  manifest: 0;
  readme: 0;
  archive: 0;
  thumbnails: 0;
  labels: 0;
  encoded: 0;
  extra: 0;
}>>;

// The published open-ended shape: no declared property, every part admitted by
// `additionalProperties`, whose array-of-binary schema decodes to `Uint8Array[]`.
type AssertSnippetContentIsIndexed = Expect<
  Equal<Ok<GetSnippetContentResult, 200>["data"], { [key: string]: Uint8Array[] }>
>;

// A multipart entry sharing a status with a JSON entry narrows on `contentType` like any other
// media, and each arm carries its own entry's type.
type AssertMultipartArmNarrows = Expect<
  Equal<
    Extract<GetMixedMediaResult, { contentType: "multipart/form-data" }>["data"],
    { manifest?: Manifest; archive?: Uint8Array; [key: string]: unknown }
  >
>;
type AssertJsonArmKeepsItsSchema = Expect<
  Equal<Extract<GetMixedMediaResult, { contentType: "application/json" }>["data"], Manifest>
>;

// The types artifact does not render the decoded object — the same split a multipart *request* body
// already takes, where the types artifact says `unknown` and the client owns the real shape.
type AssertTypesArtifactStaysOpaque = Expect<Equal<GetBundleResponse200, unknown>>;

export type {
  AssertBundleShape,
  AssertBundleIsClosed,
  AssertSnippetContentIsIndexed,
  AssertMultipartArmNarrows,
  AssertJsonArmKeepsItsSchema,
  AssertTypesArtifactStaysOpaque,
};
