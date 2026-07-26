// Typechecked after the emitter generates the sibling `../generated` tree.

import type { CompleteUploadRequest as CompleteUploadRequestComponent } from "../generated/types/components/completeuploadrequest.js";
import type { CompleteUploadResponse200 as CompleteUploadResponse200Component } from "../generated/types/components/completeuploadresponse200.js";
import type {
  CompleteUploadRequest,
  CompleteUploadResponse200,
} from "../generated/types/operations/completeupload.js";

// The component and the operation envelope carry the same exported name from different modules.
// These pin which one each reference site resolves to: a regression that let the local declaration
// shadow the import would retype `body` to the envelope itself, which still compiles.
export function bodyNamesTheComponent(
  component: CompleteUploadRequestComponent,
): CompleteUploadRequest["body"] {
  return component;
}

export function bodyIsNotTheEnvelope(
  envelope: CompleteUploadRequest,
): CompleteUploadRequest["body"] {
  // @ts-expect-error the request body is the component payload, never the request envelope.
  return envelope;
}

export function responseNamesTheComponent(
  component: CompleteUploadResponse200Component,
): CompleteUploadResponse200 {
  return component;
}
