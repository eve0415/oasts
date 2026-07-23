// Typechecked after the emitter generates the sibling `../generated` tree.

import { createTransport } from "../generated/runtime/transport.js";

export function relativeServerRequiresTransportBaseUrl(): void {
  // @ts-expect-error a relative server URL requires an absolute runtime resolution base.
  createTransport({});
  createTransport({ baseUrl: "https://example.test/root/" });
}
