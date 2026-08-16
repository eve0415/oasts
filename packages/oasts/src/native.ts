/**
 * Deferred import point for the napi binding. Keeping the import inside the
 * CLI run lets its error boundary convert load failures into exit code 2;
 * Node's module cache still gives every invocation one loaded module.
 */

export type { DiagnosticJs, DiscoveredConfigJs, RunOptions, RunResult } from "../napi/index.js";

import { fromNativeLoadError } from "./diagnostics.ts";

type NativeModule = typeof import("../napi/index.js");

/** Loads the napi binding without letting a raw module error escape the CLI. */
export async function loadNative(): Promise<NativeModule> {
  try {
    return await import("../napi/index.js");
  } catch (error) {
    throw fromNativeLoadError(error);
  }
}
