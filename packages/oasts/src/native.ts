/**
 * Single import point for the napi binding so every consumer shares one
 * loaded native module and one typed surface.
 */

export { commandRefusal, discoverConfig, run } from "../napi/index.js";
export type { DiagnosticJs, DiscoveredConfigJs, RunOptions, RunResult } from "../napi/index.js";
