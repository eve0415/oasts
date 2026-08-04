/**
 * Node-owned diagnostics for the script-config path.
 *
 * These cover only what the Rust core cannot see: evaluating the config
 * module (OASTS0013), validating its export is plain JSON data (OASTS0014),
 * and a native call that failed without a structured reason (OASTS0001).
 * Rendering matches `oasts_core::diag::render` so both hosts produce one
 * stderr dialect. Everything else renders in Rust and passes through verbatim.
 */

/** Config module evaluation failed (import error, missing/async/non-object default). */
export const CODE_CONFIG_EVALUATION = "OASTS0013";
/** Config default export is not plain JSON-serializable data. */
export const CODE_CONFIG_NOT_SERIALIZABLE = "OASTS0014";

/** A Node-side diagnostic in the shared cross-host shape. */
export interface Diagnostic {
  code: string;
  severity: "error" | "warning";
  message: string;
  sourceId?: string;
}

/** Renders diagnostics in the core's `severity[CODE]: message` format. */
export function render(diagnostics: readonly Diagnostic[]): string {
  let rendered = "";
  for (const diagnostic of diagnostics) {
    rendered += `${diagnostic.severity}[${diagnostic.code}]: ${diagnostic.message}\n`;
    if (diagnostic.sourceId !== undefined) {
      rendered += `  --> ${diagnostic.sourceId}:1:1\n`;
    }
  }
  return rendered;
}

/** A failure that already knows its process exit code and stderr text. */
export class CliFailure extends Error {
  readonly exitCode: number;
  readonly renderedStderr: string;

  constructor(exitCode: number, renderedStderr: string) {
    super(renderedStderr);
    this.exitCode = exitCode;
    this.renderedStderr = renderedStderr;
  }
}

/** Builds a `CliFailure` with exit code 2 from one config diagnostic. */
export function configFailure(code: string, message: string, sourceId?: string): CliFailure {
  const diagnostic: Diagnostic =
    sourceId === undefined
      ? { code, severity: "error", message }
      : { code, severity: "error", message, sourceId };
  return new CliFailure(2, render([diagnostic]));
}

/**
 * Parses the JSON reason the napi binding attaches to thrown errors
 * (`{ exitCode, renderedStderr, ... }`) into a `CliFailure`.
 */
export function fromNativeError(error: unknown): CliFailure {
  if (error instanceof Error) {
    try {
      const payload: unknown = JSON.parse(error.message);
      if (
        typeof payload === "object" &&
        payload !== null &&
        "exitCode" in payload &&
        typeof payload.exitCode === "number" &&
        "renderedStderr" in payload &&
        typeof payload.renderedStderr === "string"
      ) {
        return new CliFailure(payload.exitCode, payload.renderedStderr);
      }
    } catch {
      // Not a structured reason; fall through to the generic wrapper.
    }
    return configFailure("OASTS0001", `native invocation failed: ${error.message}`);
  }
  return configFailure("OASTS0001", `native invocation failed: ${String(error)}`);
}
