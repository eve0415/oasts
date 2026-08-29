/**
 * Node-owned diagnostics for the script-config path.
 *
 * These cover only what the Rust core cannot see: evaluating the config
 * module (OASTS0012), validating its export is plain JSON data (OASTS0013),
 * a native call that failed without a structured reason (OASTS1022), a
 * native module load failure (OASTS1023), and a directory `oasts watch`
 * cannot watch (OASTS1031, the same code the standalone binary reports).
 * `render()` covers a single Node-owned diagnostic at a time — every call site
 * here passes exactly one. It never sorts (Rust's `render_to_string` always
 * does) and never prints a line/col (this `Diagnostic` carries none, so the
 * location line is always `sourceId:1:1`). Everything else renders in Rust
 * and passes through verbatim.
 */

/** Config module evaluation failed (import error, missing/async/non-object default). */
export const CODE_CONFIG_EVALUATION = "OASTS0012";
/** Config default export is not plain JSON-serializable data. */
export const CODE_CONFIG_NOT_SERIALIZABLE = "OASTS0013";
/** A native call failed without giving back a structured reason. */
export const CODE_NATIVE_INVOCATION = "OASTS1022";
/** The native module could not be loaded by this Node host. */
export const CODE_NATIVE_LOAD = "OASTS1023";
/** A directory `oasts watch` was told to watch could not be watched. */
export const CODE_WATCH_IO = "OASTS1031";

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
    return configFailure(CODE_NATIVE_INVOCATION, `native invocation failed: ${error.message}`);
  }
  return configFailure(CODE_NATIVE_INVOCATION, `native invocation failed: ${String(error)}`);
}

/** Wraps a native module load failure in the shared diagnostic and exit-code contract. */
export function fromNativeLoadError(error: unknown): CliFailure {
  const message = error instanceof Error ? error.message : String(error);
  return configFailure(CODE_NATIVE_LOAD, `native module load failed: ${message}`);
}
