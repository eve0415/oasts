/**
 * Script-config loading via native dynamic `import()`.
 *
 * TypeScript configs rely on Node's built-in type stripping — no jiti/tsx —
 * matching how oxlint/oxfmt load `*.config.ts`. That requires Node >= 24
 * (already the package engine floor), so the version gate exists only to turn
 * an obscure `ERR_UNKNOWN_FILE_EXTENSION` into an actionable message. The
 * import URL carries a cache-busting query so editing the config between
 * in-process runs (tests, future watch) is never served a stale module.
 */

import { pathToFileURL } from "node:url";

import {
  CODE_CONFIG_EVALUATION,
  CODE_CONFIG_NOT_SERIALIZABLE,
  type CliFailure,
  configFailure,
} from "../diagnostics.ts";
import { findSerializabilityViolation } from "./serializable.ts";

const MINIMUM_NODE_MAJOR = 24;

let importCounter = 0;

function isThenable(value: object): boolean {
  let current: object | null = value;
  while (current !== null) {
    const descriptor = Object.getOwnPropertyDescriptor(current, "then");
    if (descriptor !== undefined) {
      return typeof descriptor.value === "function";
    }
    current = Reflect.getPrototypeOf(current);
  }
  return false;
}

function evaluationFailure(configPath: string, message: string): CliFailure {
  return configFailure(CODE_CONFIG_EVALUATION, message, configPath);
}

/**
 * Evaluates a script config and returns its default export as JSON text.
 *
 * Throws `CliFailure` (exit 2) for import errors, a missing/function/thenable
 * default export, or a non-JSON-serializable export.
 */
export async function loadScriptConfig(
  configPath: string,
  nodeVersion: string = process.versions.node,
): Promise<string> {
  const major = Number.parseInt(nodeVersion, 10);
  if (Number.isNaN(major) || major < MINIMUM_NODE_MAJOR) {
    throw evaluationFailure(
      configPath,
      `TypeScript/JavaScript config requires Node >= ${MINIMUM_NODE_MAJOR} (running ${nodeVersion}); upgrade Node or use oasts.yaml`,
    );
  }

  importCounter += 1;
  const url = `${pathToFileURL(configPath).href}?oasts-cache-bust=${importCounter}`;
  let module: unknown;
  try {
    module = await import(url);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw evaluationFailure(configPath, `failed to import config module: ${message}`);
  }

  if (typeof module !== "object" || module === null || !("default" in module)) {
    throw evaluationFailure(configPath, "config module has no default export");
  }
  const exported: unknown = module.default;
  if (typeof exported === "function") {
    throw evaluationFailure(
      configPath,
      "config default export is a function; export the config object itself",
    );
  }
  if (typeof exported !== "object" || exported === null) {
    throw evaluationFailure(configPath, "config default export must be an object");
  }
  if (isThenable(exported)) {
    throw evaluationFailure(
      configPath,
      "config default export is a promise; export one synchronous object",
    );
  }

  const violation = findSerializabilityViolation(exported);
  if (violation !== null) {
    throw configFailure(
      CODE_CONFIG_NOT_SERIALIZABLE,
      `config export is not JSON-serializable: ${violation.reason} at ${violation.path}`,
      configPath,
    );
  }
  return JSON.stringify(exported);
}
