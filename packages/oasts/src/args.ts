/**
 * Argument parsing for the Node CLI, mirroring the Rust CLI's command
 * surface plus the Node-only flags (`--spec`, `--locked`).
 */

import { ok } from "node:assert";
import { parseArgs } from "node:util";

/** A parsed invocation ready for dispatch. */
export interface ParsedArgs {
  command: "generate" | "check" | "watch";
  config?: string;
  check: boolean;
  specs: string[];
  locked: boolean;
}

/** A usage error; rendered to stderr with exit code 2. */
export class ArgsError extends Error {}

export const USAGE = `Usage: oasts <command> [options]

Commands:
  generate           Generate configured artifacts
  check              Validate configuration and input without emitting
  watch              (unsupported in this build)

Options:
  --config <path>    Use an explicit configuration file
  --check            With generate: check committed output without writing
  --spec <name>      Select a workspace spec (workspace configs are
                     unsupported in this build; selecting one fails)
  --locked           Accepted for CI parity; a no-op without a remote input
`;

function parseRaw(argv: readonly string[]) {
  try {
    return parseArgs({
      args: [...argv],
      allowPositionals: true,
      options: {
        config: { type: "string" },
        check: { type: "boolean" },
        spec: { type: "string", multiple: true },
        locked: { type: "boolean" },
      },
    });
  } catch (error) {
    ok(error instanceof Error);
    throw new ArgsError(error.message);
  }
}

/** Parses CLI arguments (without the node/script prefix). */
export function parse(argv: readonly string[]): ParsedArgs {
  const parsed = parseRaw(argv);

  const [command, ...extra] = parsed.positionals;
  if (command === undefined) {
    throw new ArgsError("missing command");
  }
  if (command !== "generate" && command !== "check" && command !== "watch") {
    throw new ArgsError(`unknown command '${command}'`);
  }
  if (extra.length > 0) {
    throw new ArgsError(`unexpected argument '${extra[0]}'`);
  }
  const check = parsed.values.check === true;
  if (check && command !== "generate") {
    throw new ArgsError("--check is only valid with the generate command");
  }

  const config = parsed.values.config;
  const specValues = parsed.values.spec;
  const result: ParsedArgs = {
    command,
    check,
    specs: specValues === undefined ? [] : [...specValues],
    locked: parsed.values.locked === true,
  };
  if (typeof config === "string") {
    result.config = config;
  }
  return result;
}
