/**
 * In-process CLI entry point.
 *
 * `run` mirrors the Rust CLI's `run_with_io`: it takes argv and a working
 * directory, writes to injectable streams, and returns the process exit code
 * (0 success / 1 input drift or input errors / 2 config, IO, and usage
 * errors) so tests exercise the full CLI without spawning a child process.
 */

import { ArgsError, USAGE, parse } from "./args.ts";
import { loadScriptConfig } from "./config/load.ts";
import { CliFailure, fromNativeError } from "./diagnostics.ts";
import { loadNative } from "./native.ts";
import { compileOnce, FsChanges, session } from "./watch.ts";

/** Byte sinks for CLI output; `process.stdout`/`process.stderr` in the shim. */
export interface OutputStreams {
  write(text: string): void;
}

async function dispatch(
  argv: readonly string[],
  cwd: string,
  stdout: OutputStreams,
  stderr: OutputStreams,
): Promise<number> {
  const args = parse(argv);
  const native = await loadNative();
  if (args.command === "watch") {
    return await session(
      new FsChanges(),
      () => compileOnce(native, args, cwd),
      (cycle) => {
        if (cycle.stderr !== "") {
          stderr.write(cycle.stderr);
        }
        if (cycle.stdout !== "") {
          stdout.write(cycle.stdout);
        }
        return cycle.exitCode;
      },
    );
  }

  const { discoverConfig, run: nativeRun } = native;
  let discovered;
  try {
    discovered = discoverConfig(cwd, args.config ?? null);
  } catch (error) {
    throw fromNativeError(error);
  }

  const configJson = discovered.isScript ? await loadScriptConfig(discovered.path) : null;

  const result = nativeRun({
    cwd,
    configPath: discovered.path,
    ...(configJson === null ? {} : { configJson }),
    command: args.command,
    check: args.check,
    specs: args.specs,
    trackInputs: false,
  });

  if (result.renderedStderr !== "") {
    stderr.write(result.renderedStderr);
  }
  if (result.stdoutSummary !== undefined) {
    stdout.write(`${result.stdoutSummary}\n`);
  }
  return result.exitCode;
}

/** Runs the CLI; never throws — every failure becomes an exit code. */
export async function run(
  argv: readonly string[],
  cwd: string,
  stdout: OutputStreams,
  stderr: OutputStreams,
): Promise<number> {
  try {
    return await dispatch(argv, cwd, stdout, stderr);
  } catch (error) {
    if (error instanceof ArgsError) {
      stderr.write(`error: ${error.message}\n\n${USAGE}`);
      return 2;
    }
    if (error instanceof CliFailure) {
      stderr.write(error.renderedStderr);
      return error.exitCode;
    }
    const message = error instanceof Error ? error.message : String(error);
    stderr.write(`error: ${message}\n`);
    return 2;
  }
}
