/**
 * The `watch` command: compile once, then compile again whenever an input changes.
 *
 * The loop lives here rather than in the compiler because a cycle is more than a compile on this
 * host: a `oasts.config.ts` has to be re-imported and re-evaluated in JavaScript before the core
 * sees anything, and only this side can do that.
 *
 * What gets watched is the *directory* holding each input rather than the input itself. Editors
 * save through a temporary file and rename over the target, which replaces the inode a per-file
 * watch is bound to; a directory watch survives that, and it is also what lets config discovery
 * notice a second `oasts.*` name appearing. Events are filtered against the paths the compile
 * actually read before any of them counts as a change, so the run's own output never wakes it.
 *
 * A session never ends on its own. Diagnostics are reported and the loop continues, because a typo
 * in a document is the ordinary case a watch exists for. The one exception is a directory that
 * cannot be watched at all, which is the only condition under which no promise about freshness can
 * be kept.
 */

import { statSync, watch as watchDirectory } from "node:fs";
import type { FSWatcher } from "node:fs";
import { dirname, join, sep } from "node:path";

import { loadScriptConfig } from "./config/load.ts";
import {
  CliFailure,
  CODE_WATCH_IO,
  type Diagnostic,
  fromNativeError,
  render,
} from "./diagnostics.ts";
import type { DiscoveredConfigJs, RunOptions, RunResult } from "./native.ts";

/** What one compile left behind for the next wait. */
export interface WatchPlan {
  inputs: readonly string[];
  outputRoot: string | null;
  debounceMs: number;
}

/** One compile, rendered and ready to report. */
export interface Cycle {
  exitCode: number;
  stdout: string;
  stderr: string;
  plan: WatchPlan | null;
}

/** What a change source reported. */
export type Wake =
  | { readonly kind: "changed"; readonly path: string }
  | { readonly kind: "quiet" }
  | { readonly kind: "stopped" };

/**
 * Where a session's change notifications come from.
 *
 * The loop is written against this rather than against `node:fs` directly, so its coalescing and
 * filtering can be driven through the exact event sequences a real filesystem only produces by
 * luck — an event during a compile, an event for a file nobody read, a burst from one save.
 */
export interface Changes {
  /** Replaces the watched set; throws when a directory cannot be watched. */
  watch(directories: readonly string[]): void;
  /** Waits for the next event, up to `quietMs` when a deadline is given. */
  wake(quietMs: number | null): Promise<Wake>;
  /** Releases every watcher, so the process can exit. */
  close(): void;
}

/** The real filesystem, through one non-recursive watcher per directory. */
export class FsChanges implements Changes {
  #watchers = new Map<string, FSWatcher>();
  #pending: string[] = [];
  #waiting: ((wake: Wake) => void) | null = null;
  #stopped = false;

  watch(directories: readonly string[]): void {
    const wanted = new Set(directories);
    for (const [directory, watcher] of this.#watchers) {
      if (!wanted.has(directory)) {
        watcher.close();
        this.#watchers.delete(directory);
      }
    }
    for (const directory of wanted) {
      if (this.#watchers.has(directory)) {
        continue;
      }
      const watcher = watchDirectory(directory, (_event, filename) => {
        if (filename !== null) {
          this.#deliver(join(directory, filename));
        }
      });
      this.#watchers.set(directory, watcher);
    }
  }

  wake(quietMs: number | null): Promise<Wake> {
    if (this.#stopped) {
      return Promise.resolve({ kind: "stopped" });
    }
    const next = this.#pending.shift();
    if (next !== undefined) {
      return Promise.resolve({ kind: "changed", path: next });
    }
    return new Promise<Wake>((resolve) => {
      const timer =
        quietMs === null
          ? null
          : setTimeout(() => {
              this.#waiting = null;
              resolve({ kind: "quiet" });
            }, quietMs);
      timer?.unref();
      this.#waiting = (wake) => {
        if (timer !== null) {
          clearTimeout(timer);
        }
        this.#waiting = null;
        resolve(wake);
      };
    });
  }

  close(): void {
    this.#stopped = true;
    for (const watcher of this.#watchers.values()) {
      watcher.close();
    }
    this.#watchers.clear();
    this.#waiting?.({ kind: "stopped" });
  }

  #deliver(path: string): void {
    const waiting = this.#waiting;
    if (waiting === null) {
      this.#pending.push(path);
      return;
    }
    waiting({ kind: "changed", path });
  }
}

/** The paths a session is watching, and the tree it must ignore its own writes in. */
export class Watched {
  #inputs = new Set<string>();
  #outputRoot: string | null = null;
  #settled = false;

  absorb(plan: WatchPlan, settled: boolean): void {
    if (settled) {
      this.#inputs = new Set(plan.inputs);
    } else {
      // Never narrow on failure: a run that stopped at a broken document read less than the one
      // before it, and dropping the rest would strand the session.
      for (const input of plan.inputs) {
        this.#inputs.add(input);
      }
    }
    if (plan.outputRoot !== null) {
      this.#outputRoot = plan.outputRoot;
    }
    this.#settled = settled;
  }

  /**
   * One directory per input, deduplicated and in a stable order.
   *
   * An input whose own directory is not there yet — a document the config names and nobody has
   * created — falls back to the nearest ancestor that is, so creating it is still noticed.
   */
  directories(): string[] {
    const directories = new Set<string>();
    for (const input of this.#inputs) {
      directories.add(nearestExistingDirectory(dirname(input)));
    }
    return [...directories].toSorted();
  }

  /** Whether an event on `path` is worth a recompile. */
  triggers(path: string): boolean {
    if (this.#outputRoot !== null && isInside(path, this.#outputRoot)) {
      // Our own writes land here every successful cycle, so nothing under the output tree counts
      // unless the compile itself read it — which one path does, the `tsconfig.json` the ancestor
      // walk looks for beside the emitted files.
      return this.#inputs.has(path);
    }
    // Anything else while the last compile is broken: the fix may well be a file that run never
    // reached, and one wasted compile is cheaper than a session that cannot recover.
    return this.#inputs.has(path) || !this.#settled;
  }
}

function nearestExistingDirectory(from: string): string {
  let candidate = from;
  while (
    dirname(candidate) !== candidate &&
    statSync(candidate, { throwIfNoEntry: false })?.isDirectory() !== true
  ) {
    candidate = dirname(candidate);
  }
  return candidate;
}

function isInside(path: string, root: string): boolean {
  return path === root || path.startsWith(root.endsWith(sep) ? root : `${root}${sep}`);
}

/**
 * Waits until something worth recompiling for has changed and the tree has gone quiet again.
 *
 * Coalescing is what makes one save one compile: a single editor write is several events, and an
 * edit landing while a compile runs queues behind it rather than starting a second one.
 */
async function waitForChange(
  watched: Watched,
  changes: Changes,
  quietMs: number,
): Promise<boolean> {
  for (;;) {
    const wake = await changes.wake(null);
    if (wake.kind === "stopped") {
      return false;
    }
    if (wake.kind === "quiet" || !watched.triggers(wake.path)) {
      continue;
    }
    for (;;) {
      const settling = await changes.wake(quietMs);
      if (settling.kind === "quiet") {
        return true;
      }
      if (settling.kind === "stopped") {
        return false;
      }
    }
  }
}

/** The failure a session ends on: a directory it was told to watch and could not. */
export function watchFailure(reason: string): Cycle {
  const diagnostic: Diagnostic = {
    code: CODE_WATCH_IO,
    severity: "error",
    message: `failed to watch for changes: ${reason}`,
  };
  return { exitCode: 2, stdout: "", stderr: render([diagnostic]), plan: null };
}

/** The `watch.debounceMs` default, for a cycle that never reached a configuration to read it. */
const DEFAULT_DEBOUNCE_MS = 100;

const EMPTY_PLAN: WatchPlan = { inputs: [], outputRoot: null, debounceMs: DEFAULT_DEBOUNCE_MS };

/** Runs one watch session, compiling through `compile` and rendering through `report`. */
export async function session(
  changes: Changes,
  compile: () => Promise<Cycle>,
  report: (cycle: Cycle) => number,
): Promise<number> {
  const watched = new Watched();
  for (;;) {
    const cycle = await compile();
    // A cycle that reported no plan leaves the previous set in place rather than clearing it,
    // which is what keeps a session alive across a compile that never reached a config.
    const plan = cycle.plan ?? EMPTY_PLAN;
    watched.absorb(plan, cycle.exitCode === 0);
    report(cycle);

    try {
      changes.watch(watched.directories());
    } catch (error) {
      changes.close();
      return report(watchFailure(error instanceof Error ? error.message : String(error)));
    }
    if (!(await waitForChange(watched, changes, plan.debounceMs))) {
      changes.close();
      return 0;
    }
  }
}

/** The compiler surface one watch cycle drives. */
export interface WatchNative {
  discoveryCandidates(cwd: string, explicitPath?: string | null): string[];
  discoverConfig(cwd: string, explicitPath?: string | null): DiscoveredConfigJs;
  run(options: RunOptions): RunResult;
}

/** What the invocation selected, as far as a cycle cares. */
export interface WatchArgs {
  config?: string;
  specs: readonly string[];
}

/**
 * Runs one compile: rediscover, re-evaluate a script config, compile, emit.
 *
 * Everything is redone from scratch each time, which is what makes a config edit take effect
 * without restarting and what keeps a recompile byte-identical to a cold run. A failure anywhere
 * becomes a reported cycle rather than a thrown error, because the session has to survive it.
 */
export async function compileOnce(
  native: WatchNative,
  args: WatchArgs,
  cwd: string,
): Promise<Cycle> {
  const explicit = args.config ?? null;
  // Known even when discovery fails, and the only thing left to watch when it does.
  const fallback: WatchPlan = {
    inputs: native.discoveryCandidates(cwd, explicit),
    outputRoot: null,
    debounceMs: DEFAULT_DEBOUNCE_MS,
  };
  try {
    const discovered = native.discoverConfig(cwd, explicit);
    const configJson = discovered.isScript ? await loadScriptConfig(discovered.path) : null;
    const result = native.run({
      cwd,
      configPath: discovered.path,
      ...(configJson === null ? {} : { configJson }),
      command: "generate",
      check: false,
      specs: [...args.specs],
      trackInputs: true,
    });
    const plan = result.watchPlan;
    return {
      exitCode: result.exitCode,
      stdout: result.stdoutSummary === undefined ? "" : `${result.stdoutSummary}\n`,
      stderr: result.renderedStderr,
      plan:
        plan === undefined
          ? fallback
          : {
              inputs: plan.inputs,
              outputRoot: plan.outputRoot ?? null,
              debounceMs: plan.debounceMs,
            },
    };
  } catch (error) {
    const failure = error instanceof CliFailure ? error : fromNativeError(error);
    return {
      exitCode: failure.exitCode,
      stdout: "",
      stderr: failure.renderedStderr,
      plan: fallback,
    };
  }
}
