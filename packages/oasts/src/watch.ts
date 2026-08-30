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
 * A session never ends on its own over a diagnostic. Those are reported and the loop continues,
 * because a typo in a document is the ordinary case a watch exists for. It ends only where it can
 * no longer promise freshness: a compile that reported nothing to watch, a directory it could not
 * register, and a watcher that stopped reporting underneath it. All three report `OASTS1031`.
 */

import { statSync, watch as watchDirectory } from "node:fs";
import { basename, dirname, join, sep } from "node:path";

import { loadScriptConfig } from "./config/load.ts";
import { CliFailure, CODE_WATCH_IO, configFailure, fromNativeError } from "./diagnostics.ts";
import type { DiscoveredConfigJs, RunOptions, RunResult } from "./native.ts";

/** One path a compile depended on, and how a session should watch it. */
export interface WatchInput {
  path: string;
  /**
   * Whether the path names a directory, which is registered as itself rather than through its
   * parent. Decided by the compile that recorded it, never by asking the filesystem.
   */
  directory: boolean;
}

/** What one compile left behind for the next wait. */
export interface WatchPlan {
  inputs: readonly WatchInput[];
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
  /** Events were lost and the watcher cannot say which. Everything it was watching is suspect. */
  | { readonly kind: "desynchronized" }
  | { readonly kind: "quiet" }
  | { readonly kind: "stopped" };

/** The part of a directory watcher this module uses. */
export interface Watcher {
  on(event: "error", listener: (error: unknown) => void): unknown;
  close(): void;
}

/** Opens one non-recursive directory watcher, or throws if it cannot. */
export type OpenWatcher = (
  directory: string,
  listener: (event: string, filename: string | null) => void,
) => Watcher;

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

/**
 * The real filesystem, through one non-recursive watcher per directory.
 *
 * `open` exists because a watcher that fails *after* it was created reports through an event, and
 * an event no test can raise is a recovery path no test can check.
 */
export class FsChanges implements Changes {
  #open: OpenWatcher;
  #watchers = new Map<string, Watcher>();
  #pending: Wake[] = [];
  #waiting: ((wake: Wake) => void) | null = null;
  #stopped = false;

  constructor(open: OpenWatcher = watchDirectory) {
    this.#open = open;
  }

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
      const own = basename(directory);
      const watcher = this.#open(directory, (_event, filename) => {
        // An event naming the watched directory itself, rather than something in it, is that
        // directory being replaced -- and a watch is bound to the directory that existed when it
        // was registered, so it goes deaf the moment a new one takes the name. It arrives here as
        // the directory's own name, or as no name at all. A file inside that happens to share the
        // name costs one extra compile and one extra registration, which is the safe way to be
        // wrong.
        if (filename === null || filename === "" || filename === own) {
          this.forget(directory);
          return;
        }
        this.#deliver({ kind: "changed", path: join(directory, filename) });
      });
      watcher.on("error", () => {
        this.forget(directory);
      });
      this.#watchers.set(directory, watcher);
    }
  }

  /**
   * Drops a watcher that can no longer be trusted, and tells the session to recompile blind.
   *
   * Whatever that watcher missed is unknowable, and the next `watch` reopens the directory — or
   * throws, which ends the session rather than leaving it watching nothing.
   */
  forget(directory: string): void {
    this.#watchers.get(directory)?.close();
    this.#watchers.delete(directory);
    this.#deliver({ kind: "desynchronized" });
  }

  wake(quietMs: number | null): Promise<Wake> {
    if (this.#stopped) {
      return Promise.resolve({ kind: "stopped" });
    }
    const next = this.#pending.shift();
    if (next !== undefined) {
      return Promise.resolve(next);
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

  #deliver(wake: Wake): void {
    const waiting = this.#waiting;
    if (waiting === null) {
      this.#pending.push(wake);
      return;
    }
    waiting(wake);
  }
}

/** The paths a session is watching, and the tree it must ignore its own writes in. */
export class Watched {
  #inputs = new Map<string, boolean>();
  #outputRoot: string | null = null;
  #settled = false;

  absorb(plan: WatchPlan, settled: boolean): void {
    if (settled) {
      this.#inputs = new Map(plan.inputs.map((input) => [input.path, input.directory]));
    } else {
      // Never narrow on failure: a run that stopped at a broken document read less than the one
      // before it, and dropping the rest would strand the session.
      for (const input of plan.inputs) {
        this.#inputs.set(input.path, input.directory);
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
   * A file is watched through the directory holding it, because that is what survives an editor's
   * save-and-rename. A directory input — the workspace root, a `local.allowPaths` entry — is
   * watched as *itself*: taking its parent would register the directory the project sits in, which
   * is `$HOME` or a monorepo root, and reach far outside what the compile read.
   *
   * An input whose own directory is not there yet — a document the config names and nobody has
   * created, or a trust root still to appear — falls back to the nearest ancestor that is, so
   * creating it is still noticed.
   */
  directories(): string[] {
    const directories = new Set<string>();
    for (const [path, isDirectory] of this.#inputs) {
      directories.add(nearestExistingDirectory(isDirectory ? path : dirname(path)));
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

/**
 * Every input from both sides, one entry per path.
 *
 * A path either side calls a directory stays a directory: that is the wider registration and it
 * cannot be wrong, and it matches how the compiler deduplicates the same collision.
 */
function mergeInputs(
  left: readonly WatchInput[],
  right: readonly WatchInput[],
): readonly WatchInput[] {
  const merged = new Map<string, boolean>();
  for (const input of [...left, ...right]) {
    merged.set(input.path, (merged.get(input.path) ?? false) || input.directory);
  }
  return [...merged].map(([path, directory]) => ({ path, directory }));
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
 * How long a settling burst may hold a compile back before it runs anyway.
 *
 * Coalescing waits for quiet, and a directory somebody else is writing into never goes quiet — a
 * bundler or test runner emitting into the output tree would otherwise hold a recompile off for as
 * long as it kept going. Churn may delay a compile; it may not cancel one.
 */
const MAX_SETTLE_MS = 1000;

/**
 * Waits until something worth recompiling for has changed and the tree has gone quiet again.
 *
 * Coalescing is what makes one save one compile: a single editor write is several events, and an
 * edit landing while a compile runs queues behind it rather than starting a second one. Only
 * events that would themselves have started a compile keep the wait open — an event the filter
 * already rejected cannot postpone the compile it is not part of.
 */
async function waitForChange(
  watched: Watched,
  changes: Changes,
  quietMs: number,
  capMs: number,
): Promise<boolean> {
  for (;;) {
    const wake = await changes.wake(null);
    if (wake.kind === "stopped") {
      return false;
    }
    if (wake.kind === "quiet" || (wake.kind === "changed" && !watched.triggers(wake.path))) {
      continue;
    }
    const capped = Date.now() + capMs;
    let settled = Date.now() + quietMs;
    for (;;) {
      const remaining = Math.min(settled, capped) - Date.now();
      if (remaining <= 0) {
        return true;
      }
      const settling = await changes.wake(remaining);
      if (settling.kind === "quiet") {
        return true;
      }
      if (settling.kind === "stopped") {
        return false;
      }
      if (settling.kind === "desynchronized" || watched.triggers(settling.path)) {
        settled = Date.now() + quietMs;
      }
    }
  }
}

/** The failure a session ends on: a directory it was told to watch and could not. */
export function watchFailure(reason: string): Cycle {
  const failure = configFailure(CODE_WATCH_IO, `failed to watch for changes: ${reason}`);
  return { exitCode: failure.exitCode, stdout: "", stderr: failure.renderedStderr, plan: null };
}

const EMPTY_PLAN: WatchPlan = { inputs: [], outputRoot: null, debounceMs: 0 };

/** Runs one watch session, compiling through `compile` and rendering through `report`. */
export async function session(
  changes: Changes,
  compile: () => Promise<Cycle>,
  report: (cycle: Cycle) => number,
): Promise<number> {
  const watched = new Watched();
  for (;;) {
    const cycle = await compile();
    // Only a tracked run reports a plan, and every cycle asks for one — so the default here stands
    // for a caller that asked for no plan at all.
    const plan = cycle.plan ?? EMPTY_PLAN;
    watched.absorb(plan, cycle.exitCode === 0);
    report(cycle);

    const directories = watched.directories();
    // Nothing to watch is not a session: no event could ever arrive, so waiting would be a process
    // that looks alive and answers for nothing.
    if (directories.length === 0) {
      changes.close();
      return report(watchFailure("the compile reported no inputs to watch"));
    }
    try {
      changes.watch(directories);
    } catch (error) {
      changes.close();
      return report(watchFailure(error instanceof Error ? error.message : String(error)));
    }
    if (!(await waitForChange(watched, changes, plan.debounceMs, MAX_SETTLE_MS))) {
      // Not a clean end: nothing in the product asks a session to stop, so a source that has
      // stopped reporting is a watcher that died under it. Exiting 0 there would say the run was
      // fine and leave whoever asked for a watch with no watch and no reason.
      changes.close();
      return report(watchFailure("the filesystem watcher stopped reporting changes"));
    }
  }
}

/** The compiler surface one watch cycle drives. */
export interface WatchNative {
  discoveryCandidates(cwd: string, explicitPath?: string | null): string[];
  discoverConfig(cwd: string, explicitPath?: string | null): DiscoveredConfigJs;
  run(options: RunOptions): RunResult;
  /** Asked for rather than copied, so this side cannot disagree with what the compiler applies. */
  watchDefaults(): { debounceMs: number };
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
  // Discovery happens on this side, so the compiler is handed a config path it never had to look
  // for and cannot report the names it would have accepted instead. They belong in every plan, not
  // only the ones where discovery failed: a second `oasts.*` appearing is what turns a working run
  // into a discovery error, and its removal is what turns one back.
  // Config names are files, whatever else the compile went on to report.
  const candidates: readonly WatchInput[] = native
    .discoveryCandidates(cwd, explicit)
    .map((path) => ({ path, directory: false }));
  const fallback: WatchPlan = {
    inputs: candidates,
    outputRoot: null,
    debounceMs: native.watchDefaults().debounceMs,
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
              inputs: mergeInputs(candidates, plan.inputs),
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
