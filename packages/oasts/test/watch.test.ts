import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, sep } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { loadNative } from "../src/native.ts";
import type { RunOptions, RunResult } from "../src/native.ts";
import {
  type Changes,
  type Cycle,
  FsChanges,
  type Wake,
  Watched,
  type WatchNative,
  type WatchPlan,
  compileOnce,
  session,
  watchFailure,
} from "../src/watch.ts";

const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "../../../fixtures/petstore-3.0");

const CONFIG =
  "schemaVersion: 1\ninput:\n  path: ./spec/openapi.yaml\noutput: ./generated\nartifacts:\n  types: true\nwatch:\n  debounceMs: 10\n";

function plan(inputs: readonly string[], outputRoot: string | null, debounceMs = 5): WatchPlan {
  return planWithRoots(inputs, [], outputRoot, debounceMs);
}

function planWithRoots(
  files: readonly string[],
  directories: readonly string[],
  outputRoot: string | null,
  debounceMs = 5,
): WatchPlan {
  return {
    inputs: [
      ...files.map((path) => ({ path, directory: false })),
      ...directories.map((path) => ({ path, directory: true })),
    ],
    outputRoot,
    debounceMs,
  };
}

/** Whether the plan reports `path`, whatever kind it was recorded as. */
function hasInput(plan: WatchPlan, path: string): boolean {
  return plan.inputs.some((input) => input.path === path);
}

function cycle(exitCode: number, watchPlan: WatchPlan | null): Cycle {
  return { exitCode, stdout: "", stderr: "", plan: watchPlan };
}

/** A change source that replays exactly the sequence a test wants to see. */
class Scripted implements Changes {
  readonly registered: string[][] = [];
  closed = false;
  /** Returned once the script runs out, for a test that needs a source with no end. */
  repeat: Wake | null = null;
  #wakes: Wake[];
  #refuse: unknown;

  constructor(wakes: readonly Wake[], refuse: unknown = null) {
    this.#wakes = [...wakes];
    this.#refuse = refuse;
  }

  watch(directories: readonly string[]): void {
    this.registered.push([...directories]);
    if (this.#refuse !== null) {
      throw this.#refuse;
    }
  }

  wake(_quietMs: number | null): Promise<Wake> {
    return Promise.resolve(this.#wakes.shift() ?? this.repeat ?? { kind: "stopped" });
  }

  close(): void {
    this.closed = true;
  }
}

test("a watch set replaces on success and only widens on failure", () => {
  const root = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  mkdirSync(join(root, "spec"));
  const watched = new Watched();
  watched.absorb(plan([join(root, "a.yaml")], join(root, "out")), true);
  assert.deepEqual(watched.directories(), [root]);

  watched.absorb(plan([join(root, "spec/b.yaml")], null), false);
  assert.deepEqual(watched.directories(), [root, join(root, "spec")].toSorted());
  assert.ok(watched.triggers(join(root, "a.yaml")));

  watched.absorb(plan([join(root, "spec/b.yaml")], join(root, "out")), true);
  assert.deepEqual(watched.directories(), [join(root, "spec")]);
  assert.ok(!watched.triggers(join(root, "a.yaml")));
});

test("a session registers the workspace root itself", () => {
  // The guard the input set cannot give: a directory input reported as the workspace root is in
  // that set and trivially starts with itself, so a bound stated over inputs says nothing about
  // what gets registered. Taking the parent of a directory input is what reached the directory the
  // project sits in — `$HOME`, a monorepo root, the temp dir below.
  const root = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  mkdirSync(join(root, "spec"));
  const watched = new Watched();
  watched.absorb(
    planWithRoots([join(root, "oasts.yaml"), join(root, "spec/openapi.yaml")], [root], null),
    true,
  );

  const directories = watched.directories();
  assert.deepEqual(directories, [root, join(root, "spec")].toSorted());
  assert.ok(
    directories.every((path) => path === root || path.startsWith(root + sep)),
    `nothing above the workspace root may be registered: ${directories.join(", ")}`,
  );
});

test("a trust root that does not exist yet registers the nearest ancestor", () => {
  // The case the recording exists for. The root cannot be watched because it is not there, so the
  // walk falls back to the directory that will contain it — where its appearance is an event.
  const root = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  const watched = new Watched();
  watched.absorb(planWithRoots([], [join(root, "not-yet")], null), true);
  assert.deepEqual(watched.directories(), [root]);
});

test("an input under a directory that does not exist yet watches the nearest one that does", () => {
  const root = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  const watched = new Watched();
  watched.absorb(plan([join(root, "missing/deeper/api.yaml")], null), true);
  assert.deepEqual(watched.directories(), [root]);
});

test("an input whose whole chain is missing falls back to the root", () => {
  const watched = new Watched();
  watched.absorb(plan([join(sep, "oasts-nowhere-at-all", "api.yaml")], null), true);
  assert.deepEqual(watched.directories(), [sep]);
});

test("only inputs trigger once a compile has settled", () => {
  const watched = new Watched();
  watched.absorb(plan(["/w/oasts.yaml", "/w/out/tsconfig.json"], "/w/out"), true);
  assert.ok(watched.triggers("/w/oasts.yaml"));
  assert.ok(watched.triggers("/w/out/tsconfig.json"));
  assert.ok(!watched.triggers("/w/out/types/index.ts"));
  assert.ok(!watched.triggers("/w/out"));
  assert.ok(!watched.triggers("/w/unrelated.txt"));

  watched.absorb(plan(["/w/oasts.yaml"], "/w/out"), false);
  assert.ok(watched.triggers("/w/unrelated.txt"));
  assert.ok(!watched.triggers("/w/out/types/index.ts"));
});

test("an output root with a trailing separator still contains its own writes", () => {
  const watched = new Watched();
  watched.absorb(plan(["/w/oasts.yaml"], "/w/out/"), true);
  assert.ok(!watched.triggers("/w/out/types/index.ts"));
});

test("a session recompiles per change and exits zero when the source stops", async () => {
  const changes = new Scripted([
    { kind: "quiet" },
    { kind: "changed", path: "/w/unrelated.txt" },
    { kind: "changed", path: "/w/oasts.yaml" },
    { kind: "changed", path: "/w/oasts.yaml" },
    { kind: "quiet" },
    { kind: "changed", path: "/w/oasts.yaml" },
    { kind: "stopped" },
  ]);
  let compiles = 0;
  const reported: number[] = [];
  const code = await session(
    changes,
    () => {
      compiles += 1;
      return Promise.resolve(cycle(compiles === 2 ? 1 : 0, plan(["/w/oasts.yaml"], "/w/out")));
    },
    (finished) => {
      reported.push(finished.exitCode);
      return finished.exitCode;
    },
  );
  assert.equal(code, 2, "a watcher that stopped is not a clean exit");
  assert.equal(compiles, 2);
  assert.deepEqual(reported, [0, 1, 2]);
  assert.ok(changes.closed);
});

test("churn the filter rejects does not hold a compile back", async () => {
  const changes = new Scripted([
    { kind: "changed", path: "/w/oasts.yaml" },
    // Everything after this is the output tree being written by somebody else. None of it would
    // start a compile, so none of it may postpone one.
    { kind: "changed", path: "/w/out/types/a.ts" },
    { kind: "changed", path: "/w/out/types/b.ts" },
    { kind: "quiet" },
    { kind: "stopped" },
  ]);
  let compiles = 0;
  const code = await session(
    changes,
    () => {
      compiles += 1;
      return Promise.resolve(cycle(0, plan(["/w/oasts.yaml"], "/w/out")));
    },
    (finished) => finished.exitCode,
  );
  assert.equal(code, 2);
  assert.equal(compiles, 2);
});

test("unending churn delays a compile but never cancels it", async () => {
  const changes = new Scripted([]);
  // Every wake is a real change, so the settling window is refreshed forever and only the cap can
  // end the wait.
  changes.repeat = { kind: "changed", path: "/w/oasts.yaml" };
  let compiles = 0;
  const started = Date.now();
  const code = await session(
    changes,
    () => {
      compiles += 1;
      if (compiles === 2) {
        changes.repeat = null;
      }
      return Promise.resolve(cycle(0, plan(["/w/oasts.yaml"], "/w/out", 50)));
    },
    (finished) => finished.exitCode,
  );
  assert.equal(code, 2);
  assert.equal(compiles, 2, "the cap did not end a wait that never went quiet");
  assert.ok(Date.now() - started >= 500, "the cap ended the wait far too early");
});

test("a session that cannot register a watch reports it and exits two", async () => {
  const changes = new Scripted([], new Error("/w: permission denied"));
  const reported: string[] = [];
  const code = await session(
    changes,
    () => Promise.resolve(cycle(0, plan(["/w/oasts.yaml"], null))),
    (finished) => {
      reported.push(finished.stderr);
      return finished.exitCode;
    },
  );
  assert.equal(code, 2);
  assert.match(
    reported[1] ?? "",
    /error\[OASTS1031\]: failed to watch for changes: \/w: permission/,
  );
  assert.ok(changes.closed);
});

test("a first cycle with nothing to watch says so rather than waiting", async () => {
  const changes = new Scripted([]);
  let reported = "";
  const code = await session(
    changes,
    () => Promise.resolve(cycle(0, null)),
    (finished) => {
      reported = finished.stderr;
      return finished.exitCode;
    },
  );
  assert.equal(code, 2);
  assert.match(reported, /error\[OASTS1031\]: .*reported no inputs to watch/);
  assert.equal(changes.registered.length, 0);
});

test("a session survives a cycle that reported no plan", async () => {
  const root = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  const config = join(root, "oasts.yaml");
  const changes = new Scripted([{ kind: "changed", path: config }, { kind: "quiet" }]);
  let compiles = 0;
  const code = await session(
    changes,
    () => {
      compiles += 1;
      return Promise.resolve(compiles === 1 ? cycle(0, plan([config], "/w/out")) : cycle(2, null));
    },
    (finished) => finished.exitCode,
  );
  assert.equal(code, 2);
  assert.deepEqual(changes.registered[1], [root]);
});

test("a session reports a watch refusal that was not an Error", async () => {
  const changes = new Scripted([], "not an error object");
  let reported = "";
  const code = await session(
    changes,
    () => Promise.resolve(cycle(0, plan(["/w/oasts.yaml"], null))),
    (finished) => {
      reported = finished.stderr;
      return finished.exitCode;
    },
  );
  assert.equal(code, 2);
  assert.match(reported, /error\[OASTS1031\]: failed to watch for changes: not an error object/);
});

test("a watch failure renders as one config diagnostic", () => {
  const failure = watchFailure("no reason object");
  assert.equal(failure.exitCode, 2);
  assert.match(failure.stderr, /OASTS1031/);
});

test("the real watcher reports writes, drops directories, and stops on close", async () => {
  const directory = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  const other = join(directory, "other");
  mkdirSync(other);
  const changes = new FsChanges();

  changes.watch([directory, other]);
  assert.deepEqual(await changes.wake(20), { kind: "quiet" });

  // An event that arrives while nothing is waiting is queued rather than dropped.
  writeFileSync(join(directory, "touched.txt"), "a");
  await new Promise((resolve) => setTimeout(resolve, 50));
  const queued = await changes.wake(null);
  assert.equal(queued.kind, "changed");

  // Re-registering without `other` closes its watcher; writing there is no longer reported.
  changes.watch([directory]);
  writeFileSync(join(other, "ignored.txt"), "b");
  writeFileSync(join(directory, "touched.txt"), "c");
  const reported: string[] = [];
  for (;;) {
    const wake = await changes.wake(200);
    if (wake.kind !== "changed") {
      break;
    }
    reported.push(wake.path);
  }
  assert.ok(
    reported.every((path) => !path.includes("ignored.txt")),
    reported.join(", "),
  );

  const pending = changes.wake(null);
  changes.close();
  assert.deepEqual(await pending, { kind: "stopped" });
  assert.deepEqual(await changes.wake(null), { kind: "stopped" });
});

test("a desynchronized watcher recompiles without a path to blame", async () => {
  const changes = new Scripted([
    { kind: "desynchronized" },
    { kind: "desynchronized" },
    { kind: "quiet" },
    { kind: "stopped" },
  ]);
  let compiles = 0;
  const code = await session(
    changes,
    () => {
      compiles += 1;
      return Promise.resolve(cycle(0, plan(["/w/oasts.yaml"], "/w/out")));
    },
    (finished) => finished.exitCode,
  );
  assert.equal(code, 2);
  assert.equal(compiles, 2);
});

test("a watcher that fails after it was opened is dropped and reported as a lost event", async () => {
  const opened: Array<{ directory: string; fail: (() => void) | null; closed: boolean }> = [];
  const changes = new FsChanges((directory) => {
    const entry = { directory, fail: null as (() => void) | null, closed: false };
    opened.push(entry);
    return {
      on(_event: "error", listener: (error: unknown) => void) {
        entry.fail = () => {
          listener(new Error("watcher died"));
        };
        return undefined;
      },
      close() {
        entry.closed = true;
      },
    };
  });

  const directory = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  changes.watch([directory]);
  assert.equal(opened.length, 1);
  opened[0]?.fail?.();
  assert.deepEqual(await changes.wake(null), { kind: "desynchronized" });
  assert.equal(opened[0]?.closed, true);

  // The directory is no longer watched, so the next registration reopens it.
  changes.watch([directory]);
  assert.equal(opened.length, 2);
  changes.close();
});

test("a watched directory that is replaced is registered again", async () => {
  const root = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  const watched = join(root, "spec");
  mkdirSync(watched);
  const changes = new FsChanges();
  try {
    changes.watch([watched]);

    // What the platform reports when the directory a watch is bound to goes away.
    rmSync(watched, { recursive: true });
    mkdirSync(watched);
    const woke: string[] = [];
    for (;;) {
      const wake = await changes.wake(200);
      if (wake.kind === "quiet" || wake.kind === "stopped") {
        break;
      }
      woke.push(wake.kind);
    }
    assert.ok(woke.includes("desynchronized"), woke.join(", "));

    // The registration is gone, so the next one reopens the directory that is there now.
    changes.watch([watched]);
    writeFileSync(join(watched, "api.yaml"), "openapi: 3.1.0\n");
    assert.equal((await changes.wake(5000)).kind, "changed");
  } finally {
    changes.close();
  }
});

test("the real watcher refuses a directory that is not there", () => {
  const directory = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  const changes = new FsChanges();
  assert.throws(() => changes.watch([join(directory, "missing")]));
  changes.close();
});

function watchFixture(): string {
  const directory = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  mkdirSync(join(directory, "spec"));
  copyFileSync(join(FIXTURE, "openapi.yaml"), join(directory, "spec/openapi.yaml"));
  writeFileSync(
    join(directory, "oasts.yaml"),
    "schemaVersion: 1\ninput:\n  path: ./spec/openapi.yaml\noutput: ./generated\nartifacts:\n  types: true\nwatch:\n  debounceMs: 10\n",
  );
  return directory;
}

test("one cycle compiles, reports its plan, and never throws", async () => {
  const native = await loadNative();
  const directory = watchFixture();

  const compiled = await compileOnce(native, { specs: [] }, directory);
  assert.equal(compiled.exitCode, 0, compiled.stderr);
  assert.match(compiled.stdout, /^generated \d+ files\n$/);
  assert.ok(compiled.plan !== null);
  assert.ok(hasInput(compiled.plan, join(directory, "oasts.yaml")));
  assert.ok(hasInput(compiled.plan, join(directory, "spec/openapi.yaml")));
  // Discovery runs on this side, so the names it would also have accepted are added here.
  assert.ok(hasInput(compiled.plan, join(directory, "oasts.json")));
  assert.ok(hasInput(compiled.plan, join(directory, "oasts.config.ts")));
  assert.equal(compiled.plan.outputRoot, join(directory, "generated"));
  assert.equal(compiled.plan.debounceMs, 10);

  // An explicit config path narrows what discovery would have considered to that one file.
  const explicit = await compileOnce(native, { config: "oasts.yaml", specs: [] }, directory);
  assert.equal(explicit.exitCode, 0, explicit.stderr);
  assert.ok(explicit.plan !== null);
  assert.ok(!hasInput(explicit.plan, join(directory, "oasts.json")));

  // A script config is re-evaluated on this side before the compiler sees anything.
  const scripted = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  copyFileSync(join(FIXTURE, "openapi.yaml"), join(scripted, "openapi.yaml"));
  writeFileSync(
    join(scripted, "oasts.config.ts"),
    'export default { schemaVersion: 1, input: { path: "./openapi.yaml" }, output: "./generated" };\n',
  );
  const fromScript = await compileOnce(native, { specs: [] }, scripted);
  assert.equal(fromScript.exitCode, 0, fromScript.stderr);
});

test("a cycle that never reaches a config still says what to watch", async () => {
  const native = await loadNative();
  const empty = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  const failed = await compileOnce(native, { specs: [] }, empty);
  assert.equal(failed.exitCode, 2);
  assert.match(failed.stderr, /error\[OASTS0011\]/);
  assert.equal(failed.plan?.inputs.length, 8);
  assert.equal(failed.plan?.outputRoot, null);

  // A config the compiler refuses outright is reported the same way.
  const broken = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  writeFileSync(join(broken, "oasts.config.ts"), "export default Promise.resolve({});\n");
  const refused = await compileOnce(native, { specs: [] }, broken);
  assert.equal(refused.exitCode, 2);
  assert.match(refused.stderr, /error\[OASTS0012\]/);
  assert.equal(refused.plan?.inputs.length, 8);

  // A config that parses and then fails validation names no output tree to stay out of.
  const invalid = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  writeFileSync(join(invalid, "oasts.yaml"), "schemaVersion: 2\n");
  const rejected = await compileOnce(native, { specs: [] }, invalid);
  assert.equal(rejected.exitCode, 2);
  assert.equal(rejected.plan?.outputRoot, null);
  assert.ok(rejected.plan !== null);
  assert.ok(hasInput(rejected.plan, join(invalid, "oasts.yaml")));
});

test("a cycle whose compiler reports nothing falls back to the discovery candidates", async () => {
  const directory = watchFixture();
  const stub: WatchNative = {
    discoveryCandidates: () => [join(directory, "oasts.yaml")],
    discoverConfig: () => ({ path: join(directory, "oasts.yaml"), isScript: false }),
    run: (_options: RunOptions): RunResult => ({
      exitCode: 0,
      renderedStderr: "",
      diagnostics: [],
    }),
    watchDefaults: () => ({ debounceMs: 100 }),
  };
  const compiled = await compileOnce(stub, { specs: [] }, directory);
  assert.deepEqual(compiled.plan?.inputs, [
    { path: join(directory, "oasts.yaml"), directory: false },
  ]);
  assert.equal(compiled.plan?.debounceMs, 100);
  assert.equal(compiled.stdout, "");
});

/** Announces each watch registration, so an edit never races the session that must see it. */
class Armed implements Changes {
  #inner = new FsChanges();
  #armed: (() => void) | null = null;

  watch(directories: readonly string[]): void {
    this.#inner.watch(directories);
    this.#armed?.();
    this.#armed = null;
  }

  wake(quietMs: number | null): Promise<Wake> {
    return this.#inner.wake(quietMs);
  }

  close(): void {
    this.#inner.close();
  }

  registered(): Promise<void> {
    return new Promise((resolve) => {
      this.#armed = resolve;
    });
  }
}

/**
 * Every operation answers with the same `$ref`, so the referenced file is reached from the entry
 * rather than sitting beside it unread.
 */
function document(operations: readonly string[], reference = "../shared/components.yaml"): string {
  let text = "openapi: 3.1.0\ninfo: {title: watch, version: 1.0.0}\npaths:\n";
  for (const operation of operations) {
    text += `  /${operation}:\n    get:\n      operationId: ${operation}\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema: {$ref: '${reference}#/Thing'}\n`;
  }
  return text;
}

function component(properties: readonly string[]): string {
  let text = "Thing:\n  type: object\n  properties:\n";
  for (const property of properties) {
    text += `    ${property}: {type: string}\n`;
  }
  return text;
}

/** A tree whose referenced document lives in a directory of its own. */
function sessionFixture(): string {
  const directory = mkdtempSync(join(tmpdir(), "oasts-watch-"));
  mkdirSync(join(directory, "spec"));
  mkdirSync(join(directory, "shared"));
  writeFileSync(join(directory, "shared/components.yaml"), component(["id"]));
  writeFileSync(join(directory, "spec/openapi.yaml"), document(["listThings"]));
  writeFileSync(join(directory, "base.json"), '{ "compilerOptions": { "lib": ["ES2022"] } }');
  writeFileSync(join(directory, "tsconfig.json"), '{ "extends": "./base.json" }');
  writeFileSync(join(directory, "oasts.yaml"), CONFIG);
  return directory;
}

test("a real session recompiles after a document, a config, and an extends change", async () => {
  const native = await loadNative();
  const directory = sessionFixture();

  const changes = new Armed();
  const cycles: number[] = [];
  const finished = session(
    changes,
    () => compileOnce(native, { specs: [] }, directory),
    (compiled) => {
      cycles.push(compiled.exitCode);
      return compiled.exitCode;
    },
  );

  await changes.registered();
  const emitted = join(directory, "generated/types/operations/listthings.ts");
  assert.ok(existsSync(emitted), "the first compile wrote nothing");

  // 1. The entry document, in its own directory.
  let ready = changes.registered();
  writeFileSync(join(directory, "spec/openapi.yaml"), document(["listThings", "listOthers"]));
  await ready;
  assert.ok(
    existsSync(join(directory, "generated/types/operations/listothers.ts")),
    "the recompile did not emit the new operation",
  );

  // 2. The configuration file itself, reloaded rather than restarted.
  ready = changes.registered();
  writeFileSync(join(directory, "oasts.yaml"), `${CONFIG}namespace: Watched\n`);
  await ready;

  // 3. A file the tsconfig `extends` chain reaches.
  ready = changes.registered();
  writeFileSync(join(directory, "base.json"), '{ "compilerOptions": { "lib": ["ESNext"] } }');
  await ready;

  changes.close();
  // Closing the source ends the session the only way it can end: saying it can no longer answer.
  assert.equal(await finished, 2);
  assert.deepEqual(cycles, [0, 0, 0, 0, 2]);
});

/**
 * The ordinary authoring order for a reference that does not resolve yet.
 *
 * Retarget a `$ref` at a directory nobody has created, make the directory, then write the file. A
 * session that only reported the documents a *successful* load returned would have dropped every
 * `$ref`-reached path the moment the load failed, leaving the directory holding them unwatched and
 * the session unable to see either step.
 */
test("a real session sees a ref target appear after the load that wanted it failed", async () => {
  const native = await loadNative();
  const directory = sessionFixture();
  const changes = new Armed();
  const cycles: number[] = [];
  const finished = session(
    changes,
    () => compileOnce(native, { specs: [] }, directory),
    (compiled) => {
      cycles.push(compiled.exitCode);
      return compiled.exitCode;
    },
  );

  try {
    await changes.registered();

    // 1. Point the reference at a directory that is not there.
    let ready = changes.registered();
    writeFileSync(
      join(directory, "spec/openapi.yaml"),
      document(["listThings"], "../later/components.yaml"),
    );
    await ready;
    assert.notEqual(cycles.at(-1), 0, "an unresolvable reference should report, not pass");

    // 2. Create the directory. The compile still fails, and the session must be watching the new
    //    directory afterwards rather than only the one it used to read.
    ready = changes.registered();
    mkdirSync(join(directory, "later"));
    await ready;
    assert.notEqual(cycles.at(-1), 0, "the directory alone does not resolve the reference");

    // 3. Write the file the reference names.
    ready = changes.registered();
    writeFileSync(join(directory, "later/components.yaml"), component(["id"]));
    await ready;
    assert.equal(cycles.at(-1), 0, "the session did not see the file that fixes the reference");
  } finally {
    changes.close();
    await finished;
  }
});
