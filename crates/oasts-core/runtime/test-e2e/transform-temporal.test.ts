/// <reference lib="esnext.temporal" preserve="true" />
// The two Temporal representations, driven end to end through a generated client. Same consumption
// strategy as transform.test.ts; what is specific here is that both modes depend on a global Node
// only exposes under --harmony-temporal.
//
// So each contract is asserted on the side that is reachable in the run that is happening: the
// named `temporal-unavailable` failure is forced with `withoutTemporal` and therefore checked in
// every run, and the round-trip identities run only where the global is real. scripts/coverage-ts.sh
// runs flagged, which is where the second half executes.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { constants } from "node:fs";
import { access, cp, mkdtemp, rm } from "node:fs/promises";
import { register } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { pathToFileURL } from "node:url";

import {
  createScriptedServer,
  requiredFunction,
  requiredRecord,
  type ExportedFunction,
} from "./harness.ts";

const repoRoot = path.resolve(import.meta.dirname, "../../../..");
const binary = path.join(repoRoot, "target/debug/oasts");
const fixtureSource = path.join(repoRoot, "fixtures/transform-showcase-3.1");

const temporalAvailable = typeof globalThis.Temporal !== "undefined";

// Hides the global for one call, so the missing-Temporal contract is reachable in a flagged run too.
async function withoutTemporal<T>(body: () => Promise<T>): Promise<T> {
  const saved = Object.getOwnPropertyDescriptor(globalThis, "Temporal");
  Object.defineProperty(globalThis, "Temporal", { value: undefined, configurable: true });
  try {
    return await body();
  } finally {
    if (saved === undefined) {
      Reflect.deleteProperty(globalThis, "Temporal");
    } else {
      Object.defineProperty(globalThis, "Temporal", saved);
    }
  }
}

// The showcase's one request-transform-free operation, loaded across the dynamic-import boundary.
async function load(root: string): Promise<ExportedFunction> {
  const module: unknown = await import(
    pathToFileURL(path.join(root, "client/operations/getlatestevent.ts")).href
  );
  return requiredFunction(module, "getLatestEvent");
}

const harness = createScriptedServer();
const { routes, requests, scriptRoute } = harness;

let baseUrl: string;
let temporaryRoot: string;
let createTransport: ExportedFunction;
let instantLatest: ExportedFunction;
let plainDateLatest: ExportedFunction;

before(async () => {
  await access(binary, constants.X_OK);
  temporaryRoot = await mkdtemp(path.join(tmpdir(), "oasts-transform-temporal-e2e-"));
  const fixtureRoot = path.join(temporaryRoot, "transform-showcase-3.1");
  await cp(fixtureSource, fixtureRoot, { recursive: true });
  for (const config of ["oasts-temporal.yaml", "oasts-plaindate.yaml"]) {
    execFileSync(binary, ["generate", "--config", config], { cwd: fixtureRoot, stdio: "pipe" });
  }
  const instantRoot = path.join(fixtureRoot, "generated-temporal");
  const plainDateRoot = path.join(fixtureRoot, "generated-plaindate");
  // One registration covering both trees. The hook keeps a single root in module scope, so
  // registering it twice would leave only the second tree's specifiers rewritten; the fixture root
  // is the nearest prefix that contains both.
  register(new URL("./resolve-generated.mjs", import.meta.url), {
    data: { generatedRootUrl: pathToFileURL(fixtureRoot).href },
  });
  instantLatest = await load(instantRoot);
  plainDateLatest = await load(plainDateRoot);
  const transportModule: unknown = await import(
    pathToFileURL(path.join(instantRoot, "runtime/transport.ts")).href
  );
  createTransport = requiredFunction(transportModule, "createTransport");
  baseUrl = await harness.start();
});

beforeEach(() => {
  routes.clear();
  requests.length = 0;
});

after(async () => {
  await harness.stop();
  await rm(temporaryRoot, { recursive: true, force: true });
});

const WIRE_INSTANT = "2024-03-01T12:00:00.123456789Z";
const WIRE_DAY = "2024-03-01";

function scriptLatest(body: string): void {
  scriptRoute("GET", "/events/latest", {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from(body),
  });
}

test("a Temporal mode without the global fails by name, not by throwing", async () => {
  scriptLatest(`{"id":"e1","occurredAt":"${WIRE_INSTANT}"}`);

  const result = await withoutTemporal(async () => {
    const transport = createTransport({ baseUrl });
    return requiredRecord(await instantLatest(transport, {}), "getLatestEvent result");
  });

  assert.equal(result.outcome, "response-transform");
  const error = requiredRecord(result.error, "transform error");
  assert.equal(error.code, "temporal-unavailable");
  assert.equal(error.direction, "response");
});

test(
  "dateTime: temporal decodes to an Instant at epoch-nanosecond identity",
  { skip: temporalAvailable ? false : "needs --harmony-temporal" },
  async () => {
    scriptLatest(`{"id":"e1","occurredAt":"${WIRE_INSTANT}"}`);

    const transport = createTransport({ baseUrl });
    const result = requiredRecord(await instantLatest(transport, {}), "getLatestEvent result");

    assert.equal(result.outcome, 200);
    const data = requiredRecord(result.data, "getLatestEvent data");
    const occurredAt = data.occurredAt;
    assert.ok(
      occurredAt instanceof globalThis.Temporal.Instant,
      "occurredAt should decode to a Temporal.Instant",
    );
    assert.ok(
      occurredAt.equals(globalThis.Temporal.Instant.from(WIRE_INSTANT)),
      "the decoded instant should carry every declared nanosecond",
    );
  },
);

test(
  "date: temporal decodes to an ISO-calendar PlainDate",
  { skip: temporalAvailable ? false : "needs --harmony-temporal" },
  async () => {
    scriptLatest(`{"id":"e1","occurredAt":"2024-03-01T12:00:00Z","retiredOn":"${WIRE_DAY}"}`);

    const transport = createTransport({ baseUrl });
    const result = requiredRecord(await plainDateLatest(transport, {}), "getLatestEvent result");

    assert.equal(result.outcome, 200);
    const data = requiredRecord(result.data, "getLatestEvent data");
    const retiredOn = data.retiredOn;
    assert.ok(
      retiredOn instanceof globalThis.Temporal.PlainDate,
      "retiredOn should decode to a Temporal.PlainDate",
    );
    assert.ok(retiredOn.equals(globalThis.Temporal.PlainDate.from(WIRE_DAY)));
    // The ISO calendar is asserted through what the value serializes to rather than through a
    // calendar accessor: the proposal renamed that accessor mid-flight (`calendar` object →
    // `calendarId` string) and engines ship both, while a non-ISO calendar is observable either
    // way as a `[u-ca=…]` annotation the canonical form must not carry.
    assert.equal(retiredOn.toString(), WIRE_DAY);
    // The date-time property is untouched in this mode: only `format: date` converts.
    assert.equal(data.occurredAt, "2024-03-01T12:00:00Z");
  },
);
