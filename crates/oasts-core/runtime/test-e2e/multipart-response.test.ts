// Drives the generated multipart-response client against a real node:http server, so the bytes a
// server actually writes — preamble, epilogue, per-part Content-Type, repeated names — are what the
// decoder is measured on, not a body this repo's own encoder produced.

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
  requestHeader,
  requiredFunction,
  requiredRecord,
  type ExportedFunction,
} from "./harness.ts";

const repoRoot = path.resolve(import.meta.dirname, "../../../..");
const binary = path.join(repoRoot, "target/debug/oasts");
const fixtureSource = path.join(repoRoot, "fixtures/multipart-response-3.0");
const BOUNDARY = "----server-chosen-boundary";

const harness = createScriptedServer();
const { requests, routes, scriptRoute } = harness;

let baseUrl: string;
let temporaryRoot: string;
let createTransport: ExportedFunction;
let getSnippetContent: ExportedFunction;
let getBundle: ExportedFunction;

type Part = {
  readonly name: string;
  readonly contentType?: string;
  readonly body: string;
  readonly disposition?: string;
};

function multipartBody(
  parts: readonly Part[],
  options: { readonly preamble?: string; readonly epilogue?: string } = {},
): Buffer {
  const chunks: Buffer[] = [];
  if (options.preamble !== undefined) {
    chunks.push(Buffer.from(options.preamble));
  }
  for (const part of parts) {
    const headers = [part.disposition ?? `Content-Disposition: form-data; name="${part.name}"`];
    if (part.contentType !== undefined) {
      headers.push(`Content-Type: ${part.contentType}`);
    }
    chunks.push(Buffer.from(`--${BOUNDARY}\r\n${headers.join("\r\n")}\r\n\r\n${part.body}\r\n`));
  }
  chunks.push(Buffer.from(`--${BOUNDARY}--\r\n`));
  if (options.epilogue !== undefined) {
    chunks.push(Buffer.from(options.epilogue));
  }
  return Buffer.concat(chunks);
}

function scriptMultipart(method: string, url: string, body: Buffer): void {
  scriptRoute(method, url, {
    status: 200,
    headers: [["Content-Type", `multipart/form-data; boundary="${BOUNDARY}"`]],
    body,
  });
}

function decodedText(value: unknown): string {
  assert.ok(value instanceof Uint8Array, "a binary part decodes to Uint8Array");
  return Buffer.from(value).toString("utf8");
}

before(async () => {
  await access(binary, constants.X_OK);
  temporaryRoot = await mkdtemp(path.join(tmpdir(), "oasts-multipart-response-e2e-"));
  const fixtureRoot = path.join(temporaryRoot, "multipart-response-3.0");
  await cp(fixtureSource, fixtureRoot, { recursive: true });
  execFileSync(binary, ["generate", "--config", "oasts.yaml"], {
    cwd: fixtureRoot,
    stdio: "pipe",
  });
  const generatedRoot = path.join(fixtureRoot, "generated");

  register(new URL("./resolve-generated.mjs", import.meta.url), {
    data: { generatedRootUrl: pathToFileURL(generatedRoot).href },
  });
  const snippetModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "client/operations/getsnippetcontent.ts")).href
  );
  const bundleModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "client/operations/getbundle.ts")).href
  );
  const transportModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "runtime/transport.ts")).href
  );
  getSnippetContent = requiredFunction(snippetModule, "getSnippetContent");
  getBundle = requiredFunction(bundleModule, "getBundle");
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

test("decodes a well-formed body into the declared object, part by part", async () => {
  scriptMultipart(
    "GET",
    "/bundle",
    multipartBody([
      { name: "manifest", contentType: "application/json", body: '{"name":"pkg","size":3}' },
      { name: "readme", contentType: "text/plain", body: "read me" },
      { name: "archive", contentType: "application/octet-stream", body: "ARCHIVE-BYTES" },
      { name: "labels", contentType: "text/plain", body: "alpha" },
      { name: "labels", contentType: "text/plain", body: "beta" },
      { name: "encoded", contentType: "text/plain", body: "aGk=" },
      { name: "extra", contentType: "application/json", body: "[1,2,3]" },
    ]),
  );

  const result = requiredRecord(await getBundle(createTransport({ baseUrl }), {}), "bundle result");

  assert.equal(result.outcome, 200);
  assert.equal(result.ok, true);
  const data = requiredRecord(result.data, "bundle data");
  assert.deepEqual(data.manifest, { name: "pkg", size: 3 });
  assert.equal(data.readme, "read me");
  // A binary part is a Uint8Array, not the `type: string` its schema declares.
  assert.equal(decodedText(data.archive), "ARCHIVE-BYTES");
  // A repeated name collects into the array its schema declares, in wire order.
  assert.deepEqual(data.labels, ["alpha", "beta"]);
  // `format: byte` is base64 text on the wire and stays a string.
  assert.equal(data.encoded, "aGk=");
  // An unconstrained property is classified by the part's own Content-Type.
  assert.deepEqual(data.extra, [1, 2, 3]);
  // A declared property with no part is simply absent.
  assert.equal(Object.hasOwn(data, "thumbnails"), false);
  assert.equal(requestHeader(harness.requiredRequest(0), "Accept"), "multipart/form-data");
});

test("keeps a part naming no declared property even when the schema forbids one", async () => {
  scriptMultipart(
    "GET",
    "/bundle",
    multipartBody([
      { name: "readme", contentType: "text/plain", body: "read me" },
      { name: "manifest", contentType: "application/json", body: "{}" },
      { name: "archive", contentType: "application/octet-stream", body: "x" },
      { name: "undeclared", contentType: "text/plain", body: "kept" },
    ]),
  );

  const result = requiredRecord(await getBundle(createTransport({ baseUrl }), {}), "bundle result");
  const data = requiredRecord(result.data, "bundle data");

  assert.equal(data.undeclared, "kept");
});

test("collects repeated names under additionalProperties, tolerating preamble and epilogue", async () => {
  scriptMultipart(
    "GET",
    "/snippets/main/content",
    multipartBody(
      [
        { name: "main.js", contentType: "application/javascript", body: "export default 1;" },
        { name: "lib.js", contentType: "application/javascript", body: "export const a = 2;" },
        { name: "lib.js", contentType: "application/javascript", body: "export const b = 3;" },
      ],
      { preamble: "This is a multi-part message in MIME format.\r\n", epilogue: "ignored\r\n" },
    ),
  );

  const result = requiredRecord(
    await getSnippetContent(createTransport({ baseUrl }), { path: { name: "main" } }),
    "snippet result",
  );

  assert.equal(result.outcome, 200);
  const data = requiredRecord(result.data, "snippet data");
  const main = data["main.js"];
  const lib = data["lib.js"];
  assert.ok(Array.isArray(main));
  assert.ok(Array.isArray(lib));
  // Every name is an array-typed property here, so even a single occurrence is a one-element array.
  assert.equal(main.length, 1);
  assert.equal(decodedText(main[0]), "export default 1;");
  assert.equal(lib.length, 2);
  assert.equal(decodedText(lib[0]), "export const a = 2;");
  assert.equal(decodedText(lib[1]), "export const b = 3;");
});

test("rejects a repeated name whose declared property is not an array", async () => {
  scriptMultipart(
    "GET",
    "/bundle",
    multipartBody([
      { name: "manifest", contentType: "application/json", body: "{}" },
      { name: "archive", contentType: "application/octet-stream", body: "x" },
      { name: "readme", contentType: "text/plain", body: "first" },
      { name: "readme", contentType: "text/plain", body: "second" },
    ]),
  );

  const result = requiredRecord(await getBundle(createTransport({ baseUrl }), {}), "bundle result");

  assert.equal(result.outcome, "response-decode");
  assert.equal(result.ok, false);
  assert.equal(result.status, 200);
});

test("surfaces a malformed body as response-decode rather than a thrown error", async () => {
  scriptMultipart("GET", "/bundle", Buffer.from("--wrong-boundary\r\nnot a part\r\n"));

  const result = requiredRecord(await getBundle(createTransport({ baseUrl }), {}), "bundle result");

  assert.equal(result.outcome, "response-decode");
  assert.equal(result.ok, false);
  assert.match(String(result.message), /response body decoding failed for multipart\/form-data/u);
});

test("fails to decode when the response Content-Type carries no boundary", async () => {
  scriptRoute("GET", "/bundle", {
    status: 200,
    headers: [["Content-Type", "multipart/form-data"]],
    body: multipartBody([{ name: "readme", body: "read me" }]),
  });

  const result = requiredRecord(await getBundle(createTransport({ baseUrl }), {}), "bundle result");

  assert.equal(result.outcome, "response-decode");
  assert.equal(result.ok, false);
});
