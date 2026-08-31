// Proves a freshly built napi binding dlopens on the platform that built it and provides
// every function its own generated declarations promise.
//
// Four of the release's eight targets can run on no runner GitHub offers; these are the
// four it can prove before publishing, so loading the binary at all is the point.
//
// The names come from the `index.d.ts` napi emits beside the binary rather than being
// written down here. Both fall out of one `napi build`, so on its own the name assertion
// is close to a tautology; what the derivation buys is that a function the crate stops
// exporting cannot leave a stale name behind to fail a release, which is the failure
// this replaces.
import { createRequire } from "node:module";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const napi = process.argv[2]
  ? resolve(process.argv[2])
  : resolve(dirname(fileURLToPath(import.meta.url)), "../packages/oasts/napi");

const binaries = readdirSync(napi).filter((name) => /^oasts\..+\.node$/.test(name));
if (binaries.length !== 1) {
  throw new Error(`expected one built binding in ${napi}, found ${binaries.length}`);
}

const declarations = readFileSync(join(napi, "index.d.ts"), "utf8");
const expected = [...declarations.matchAll(/^export declare function (\w+)/gm)].map(
  ([, name]) => name,
);
// A declaration file that parses to nothing would make every assertion below vacuously
// true, so the empty case is the failure it looks like rather than a pass.
if (expected.length === 0) {
  throw new Error(`${join(napi, "index.d.ts")} declares no functions`);
}

// require() reads a bare path as a package name, so the binary is resolved to an absolute
// one first — which is also what makes this work under Git Bash, where the shell's idea of
// the path and node's do not agree.
const binding = createRequire(import.meta.url)(join(napi, binaries[0]));

// One direction only: the binding may carry more than the declarations name, and a napi
// enum or class arriving later must not be read as a regression.
const missing = expected.filter((name) => typeof binding[name] !== "function");
if (missing.length > 0) {
  throw new Error(`${binaries[0]} is missing ${missing.join(", ")}`);
}

console.log(`${binaries[0]} loaded, ${expected.length} declared functions present:`);
console.log(`  ${expected.join(", ")}`);
