import { defineConfig } from "tsdown";

// Two builds sharing dist/: the public entry bundles generated config.ts and
// needs .d.ts (users' oasts.config.ts imports defineConfig/UserConfig from
// it); the executable entry bundles the shebanged bin wrapper plus the napi
// loader, whose createRequire-based platform require() calls must stay
// runtime-dynamic. dts stays off for the cli entry because the root tsconfig
// does not include src/.
//
// fixedExtension defaults to true for platform: "node" (tsdown 0.22.9),
// which emits .mjs/.d.mts regardless of package.json's "type": "module".
// Disabled here so output matches plain .js/.d.ts -- package.json already
// pins "type": "module", so .js is unambiguously ESM.
//
// copy on the cli entry places the platform .node binary next to dist/cli.js
// as a dev/e2e-local bridge -- the napi loader resolves it relative to
// itself at runtime. It never ships: the package.json "files" allowlist
// negates "dist/*.node" out of the published tarball.
const shared = { platform: "node", minify: true, fixedExtension: false } as const;

export default defineConfig([
  { entry: { index: "./config.ts" }, ...shared, dts: true },
  { entry: { cli: "./bin/oasts.ts" }, ...shared, dts: false, copy: "napi/*.node" },
]);
