import { defineConfig } from "oxlint";

export default defineConfig({
  options: {
    // typeAware runs the type-informed lint rules; typeCheck additionally
    // surfaces tsc-style type errors, making oxlint the sole TS type gate
    // (no separate tsc/tsgo pass). Both require oxlint-tsgolint and must be
    // set in the root config (non-root typeAware silently no-ops:
    // oxc-project/oxc#19937).
    typeAware: true,
    typeCheck: true,
    denyWarnings: true,
  },
  categories: {
    correctness: "error",
    suspicious: "error",
  },
  overrides: [
    {
      // node:test's test() returns a promise the runner already tracks;
      // awaiting every registration is pure noise in test files.
      files: ["test/**", "test-e2e/**"],
      rules: {
        "typescript/no-floating-promises": "off",
        // The serializability suite constructs thenables and sparse arrays
        // on purpose -- they are the inputs under test.
        "unicorn/no-thenable": "off",
        "no-sparse-arrays": "off",
      },
    },
  ],
  ignorePatterns: ["node_modules/**", "napi/**"],
});
