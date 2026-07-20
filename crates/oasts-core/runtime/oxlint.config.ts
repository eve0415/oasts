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
      files: ["*.ts", "test/**"],
      rules: {
        "typescript/no-floating-promises": "off",
        // Test data intentionally mirrors public declaration snapshots.
        "typescript/no-namespace": "off",
        // Frozen error fields require an explicit literal annotation on real classes.
        "typescript/prefer-as-const": "off",
      },
    },
  ],
  ignorePatterns: ["node_modules/**"],
});
