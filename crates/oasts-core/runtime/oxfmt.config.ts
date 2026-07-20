import { defineConfig } from "oxfmt";

export default defineConfig({
  // The runtime source modules embed spec-frozen declaration blocks whose byte
  // layout the spec owns; formatting would rewrite those bytes. Test files stay
  // formatted — oracle values live in literals, which formatting never alters.
  ignorePatterns: [
    "node_modules/**",
    "result.ts",
    "serialize.ts",
    "standard-schema.ts",
    "transport.ts",
  ],
});
