import { defineConfig } from "oxfmt";

export default defineConfig({
  // npm/** is regenerated wholesale by `napi create-npm-dirs`.
  ignorePatterns: ["node_modules/**", "napi/**", "dist/**", "npm/**"],
});
