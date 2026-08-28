import { defineConfig } from "astro/config";
import type { AstroIntegration } from "astro";
import tailwindcss from "@tailwindcss/vite";
import nimbus, { defineConfig as defineNimbusConfig } from "@cloudflare/nimbus-docs";
import { tableScroll } from "@cloudflare/nimbus-docs/markdown";
import react from "@astrojs/react";
import cloudflare from "@astrojs/cloudflare";

const nimbusConfig = defineNimbusConfig({
  site: "https://oasts.eve0415.workers.dev",
  title: "oasts",
  description:
    "Compile OpenAPI 3.0/3.1 into TypeScript types and a zero-dependency typed client.",
  locale: "en",
  github: "https://github.com/eve0415/oasts",
  // `{path}` arrives relative to the Astro root, and this site is a
  // subdirectory of the repo.
  editPattern: "https://github.com/eve0415/oasts/edit/main/www/{path}",
  socialImageAlt: "oasts documentation",
});

// Sourcemaps for the Worker bundle only. `upload_source_maps` sends them to
// Cloudflare so exceptions in the observability logs resolve to TypeScript
// instead of minified chunk offsets. The client build stays map-free — those
// would ship to readers and map nothing anyone can act on.
const serverSourcemaps: AstroIntegration = {
  name: "server-sourcemaps",
  hooks: {
    "astro:build:setup": ({ target, updateConfig }) => {
      if (target === "server") {
        updateConfig({ build: { sourcemap: true } });
      }
    },
  },
};

export default defineConfig({
  output: "static",
  // nimbus reads content collections and git from disk, and the OG generator drives
  // canvaskit; none of that survives workerd, so prerendering stays in node.
  adapter: cloudflare({ prerenderEnvironment: "node" }),
  // Nothing here keeps server state — the playground carries its own in the URL — and
  // leaving sessions on makes the adapter demand a KV namespace that does not exist.
  session: false,
  // Tailwind v4 via its Vite plugin (the integration Astro recommends for
  // Tailwind v4 — replaces the PostCSS plugin, which doesn't build under
  // Astro 7's Vite 8 bundler).
  vite: {
    plugins: [tailwindcss()],
  },
  // Hover-prefetch link targets so full-page navigations feel instant without
  // a client-side router.
  prefetch: {
    prefetchAll: true,
    defaultStrategy: "hover",
  },
  integrations: [
    serverSourcemaps,
    // The playground still hand-rolls useCallback/useMemo where referential
    // identity is functionally required (effect deps, worker lifecycle) —
    // React Compiler covers the remaining render-perf memoization on top of that.
    // Only the playground island is React; every docs page still ships zero React.
    react({ babel: { plugins: ["babel-plugin-react-compiler"] } }),
    nimbus(nimbusConfig, {
      // Authoring rules are opt-in by design — your repo, your taste. The
      // two below are the load-bearing pair: frontmatter has to validate
      // against the content schema for the page to render properly, and
      // broken internal links are 404s for your readers. Add the others
      // (heading hierarchy, code-block language, style, etc.) when you're
      // ready to enforce them — see `nimbus-docs lint --help`.
      rules: {
        "nimbus/frontmatter-shape": "error",
        "nimbus/internal-link": "error",
      },
      // Wrap wide tables so they scroll instead of overflowing the page
      // (styled by `.nb-table-scroll` in src/styles/prose.css).
      markdown: {
        hastPlugins: [tableScroll()],
      },
    }),
  ],
});
