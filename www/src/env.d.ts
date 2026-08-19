/**
 * `wrangler types` would declare the bindings, but it emits the whole workerd runtime into the
 * global scope, which replaces the DOM lib the rest of the site is written against. Declaring
 * only the boundary this code touches keeps both halves correctly typed.
 */

/** The subset of R2 the playground archive route uses. */
interface PlaygroundArchive {
	get(key: string): Promise<{ body: ReadableStream; httpEtag: string } | null>;
}

declare module "cloudflare:workers" {
	export const env: { PLAYGROUND_WASM: PlaygroundArchive };
}

declare namespace App {
	interface Locals {
		/**
		 * Per-render counters keyed by component, so two blocks with identical props still get
		 * distinct ids. Lives on locals because it must reset per page and stay stable within a
		 * render — incremental builds have to match cold ones.
		 */
		__nbCounters?: Map<string, number>;
	}
}
