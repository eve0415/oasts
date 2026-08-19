import type { APIRoute } from "astro";
import { env } from "cloudflare:workers";

/**
 * Serves historical compiler builds out of R2.
 *
 * The version shipped with this deploy is a static asset, and Cloudflare serves assets before the
 * request ever reaches the Worker — so this route runs only for versions the current build does
 * not carry.
 *
 * There is deliberately no Cache API use here: the edge cache is zone-level and does nothing on a
 * workers.dev subdomain, so calling it would be a no-op dressed up as an optimisation. The
 * immutable response headers still let each visitor's browser keep a version after first use, and
 * moving the site to a custom domain would add edge caching on top without changing this code.
 */

export const prerender = false;

const IMMUTABLE = "public, max-age=31536000, immutable";

/** Short-lived: the archive manifest is the one object a release rewrites. */
const MANIFEST = "public, max-age=300";

const contentTypeFor = (key: string): string => {
	if (key.endsWith(".wasm")) return "application/wasm";
	if (key.endsWith(".json")) return "application/json";
	return "application/octet-stream";
};

export const GET: APIRoute = async ({ params }) => {
	const key = params.path;
	if (key === undefined || key === "" || key.includes("..")) {
		return new Response("Not found", { status: 404 });
	}

	const object = await env.PLAYGROUND_WASM.get(key);
	if (object === null) {
		return new Response("Not found", { status: 404 });
	}

	return new Response(object.body, {
		headers: {
			"content-type": contentTypeFor(key),
			"cache-control": key.endsWith("versions.json") ? MANIFEST : IMMUTABLE,
			etag: object.httpEtag,
		},
	});
};
