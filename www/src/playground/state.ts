import type { PlaygroundState } from "./types";

/**
 * Share links carry the whole playground — document, config and compiler version — in the URL.
 *
 * It goes in the QUERY string rather than the fragment on purpose: a fragment never reaches the
 * server, and the plain-text view of a link has to be renderable without running the page.
 * Compression is `CompressionStream`, which every target runtime ships, so nothing is bundled
 * for it.
 */

export const STATE_PARAM = "s";

const toBase64Url = (bytes: Uint8Array): string => {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
};

const fromBase64Url = (value: string): Uint8Array => {
	const padded = value.replaceAll("-", "+").replaceAll("_", "/");
	const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="));
	return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

const through = async (data: BufferSource, transform: TransformStream): Promise<Uint8Array> => {
	const stream = new Blob([data]).stream().pipeThrough(transform);
	return new Uint8Array(await new Response(stream).arrayBuffer());
};

export const encodeState = async (state: PlaygroundState): Promise<string> => {
	const json = new TextEncoder().encode(JSON.stringify(state));
	return toBase64Url(await through(json, new CompressionStream("deflate-raw")));
};

export const decodeState = async (encoded: string): Promise<PlaygroundState | null> => {
	try {
		const inflated = await through(fromBase64Url(encoded), new DecompressionStream("deflate-raw"));
		const parsed: unknown = JSON.parse(new TextDecoder().decode(inflated));
		if (
			typeof parsed !== "object" ||
			parsed === null ||
			typeof (parsed as PlaygroundState).d !== "string" ||
			typeof (parsed as PlaygroundState).c !== "string"
		) {
			return null;
		}
		const state = parsed as PlaygroundState;
		return { d: state.d, c: state.c, v: typeof state.v === "string" ? state.v : "" };
	} catch {
		// A hand-edited or truncated link is a normal thing to receive, not an error to report.
		return null;
	}
};
