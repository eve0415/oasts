import type { PlaygroundState } from "./types";
import { stringOf } from "./json";

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

const fromBase64Url = (value: string): Uint8Array<ArrayBuffer> => {
	const padded = value.replaceAll("-", "+").replaceAll("_", "/");
	const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="));
	const bytes = new Uint8Array(new ArrayBuffer(binary.length));
	for (let index = 0; index < binary.length; index += 1) {
		bytes[index] = binary.charCodeAt(index);
	}
	return bytes;
};

const through = async (
	data: Uint8Array<ArrayBuffer>,
	transform: TransformStream,
): Promise<Uint8Array> => {
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
		const document = stringOf(parsed, "d");
		const config = stringOf(parsed, "c");
		if (document === null || config === null) return null;
		return { d: document, c: config, v: stringOf(parsed, "v") ?? "" };
	} catch {
		// A hand-edited or truncated link is a normal thing to receive, not an error to report.
		return null;
	}
};
