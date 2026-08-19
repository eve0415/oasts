import type { CompileRequest, CompileResponse } from "../types";

/**
 * The whole host side of the compiler boundary.
 *
 * The module declares zero imports, so it instantiates against an empty import object and
 * structurally cannot reach a filesystem, a socket, or the page. That is the mechanism behind
 * "the playground cannot phone home" — there is no sandbox to inspect because there is nothing
 * to sandbox.
 */

const LENGTH_PREFIX = 4;

interface Exports {
	memory: WebAssembly.Memory;
	oasts_alloc: (len: number) => number;
	oasts_free: (ptr: number, len: number) => void;
	oasts_generate: (ptr: number, len: number) => number;
}

export class CompilerModule {
	readonly #exports: Exports;

	private constructor(exports: Exports) {
		this.#exports = exports;
	}

	static async instantiate(source: Response | ArrayBuffer): Promise<CompilerModule> {
		const { instance } =
			source instanceof Response
				? await WebAssembly.instantiateStreaming(source, {})
				: await WebAssembly.instantiate(source, {});

		return new CompilerModule(instance.exports as unknown as Exports);
	}

	generate(request: CompileRequest): CompileResponse {
		const { memory, oasts_alloc, oasts_free, oasts_generate } = this.#exports;

		const encoded = new TextEncoder().encode(JSON.stringify(request));
		const inPtr = oasts_alloc(encoded.length);
		new Uint8Array(memory.buffer, inPtr, encoded.length).set(encoded);

		const outPtr = oasts_generate(inPtr, encoded.length);
		oasts_free(inPtr, encoded.length);

		// Re-read the view after the call: growing the heap detaches any buffer taken before it.
		const length = new DataView(memory.buffer).getUint32(outPtr, true);
		const body = new TextDecoder().decode(
			new Uint8Array(memory.buffer, outPtr + LENGTH_PREFIX, length),
		);
		oasts_free(outPtr, LENGTH_PREFIX + length);

		return JSON.parse(body) as CompileResponse;
	}
}
