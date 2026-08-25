import type { CompileRequest, CompileResponse, Diagnostic, Severity } from "../types";
import { arrayOf, numberOf, propertyOf, stringOf } from "../json";

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

/** Checks the module really exports the boundary before anything calls through it. */
const hasExports = (value: unknown): value is Exports => {
	if (typeof value !== "object" || value === null) return false;
	if (!("memory" in value) || !(value.memory instanceof WebAssembly.Memory)) return false;
	return (
		"oasts_alloc" in value &&
		typeof value.oasts_alloc === "function" &&
		"oasts_free" in value &&
		typeof value.oasts_free === "function" &&
		"oasts_generate" in value &&
		typeof value.oasts_generate === "function"
	);
};

const toSeverity = (value: unknown): Severity => (value === "error" ? "error" : "warning");

const toDiagnostic = (node: unknown): Diagnostic => ({
	code: stringOf(node, "code") ?? "",
	severity: toSeverity(propertyOf(node, "severity")),
	message: stringOf(node, "message") ?? "",
	sourceId: stringOf(node, "sourceId"),
	line: numberOf(node, "line"),
	col: numberOf(node, "col"),
	jsonPointer: stringOf(node, "jsonPointer"),
});

export const toResponse = (node: unknown): CompileResponse => ({
	files: arrayOf(node, "files").map((file) => ({
		path: stringOf(file, "path") ?? "",
		content: stringOf(file, "content") ?? "",
	})),
	diagnostics: arrayOf(node, "diagnostics").map(toDiagnostic),
	error: stringOf(node, "error"),
});

export class CompilerModule {
	readonly #exports: Exports;

	private constructor(exports: Exports) {
		this.#exports = exports;
	}

	/**
	 * Streaming instantiation specifically: V8 only code-caches modules compiled through the
	 * streaming API, and at 2 MB this one is well past the 128 kB threshold where that pays.
	 */
	static async instantiate(source: Response): Promise<CompilerModule> {
		const { instance } = await WebAssembly.instantiateStreaming(source, {});

		if (!hasExports(instance.exports)) {
			throw new Error("the compiler module does not export the expected boundary");
		}
		return new CompilerModule(instance.exports);
	}

	generate(request: CompileRequest): CompileResponse {
		const { memory, oasts_alloc, oasts_free, oasts_generate } = this.#exports;

		const encoded = new TextEncoder().encode(JSON.stringify(request));
		const inPtr = oasts_alloc(encoded.length);
		new Uint8Array(memory.buffer, inPtr, encoded.length).set(encoded);

		const outPtr = oasts_generate(inPtr, encoded.length);
		oasts_free(inPtr, encoded.length);

		// Read the views only after the call: growing the heap detaches any buffer taken before it.
		const length = new DataView(memory.buffer).getUint32(outPtr, true);
		const body = new TextDecoder().decode(
			new Uint8Array(memory.buffer, outPtr + LENGTH_PREFIX, length),
		);
		oasts_free(outPtr, LENGTH_PREFIX + length);

		const parsed: unknown = JSON.parse(body);
		return toResponse(parsed);
	}
}
