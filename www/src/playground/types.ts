/**
 * The compiler boundary, matching `crates/oasts-wasm/src/lib.rs` field for field.
 * Everything crossing it is JSON; there are no pointers in these shapes.
 */

export interface CompileRequest {
	spec: string;
	config: unknown;
}

export interface GeneratedFile {
	path: string;
	content: string;
}

export type Severity = "error" | "warning";

export interface Diagnostic {
	code: string;
	severity: Severity;
	message: string;
	sourceId: string | null;
	line: number | null;
	col: number | null;
	jsonPointer: string | null;
}

export interface CompileResponse {
	files: GeneratedFile[];
	diagnostics: Diagnostic[];
	/** Set only when the module could not read the request at all. */
	error: string | null;
}

export interface VersionEntry {
	version: string;
	/** The compiler module for this version. */
	url: string;
	/** The config schema this exact compiler enforces, which the options form is generated from. */
	schema: string;
}

export interface VersionManifest {
	current: string;
	versions: VersionEntry[];
}

/** What a share link carries. Kept short — it is compressed into a query parameter. */
export interface PlaygroundState {
	/** The OpenAPI document. */
	d: string;
	/** The oasts.yaml configuration, as written. */
	c: string;
	/** Compiler version the link was made on. */
	v: string;
}
