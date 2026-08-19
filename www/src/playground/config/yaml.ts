import { Document, isCollection, isNode, parseDocument } from "yaml";

/**
 * The options form and the YAML editor are two views of one document, so edits go through the
 * YAML AST rather than a re-serialised object: comments, key order and formatting survive a
 * checkbox being toggled.
 */

export interface ParsedConfig {
	/** Plain JSON for the compiler, or null when the text does not parse. */
	value: unknown;
	/** A parse or schema-shape complaint about the config text itself. */
	error: string | null;
}

export const parseConfig = (text: string): ParsedConfig => {
	const document = parseDocument(text);
	if (document.errors.length > 0) {
		const first = document.errors[0];
		return { value: null, error: first ? first.message : "the configuration is not valid YAML" };
	}
	const value: unknown = document.toJS({ maxAliasCount: 100 });
	if (value === null || typeof value !== "object" || Array.isArray(value)) {
		return { value: null, error: "the configuration must be a mapping" };
	}
	return { value, error: null };
};

/** Reads a value at a dotted path without materialising the whole document. */
export const readAt = (text: string, segments: string[]): unknown => {
	const document = parseDocument(text);
	if (document.errors.length > 0) return undefined;
	return document.getIn(segments, false);
};

/**
 * Writes a value at a path, or removes the key when `value` is undefined. Returns the new text.
 * Removing prunes mappings that the removal emptied, so turning an artifact off does not leave
 * `artifacts: {}` behind.
 */
export const writeAt = (text: string, segments: string[], value: unknown): string => {
	const document = parseDocument(text);
	if (document.errors.length > 0) return text;

	if (value === undefined) {
		document.deleteIn(segments);
		for (let depth = segments.length - 1; depth > 0; depth -= 1) {
			const parentPath = segments.slice(0, depth);
			const parent = document.getIn(parentPath, true);
			if (isCollection(parent) && parent.items.length === 0) {
				document.deleteIn(parentPath);
			} else {
				break;
			}
		}
	} else {
		document.setIn(segments, value);
	}

	return String(document);
};

/**
 * Where a JSON Pointer lands in the text, so a config diagnostic can be shown on its own line
 * instead of at the top of the file. Config diagnostics arrive with a pointer and no position —
 * the compiler resolved them against a parsed value, not this text.
 */
export const pointerToOffset = (text: string, pointer: string): number | null => {
	if (!pointer || pointer === "/") return null;
	const segments = pointer
		.slice(1)
		.split("/")
		.map((segment) => segment.replaceAll("~1", "/").replaceAll("~0", "~"));

	const document = parseDocument(text);
	if (document.errors.length > 0) return null;

	// Walk toward the pointer and stop at the deepest key that exists: a diagnostic about a
	// missing key should land on its parent rather than nowhere.
	for (let depth = segments.length; depth > 0; depth -= 1) {
		const node = document.getIn(segments.slice(0, depth), true);
		if (isNode(node) && node.range) return node.range[0];
	}
	return null;
};

/** A fresh document, used when the form edits a config the editor has not written yet. */
export const emptyDocument = (): string => String(new Document({}));
