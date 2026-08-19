import { arrayOf, entriesOf, propertyOf, stringOf } from "../json";

/**
 * Turns the compiler's own config schema into a form model.
 *
 * The form is generated rather than hand-written so it cannot drift from the compiler: the
 * schema staged next to each module is the one that module enforces, so selecting an older
 * version reshapes the form to that version's options.
 */

export type FieldKind = "boolean" | "string" | "number" | "enum";

export interface Field {
	/** Dotted path, e.g. `validation.engine`. */
	path: string;
	/** Path segments, for reading and writing the YAML document. */
	segments: string[];
	label: string;
	kind: FieldKind;
	description: string | null;
	options: string[];
	default: unknown;
}

export interface Section {
	/** Top-level config key, e.g. `validation`. */
	key: string;
	description: string | null;
	fields: Field[];
}

export interface ConfigSchema {
	sections: Section[];
	byPath: Map<string, Field>;
}

/** Keys describing the run rather than the output, or that the browser host cannot honour. */
const HIDDEN_ROOT_KEYS = new Set([
	"$schema",
	"schemaVersion",
	"input",
	"output",
	"workspaceRoot",
	"specs",
	"shared",
	"watch",
	"ci",
	"local",
	"remote",
	"typescript",
]);

const MAX_DEPTH = 3;

const typeOf = (node: unknown): string | null => {
	const type = propertyOf(node, "type");
	if (typeof type === "string") return type;
	if (Array.isArray(type)) {
		const first = type[0];
		return typeof first === "string" ? first : null;
	}
	return null;
};

const resolve = (node: unknown, defs: unknown): unknown => {
	let current = node;
	// Chains are shallow in practice; the bound guards a malformed schema, it is not a limit.
	for (let hop = 0; hop < 8; hop += 1) {
		const ref = stringOf(current, "$ref");
		if (ref === null) return current;
		const name = ref.split("/").pop();
		const target = name === undefined ? undefined : propertyOf(defs, name);
		if (target === undefined) return current;
		current = target;
	}
	return current;
};

/**
 * Picks the branch a form can edit. `boolean | {…}` is the artifact shorthand: the form offers
 * the boolean and leaves the option block to the YAML editor, which is the honest split — a
 * checkbox cannot express a directory override.
 */
const collapse = (node: unknown, defs: unknown): unknown => {
	const branches = [...arrayOf(node, "anyOf"), ...arrayOf(node, "oneOf")];
	if (branches.length === 0) return node;
	const resolved = branches.map((branch) => resolve(branch, defs));
	return (
		resolved.find((branch) => arrayOf(branch, "enum").length > 0) ??
		resolved.find((branch) => typeOf(branch) === "boolean") ??
		resolved.find((branch) => {
			const type = typeOf(branch);
			return type === "string" || type === "integer" || type === "number";
		}) ??
		node
	);
};

const kindOf = (node: unknown): FieldKind | null => {
	if (arrayOf(node, "enum").length > 0) return "enum";
	const type = typeOf(node);
	if (type === "boolean") return "boolean";
	if (type === "string") return "string";
	if (type === "integer" || type === "number") return "number";
	return null;
};

export const parseConfigSchema = (raw: unknown): ConfigSchema => {
	const defs = propertyOf(raw, "$defs");
	const sections: Section[] = [];
	const byPath = new Map<string, Field>();

	const walk = (node: unknown, segments: string[], into: Field[], depth: number): void => {
		const resolved = collapse(resolve(node, defs), defs);
		const kind = kindOf(resolved);

		if (kind !== null) {
			const field: Field = {
				path: segments.join("."),
				segments,
				label: segments[segments.length - 1] ?? "",
				kind,
				description: stringOf(resolved, "description") ?? stringOf(node, "description"),
				options: arrayOf(resolved, "enum").map(String),
				default: propertyOf(resolved, "default"),
			};
			into.push(field);
			byPath.set(field.path, field);
			return;
		}

		if (depth >= MAX_DEPTH) return;
		for (const [key, child] of entriesOf(propertyOf(resolved, "properties"))) {
			walk(child, [...segments, key], into, depth + 1);
		}
	};

	for (const [key, node] of entriesOf(propertyOf(raw, "properties"))) {
		if (HIDDEN_ROOT_KEYS.has(key)) continue;
		const fields: Field[] = [];
		walk(node, [key], fields, 1);
		if (fields.length === 0) continue;
		sections.push({
			key,
			description: stringOf(resolve(node, defs), "description"),
			fields,
		});
	}

	return { sections, byPath };
};
