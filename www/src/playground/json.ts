/**
 * Readers for JSON that arrived from somewhere else — a fetched manifest, a fetched schema, the
 * compiler's response. Everything crossing those boundaries is `unknown` until something here
 * has checked it, so no shape in this app is asserted into existence.
 */

export const entriesOf = (node: unknown): ReadonlyArray<readonly [string, unknown]> => {
	if (typeof node !== "object" || node === null) return [];
	return Object.entries(node);
};

export const propertyOf = (node: unknown, key: string): unknown => {
	for (const [candidate, value] of entriesOf(node)) {
		if (candidate === key) return value;
	}
	return undefined;
};

export const stringOf = (node: unknown, key: string): string | null => {
	const value = propertyOf(node, key);
	return typeof value === "string" ? value : null;
};

export const booleanOf = (node: unknown, key: string): boolean | null => {
	const value = propertyOf(node, key);
	return typeof value === "boolean" ? value : null;
};

export const numberOf = (node: unknown, key: string): number | null => {
	const value = propertyOf(node, key);
	return typeof value === "number" && Number.isFinite(value) ? value : null;
};

export const arrayOf = (node: unknown, key: string): readonly unknown[] => {
	const value = propertyOf(node, key);
	return Array.isArray(value) ? value : [];
};
