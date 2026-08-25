import type { Diagnostic } from "./types";

/**
 * The in-memory host seats the config as JSON, so diagnostics about it name `oasts.json`. The
 * file a reader actually edits is `oasts.yaml`, and pointing them at a name that is not on screen
 * is a small lie with a real cost.
 */
const DISPLAY_NAMES = new Map([
	["oasts.json", "oasts.yaml"],
	["oasts.yml", "oasts.yaml"],
]);

export const displaySource = (sourceId: string | null): string => {
	if (sourceId === null || sourceId === "") return "";
	const name = sourceId.split("/").pop() ?? sourceId;
	return DISPLAY_NAMES.get(name) ?? name;
};

/** `file:line:col` when the compiler resolved a position, otherwise `file /json/pointer`. */
export const describeLocation = (diagnostic: Diagnostic): string => {
	const source = displaySource(diagnostic.sourceId);
	if (diagnostic.line !== null && diagnostic.col !== null) {
		return `${source}:${diagnostic.line}:${diagnostic.col}`;
	}
	return diagnostic.jsonPointer ? `${source} ${diagnostic.jsonPointer}` : source;
};
