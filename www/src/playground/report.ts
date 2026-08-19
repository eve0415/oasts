import type { CompileOutcome } from "./useCompiler";
import { describeLocation } from "./sources";

/**
 * The playground state as a Markdown report, for pasting into an issue.
 *
 * This used to be a server-rendered route, which could only ever compile with the single module
 * baked into a deploy — so on a link pinning an older version it reported a version it had not
 * used. Built here instead, it always describes the compiler that actually ran.
 */

export interface ReportInput {
	outcome: CompileOutcome;
	version: string;
	link: string;
	spec: string;
	config: string;
}

/** Widens the fence until it cannot collide with anything inside the content. */
const fence = (content: string): string => {
	const longest = [...content.matchAll(/`{3,}/g)].reduce(
		(width, match) => Math.max(width, match[0].length),
		2,
	);
	return "`".repeat(longest + 1);
};

const block = (language: string, content: string): string => {
	const rail = fence(content);
	return `${rail}${language}\n${content}\n${rail}`;
};

export const buildReport = ({ outcome, version, link, spec, config }: ReportInput): string => {
	const lines: string[] = [
		`# oasts ${version} — ${outcome.files.length} files, ${Math.round(outcome.elapsedMs)} ms`,
		"",
		`[Open in the playground](${link})`,
		"",
		"## Diagnostics",
		"",
	];

	if (outcome.diagnostics.length === 0) {
		lines.push("None.", "");
	} else {
		for (const diagnostic of outcome.diagnostics) {
			lines.push(
				`- **${diagnostic.severity}** \`${diagnostic.code}\` ${describeLocation(diagnostic)}`,
				`  ${diagnostic.message}`,
			);
		}
		lines.push("");
	}

	for (const note of outcome.hostNotes) {
		lines.push(`> Compiled in a browser: \`${note.code}\` ${note.message}`, "");
	}

	lines.push("## openapi.yaml", "", block("yaml", spec), "");
	lines.push("## oasts.yaml", "", block("yaml", config), "");

	lines.push("## Generated files", "");
	for (const file of outcome.files) lines.push(`- \`${file.path}\``);
	lines.push("");

	return lines.join("\n");
};
