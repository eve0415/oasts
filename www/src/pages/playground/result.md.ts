import type { APIRoute } from "astro";
import compilerModule from "@/playground/wasm/generated/compiler.wasm";
import { CompilerModule } from "@/playground/wasm/host";
import { parseConfig } from "@/playground/config/yaml";
import { decodeState, STATE_PARAM } from "@/playground/state";
import { DEFAULT_CONFIG, DEFAULT_DOCUMENT } from "@/playground/defaults";
import type { CompileResponse } from "@/playground/types";
import { describeLocation } from "@/playground/sources";

/**
 * The same playground state, as plain text.
 *
 * A reproduction link is increasingly read by an agent rather than a person, and an agent should
 * not have to run an editor, wait out a debounce and scrape a DOM to see what the compiler said.
 * One request, one deterministic body, the same answer the page is showing.
 *
 * This is why share links put their state in the query string: a fragment never reaches a server.
 */

export const prerender = false;

/** Compiled once per isolate — instantiation is the expensive part, not the compile. */
let compiler: Promise<CompilerModule> | null = null;

const load = (): Promise<CompilerModule> => {
	compiler ??= CompilerModule.instantiate(compilerModule);
	return compiler;
};

const fence = (path: string, content: string): string => {
	// A generated file could itself contain a fence; widen ours until it cannot collide.
	const longest = [...content.matchAll(/`{3,}/g)].reduce(
		(width, match) => Math.max(width, match[0].length),
		2,
	);
	const rail = "`".repeat(longest + 1);
	return `### ${path}\n\n${rail}typescript\n${content}\n${rail}\n`;
};

const render = (response: CompileResponse, version: string, elapsed: number): string => {
	const lines: string[] = [];
	lines.push(`# oasts ${version} — ${response.files.length} files, ${elapsed} ms`, "");

	if (response.error !== null) {
		lines.push("## error", "", response.error, "");
		return lines.join("\n");
	}

	lines.push("## diagnostics", "");
	if (response.diagnostics.length === 0) {
		lines.push("None.", "");
	} else {
		for (const diagnostic of response.diagnostics) {
			lines.push(
				`- **${diagnostic.severity}** \`${diagnostic.code}\` ${describeLocation(diagnostic)}`,
			);
			lines.push(`  ${diagnostic.message}`);
		}
		lines.push("");
	}

	lines.push("## files", "");
	for (const file of response.files) lines.push(`- ${file.path}`);
	lines.push("");

	for (const file of response.files) lines.push(fence(file.path, file.content));

	return lines.join("\n");
};

export const GET: APIRoute = async ({ url }) => {
	const encoded = url.searchParams.get(STATE_PARAM);
	const restored = encoded === null ? null : await decodeState(encoded);

	const spec = restored?.d ?? DEFAULT_DOCUMENT;
	const configText = restored?.c ?? DEFAULT_CONFIG;
	const parsed = parseConfig(configText);

	const headers = {
		"content-type": "text/markdown; charset=utf-8",
		// The answer is a pure function of the URL, so it is safe to cache hard.
		"cache-control": "public, max-age=600",
	};

	if (parsed.value === null) {
		return new Response(`# oasts\n\n## error\n\n${parsed.error ?? "the configuration is unreadable"}\n`, {
			status: 400,
			headers,
		});
	}

	const started = Date.now();
	const response = (await load()).generate({ spec, config: parsed.value });

	return new Response(render(response, restored?.v || "current", Date.now() - started), {
		headers,
	});
};
