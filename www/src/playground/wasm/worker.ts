/// <reference lib="webworker" />
import { CompilerModule } from "./host";
import type { CompileRequest, CompileResponse } from "../types";
import { propertyOf, stringOf } from "../json";

/**
 * Compilation runs here so a 2 MB instantiation and every keystroke-driven rebuild stay off the
 * main thread. The UI stays responsive while a large document compiles, and a runaway document
 * cannot lock the tab.
 */

declare const self: DedicatedWorkerGlobalScope;

export type Outgoing =
	| { kind: "ready" }
	| { kind: "failed"; reason: string }
	| { kind: "result"; id: number; response: CompileResponse; elapsedMs: number };

let compiler: CompilerModule | null = null;

const post = (message: Outgoing): void => {
	self.postMessage(message);
};

const reasonOf = (error: unknown): string =>
	error instanceof Error ? error.message : String(error);

const load = async (url: string): Promise<void> => {
	try {
		const response = await fetch(url);
		if (!response.ok) {
			post({ kind: "failed", reason: `the compiler could not be downloaded (${response.status})` });
			return;
		}
		compiler = await CompilerModule.instantiate(response);
		post({ kind: "ready" });
	} catch (error) {
		post({ kind: "failed", reason: reasonOf(error) });
	}
};

const compile = (id: number, request: CompileRequest): void => {
	if (compiler === null) {
		post({
			kind: "result",
			id,
			elapsedMs: 0,
			response: { files: [], diagnostics: [], error: "the compiler is still loading" },
		});
		return;
	}

	const started = performance.now();
	try {
		post({ kind: "result", id, response: compiler.generate(request), elapsedMs: performance.now() - started });
	} catch (error) {
		// A panic leaves the instance poisoned, so it is dropped rather than left to answer wrongly.
		compiler = null;
		post({
			kind: "result",
			id,
			elapsedMs: performance.now() - started,
			response: { files: [], diagnostics: [], error: reasonOf(error) },
		});
	}
};

self.addEventListener("message", (event: MessageEvent) => {
	const message: unknown = event.data;
	const kind = stringOf(message, "kind");

	if (kind === "load") {
		const url = stringOf(message, "url");
		if (url !== null) void load(url);
		return;
	}

	if (kind === "compile") {
		const id = propertyOf(message, "id");
		const request = propertyOf(message, "request");
		const spec = stringOf(request, "spec");
		if (typeof id !== "number" || spec === null) return;
		compile(id, { spec, config: propertyOf(request, "config") });
	}
});
