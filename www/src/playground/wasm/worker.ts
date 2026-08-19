/// <reference lib="webworker" />
import { CompilerModule } from "./host";
import type { CompileRequest, CompileResponse } from "../types";

/**
 * Compilation runs here so a 2 MB instantiation and every keystroke-driven rebuild stay off the
 * main thread. The UI stays responsive while a large document compiles, and a runaway document
 * cannot lock the tab.
 */

type Incoming =
	| { kind: "load"; url: string }
	| { kind: "compile"; id: number; request: CompileRequest };

type Outgoing =
	| { kind: "ready"; version: string }
	| { kind: "failed"; reason: string }
	| { kind: "result"; id: number; response: CompileResponse; elapsedMs: number };

let compiler: CompilerModule | null = null;

const post = (message: Outgoing) => {
	(self as unknown as DedicatedWorkerGlobalScope).postMessage(message);
};

self.addEventListener("message", (event: MessageEvent<Incoming>) => {
	const message = event.data;

	if (message.kind === "load") {
		void (async () => {
			try {
				const response = await fetch(message.url);
				if (!response.ok) {
					post({ kind: "failed", reason: `the compiler could not be downloaded (${response.status})` });
					return;
				}
				compiler = await CompilerModule.instantiate(response);
				post({ kind: "ready", version: message.url });
			} catch (error) {
				post({ kind: "failed", reason: error instanceof Error ? error.message : String(error) });
			}
		})();
		return;
	}

	if (message.kind === "compile") {
		if (compiler === null) {
			post({
				kind: "result",
				id: message.id,
				elapsedMs: 0,
				response: { files: [], diagnostics: [], error: "the compiler is still loading" },
			});
			return;
		}

		const started = performance.now();
		try {
			const response = compiler.generate(message.request);
			post({ kind: "result", id: message.id, response, elapsedMs: performance.now() - started });
		} catch (error) {
			// A panic unwinds into a poisoned instance, so the module is dropped and reloaded
			// rather than left to return wrong answers.
			compiler = null;
			post({
				kind: "result",
				id: message.id,
				elapsedMs: performance.now() - started,
				response: {
					files: [],
					diagnostics: [],
					error: error instanceof Error ? error.message : String(error),
				},
			});
		}
	}
});
