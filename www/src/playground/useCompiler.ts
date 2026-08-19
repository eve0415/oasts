import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CompileResponse, Diagnostic, VersionEntry } from "./types";
import { arrayOf, numberOf, propertyOf, stringOf } from "./json";
import { toResponse } from "./wasm/host";

/**
 * Owns the worker, the module for the selected version, and the debounce.
 *
 * Debouncing is as much an accessibility decision as a performance one: recompiling on every
 * keystroke would push a screen-reader announcement per character. The summary this returns
 * changes only when the diagnostic picture actually changes, and that is what gets announced.
 */

const DEBOUNCE_MS = 300;

/**
 * Codes the browser host raises about ITSELF rather than about the document. Only as warnings —
 * the same codes are real refusals when a config asks for something this host cannot do, and
 * those belong in the diagnostics list.
 */
const HOST_NOTE_CODES = new Set(["OASTS0221", "OASTS0251"]);

const isHostNote = (diagnostic: Diagnostic): boolean =>
	diagnostic.severity === "warning" && HOST_NOTE_CODES.has(diagnostic.code);

export type CompilerStatus = "loading" | "ready" | "compiling" | "failed";

export interface CompileOutcome {
	files: CompileResponse["files"];
	/** Diagnostics about the document and config. */
	diagnostics: Diagnostic[];
	/** Diagnostics about the browser host itself. */
	hostNotes: Diagnostic[];
	elapsedMs: number;
	/** Set when the request could not be read at all. */
	error: string | null;
}

const EMPTY: CompileOutcome = {
	files: [],
	diagnostics: [],
	hostNotes: [],
	elapsedMs: 0,
	error: null,
};

export interface UseCompiler {
	status: CompilerStatus;
	failure: string | null;
	outcome: CompileOutcome;
	/** Kept from the last successful build, so an error does not blank the pane. */
	stale: boolean;
	versions: VersionEntry[];
	version: string;
	selectVersion: (version: string) => void;
	compile: (spec: string, config: unknown) => void;
	summary: string;
}

export const useCompiler = (): UseCompiler => {
	const [versions, setVersions] = useState<VersionEntry[]>([]);
	const [version, setVersion] = useState("");
	const [status, setStatus] = useState<CompilerStatus>("loading");
	const [failure, setFailure] = useState<string | null>(null);
	const [outcome, setOutcome] = useState<CompileOutcome>(EMPTY);
	const [stale, setStale] = useState(false);

	const workerRef = useRef<Worker | null>(null);
	const timerRef = useRef<number | null>(null);
	const requestId = useRef(0);
	const pending = useRef<{ spec: string; config: unknown } | null>(null);
	const loaded = useRef(false);

	/** Sends whatever is queued, once there is a module to send it to. */
	const flush = useCallback(() => {
		const worker = workerRef.current;
		const queued = pending.current;
		if (!worker || !loaded.current || !queued) return;
		pending.current = null;
		requestId.current += 1;
		worker.postMessage({ kind: "compile", id: requestId.current, request: queued });
		setStatus("compiling");
	}, []);

	useEffect(() => {
		let cancelled = false;
		void (async () => {
			try {
				const response = await fetch("/play/wasm/versions.json");
				const manifest: unknown = await response.json();
				if (cancelled) return;
				const entries: VersionEntry[] = [];
				for (const entry of arrayOf(manifest, "versions")) {
					const version = stringOf(entry, "version");
					const url = stringOf(entry, "url");
					const schema = stringOf(entry, "schema");
					if (version === null || url === null || schema === null) continue;
					entries.push({ version, url, schema });
				}
				const current = stringOf(manifest, "current") ?? entries[0]?.version ?? "";
				if (entries.length === 0) {
					setStatus("failed");
					setFailure("no compiler build is available");
					return;
				}
				setVersions(entries);
				setVersion(current);
			} catch {
				if (!cancelled) {
					setStatus("failed");
					setFailure("the compiler version list could not be loaded");
				}
			}
		})();
		return () => {
			cancelled = true;
		};
	}, []);

	useEffect(() => {
		if (version === "") return;
		const entry = versions.find((candidate) => candidate.version === version);
		if (!entry) return;

		setStatus("loading");
		setFailure(null);
		loaded.current = false;

		const worker = new Worker(new URL("./wasm/worker.ts", import.meta.url), { type: "module" });
		workerRef.current = worker;

		worker.addEventListener("message", (event: MessageEvent) => {
			const message: unknown = event.data;
			const kind = stringOf(message, "kind");

			if (kind === "ready") {
				loaded.current = true;
				setStatus("ready");
				flush();
				return;
			}

			if (kind === "failed") {
				loaded.current = false;
				setStatus("failed");
				setFailure(stringOf(message, "reason") ?? "the compiler could not be started");
				return;
			}

			if (kind !== "result") return;
			// A late reply from a superseded request would show output for text that is gone.
			if (numberOf(message, "id") !== requestId.current) return;

			const response = toResponse(propertyOf(message, "response"));
			const elapsedMs = numberOf(message, "elapsedMs") ?? 0;
			const hostNotes = response.diagnostics.filter(isHostNote);
			const diagnostics = response.diagnostics.filter((d) => !isHostNote(d));
			const failed = response.files.length === 0 && diagnostics.some((d) => d.severity === "error");

			setStatus("ready");
			setStale(failed);
			setOutcome((previous) => ({
				files: failed ? previous.files : response.files,
				diagnostics,
				hostNotes,
				elapsedMs,
				error: response.error,
			}));
		});

		worker.postMessage({ kind: "load", url: entry.url });

		return () => {
			worker.terminate();
		};
	}, [version, versions, flush]);

	const compile = useCallback(
		(spec: string, config: unknown) => {
			if (timerRef.current !== null) window.clearTimeout(timerRef.current);
			timerRef.current = window.setTimeout(() => {
				// Queued rather than posted, so a compile requested before the module finishes
				// downloading still runs the moment it is ready.
				pending.current = { spec, config };
				flush();
			}, DEBOUNCE_MS);
		},
		[flush],
	);

	useEffect(
		() => () => {
			if (timerRef.current !== null) window.clearTimeout(timerRef.current);
		},
		[],
	);

	const summary = useMemo(() => {
		const errors = outcome.diagnostics.filter((d) => d.severity === "error").length;
		const warnings = outcome.diagnostics.filter((d) => d.severity === "warning").length;
		if (errors === 0 && warnings === 0) {
			return `No problems. ${outcome.files.length} files generated.`;
		}
		const parts: string[] = [];
		if (errors > 0) parts.push(`${errors} ${errors === 1 ? "error" : "errors"}`);
		if (warnings > 0) parts.push(`${warnings} ${warnings === 1 ? "warning" : "warnings"}`);
		return parts.join(", ");
	}, [outcome]);

	return {
		status,
		failure,
		outcome,
		stale,
		versions,
		version,
		selectVersion: setVersion,
		compile,
		summary,
	};
};
