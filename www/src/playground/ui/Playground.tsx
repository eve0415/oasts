import { useCallback, useEffect, useMemo, useState } from "react";
import { Editor, type Marker } from "./Editor";
import { Tabs } from "./Tabs";
import { OptionsForm } from "./OptionsForm";
import { OutputPane } from "./OutputPane";
import { DiagnosticsPanel } from "./DiagnosticsPanel";
import { useCompiler } from "../useCompiler";
import { DEFAULT_CONFIG, DEFAULT_DOCUMENT } from "../defaults";
import { parseConfig, pointerToOffset } from "../config/yaml";
import { parseConfigSchema, type ConfigSchema } from "../config/schema";
import { STATE_PARAM, decodeState, encodeState } from "../state";
import type { Diagnostic } from "../types";

type InputTab = "document" | "config" | "options";

/** The end of the token at `offset`, so a squiggle covers a word rather than one character. */
const wordAt = (text: string, offset: number): number => {
	let end = offset;
	while (end < text.length && !/[\s:,{}[\]]/.test(text[end] ?? "")) end += 1;
	return end === offset ? Math.min(offset + 1, text.length) : end;
};

export const Playground = () => {
	const [spec, setSpec] = useState(DEFAULT_DOCUMENT);
	const [config, setConfig] = useState(DEFAULT_CONFIG);
	const [tab, setTab] = useState<InputTab>("document");
	const [selected, setSelected] = useState("");
	const [schema, setSchema] = useState<ConfigSchema | null>(null);
	const [hydrated, setHydrated] = useState(false);
	const [copied, setCopied] = useState(false);

	const compiler = useCompiler();
	const { compile, version, versions, selectVersion, outcome, status, stale, failure, summary } =
		compiler;

	// A shared link is the whole point of the URL carrying state, so it is read before the first
	// compile rather than overwritten by the default document.
	useEffect(() => {
		void (async () => {
			const encoded = new URLSearchParams(window.location.search).get(STATE_PARAM);
			if (encoded !== null) {
				const restored = await decodeState(encoded);
				if (restored) {
					setSpec(restored.d);
					setConfig(restored.c);
				}
			}
			setHydrated(true);
		})();
	}, []);

	const parsed = useMemo(() => parseConfig(config), [config]);

	useEffect(() => {
		if (!hydrated || parsed.value === null) return;
		compile(spec, parsed.value);
	}, [hydrated, spec, parsed.value, compile]);

	// The options form is generated from the schema the SELECTED compiler enforces.
	useEffect(() => {
		const entry = versions.find((candidate) => candidate.version === version);
		if (!entry) return;
		let cancelled = false;
		void (async () => {
			try {
				const response = await fetch(entry.schema);
				const raw: unknown = await response.json();
				if (!cancelled) setSchema(parseConfigSchema(raw));
			} catch {
				if (!cancelled) setSchema(null);
			}
		})();
		return () => {
			cancelled = true;
		};
	}, [version, versions]);

	const share = useCallback(async () => {
		const encoded = await encodeState({ d: spec, c: config, v: version });
		const url = new URL(window.location.href);
		url.searchParams.set(STATE_PARAM, encoded);
		window.history.replaceState(null, "", url);
		await navigator.clipboard.writeText(url.toString());
		setCopied(true);
		window.setTimeout(() => setCopied(false), 2000);
	}, [spec, config, version]);

	const documentMarkers = useMemo(
		(): Marker[] =>
			outcome.diagnostics
				.filter((diagnostic) => diagnostic.line !== null && diagnostic.col !== null)
				.flatMap((diagnostic) => {
					const lines = spec.split("\n");
					let offset = 0;
					for (let index = 0; index < (diagnostic.line ?? 1) - 1; index += 1) {
						offset += (lines[index]?.length ?? 0) + 1;
					}
					const from = offset + Math.max((diagnostic.col ?? 1) - 1, 0);
					if (from >= spec.length) return [];
					return [{ from, to: wordAt(spec, from), severity: diagnostic.severity }];
				}),
		[outcome.diagnostics, spec],
	);

	const configMarkers = useMemo(
		(): Marker[] =>
			outcome.diagnostics
				.filter((diagnostic) => diagnostic.line === null && diagnostic.jsonPointer !== null)
				.flatMap((diagnostic) => {
					const from = pointerToOffset(config, diagnostic.jsonPointer ?? "");
					if (from === null) return [];
					return [{ from, to: wordAt(config, from), severity: diagnostic.severity }];
				}),
		[outcome.diagnostics, config],
	);

	const configProblems = outcome.diagnostics.filter(
		(diagnostic) => diagnostic.jsonPointer !== null,
	).length;

	const onDiagnostic = useCallback((diagnostic: Diagnostic) => {
		setTab(diagnostic.jsonPointer !== null && diagnostic.line === null ? "config" : "document");
	}, []);

	const tabs = [
		{ id: "document", label: <span className="pg-mono">openapi.yaml</span> },
		{
			id: "config",
			label: (
				<span className="pg-mono">
					oasts.yaml
					{configProblems > 0 ? <span className="pg-tab-badge">{configProblems}</span> : null}
				</span>
			),
			accessibleName:
				configProblems > 0
					? `oasts.yaml, ${configProblems} ${configProblems === 1 ? "problem" : "problems"}`
					: "oasts.yaml",
		},
		{ id: "options", label: "Options" },
	];

	return (
		<div className="pg-root">
			<header className="pg-header">
				<span className="pg-wordmark">oasts</span>
				<span className="pg-chip">Playground</span>

				<span className="pg-divider" aria-hidden="true" />

				<label htmlFor="pg-version" className="pg-version-label">
					Version
				</label>
				<select
					id="pg-version"
					className="pg-input pg-select"
					value={version}
					onChange={(event) => selectVersion(event.target.value)}
					disabled={versions.length < 2}
				>
					{versions.map((entry) => (
						<option key={entry.version} value={entry.version}>
							{entry.version}
						</option>
					))}
				</select>

				<span className="pg-spacer" />

				<button type="button" className="pg-button" onClick={() => void share()}>
					{copied ? "Link copied" : "Share"}
				</button>
				<a className="pg-button pg-button-link" href="/introduction">
					Docs
				</a>
			</header>

			<div className="pg-workspace">
				<section className="pg-input" aria-label="Input">
					<h2 className="pg-visually-hidden">Input</h2>
					<Tabs
						label="Input"
						tabs={tabs}
						active={tab}
						onSelect={(id) => setTab(id === "config" || id === "options" ? id : "document")}
					/>

					<div
						role="tabpanel"
						id="pg-panel-document"
						aria-labelledby="pg-tab-document"
						hidden={tab !== "document"}
						className="pg-panel"
					>
						<Editor
							value={spec}
							language="yaml"
							markers={documentMarkers}
							onChange={setSpec}
							ariaLabel="OpenAPI document"
						/>
					</div>

					<div
						role="tabpanel"
						id="pg-panel-config"
						aria-labelledby="pg-tab-config"
						hidden={tab !== "config"}
						className="pg-panel"
					>
						{parsed.error === null ? null : <p className="pg-parse-error">{parsed.error}</p>}
						<Editor
							value={config}
							language="yaml"
							markers={configMarkers}
							onChange={setConfig}
							ariaLabel="oasts configuration"
						/>
					</div>

					<div
						role="tabpanel"
						id="pg-panel-options"
						aria-labelledby="pg-tab-options"
						hidden={tab !== "options"}
						className="pg-panel"
					>
						{schema === null ? (
							<p className="pg-empty-note">The option list for this version is loading.</p>
						) : (
							<OptionsForm
								schema={schema}
								config={config}
								diagnostics={outcome.diagnostics}
								onChange={setConfig}
							/>
						)}
					</div>
				</section>

				<section className="pg-output-region" id="pg-output" aria-label="Generated output">
					<OutputPane
						files={outcome.files}
						selected={selected}
						onSelect={setSelected}
						stale={stale}
						busy={status === "compiling" || status === "loading"}
					/>
				</section>
			</div>

			<DiagnosticsPanel
				diagnostics={outcome.diagnostics}
				hostNotes={outcome.hostNotes}
				onSelect={onDiagnostic}
			/>

			<div className="pg-status">
				<span className={`pg-dot pg-dot-${status}`} aria-hidden="true" />
				<span>
					{status === "loading"
						? "Downloading the compiler…"
						: status === "compiling"
							? "Compiling…"
							: status === "failed"
								? (failure ?? "The compiler could not be started")
								: `${outcome.files.length} files · ${Math.round(outcome.elapsedMs)} ms`}
				</span>
				<span className="pg-status-note">compiled in your browser · WebAssembly {version}</span>
			</div>

			{/* One polite channel, updated only when the picture actually changes — never per keystroke. */}
			<p aria-live="polite" className="pg-visually-hidden">
				{status === "ready" ? summary : ""}
			</p>
		</div>
	);
};
