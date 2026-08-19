import { useEffect, useMemo, useState } from "react";
import { Editor } from "./Editor";
import type { GeneratedFile } from "../types";

/**
 * A generate run emits tens of files across several artifacts, so the output needs a browser
 * rather than a single pane.
 *
 * It is deliberately NOT an ARIA tree: a tree is a full APG commitment — typeahead, expand and
 * collapse keys, level semantics — and this is one fixed level of grouping. Grouped lists of
 * buttons under real headings navigate the same way with native semantics.
 */

const WRAP_KEY = "oasts-playground-wrap";

export interface OutputPaneProps {
	files: GeneratedFile[];
	selected: string;
	onSelect: (path: string) => void;
	stale: boolean;
	busy: boolean;
}

interface Group {
	name: string;
	files: GeneratedFile[];
}

const groupOf = (path: string): string => {
	const slash = path.indexOf("/");
	return slash === -1 ? "." : `${path.slice(0, slash)}/`;
};

export const OutputPane = ({ files, selected, onSelect, stale, busy }: OutputPaneProps) => {
	// Remembered per visitor, the way an editor remembers word wrap.
	const [wrap, setWrap] = useState(() => window.localStorage.getItem(WRAP_KEY) !== "off");

	useEffect(() => {
		window.localStorage.setItem(WRAP_KEY, wrap ? "on" : "off");
	}, [wrap]);

	const groups = useMemo(() => {
		const byName = new Map<string, GeneratedFile[]>();
		for (const file of files) {
			const name = groupOf(file.path);
			const bucket = byName.get(name);
			if (bucket) bucket.push(file);
			else byName.set(name, [file]);
		}
		return [...byName.entries()]
			.map(([name, entries]): Group => ({ name, files: entries }))
			.sort((left, right) => left.name.localeCompare(right.name));
	}, [files]);

	const active = files.find((file) => file.path === selected) ?? files[0];

	if (files.length === 0) {
		return (
			<div className="pg-output-empty">
				<h2>Nothing to compile yet</h2>
				<p>
					Paste an OpenAPI 3.0 or 3.1 document on the left and the TypeScript appears here as you
					type.
				</p>
			</div>
		);
	}

	return (
		<div className="pg-output" aria-busy={busy || undefined}>
			<h2 className="pg-visually-hidden">Generated output</h2>
			<nav className="pg-files" aria-label="Generated files">
				{groups.map((group) => (
					<div key={group.name} className="pg-file-group">
						<h3 className="pg-file-group-name">
							{group.name}
							<span className="pg-file-count">
								{group.files.length} {group.files.length === 1 ? "file" : "files"}
							</span>
						</h3>
						<ul>
							{group.files.map((file) => {
								const isActive = active?.path === file.path;
								return (
									<li key={file.path}>
										<button
											type="button"
											className={`pg-file${isActive ? " pg-file-active" : ""}`}
											aria-current={isActive ? "true" : undefined}
											onClick={() => onSelect(file.path)}
										>
											{file.path.slice(group.name === "." ? 0 : group.name.length)}
										</button>
									</li>
								);
							})}
						</ul>
					</div>
				))}
			</nav>

			<div className="pg-output-view">
				{stale ? (
					<p className="pg-stale" role="status">
						Showing the last build that succeeded. Fix the errors below to update it.
					</p>
				) : null}
				<div className="pg-output-head">
					<span className="pg-path">{active?.path}</span>
					<button
						type="button"
						className="pg-button"
						aria-pressed={wrap}
						onClick={() => setWrap((current) => !current)}
					>
						Wrap
					</button>
					<button
						type="button"
						className="pg-button"
						onClick={() => {
							if (active) void navigator.clipboard.writeText(active.content);
						}}
					>
						Copy
					</button>
				</div>
				<div className="pg-output-code">
					<Editor
						key={active?.path}
						value={active?.content ?? ""}
						language="typescript"
						readOnly
						wrap={wrap}
						ariaLabel={`Generated ${active?.path ?? "file"}, read only`}
					/>
				</div>
			</div>
		</div>
	);
};
