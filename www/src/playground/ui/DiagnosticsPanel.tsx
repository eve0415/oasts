import type { Diagnostic } from "../types";

/**
 * Diagnostics are a list of things about YOUR document. Notes the browser host raises about
 * itself sit in their own row below, so a permanent host caveat never inflates the warning count
 * and train people to ignore the panel.
 */

export interface DiagnosticsPanelProps {
	diagnostics: Diagnostic[];
	hostNotes: Diagnostic[];
	onSelect: (diagnostic: Diagnostic) => void;
}

const where = (diagnostic: Diagnostic): string => {
	const source = diagnostic.sourceId?.split("/").pop() ?? "";
	if (diagnostic.line !== null && diagnostic.col !== null) {
		return `${source}:${diagnostic.line}:${diagnostic.col}`;
	}
	return diagnostic.jsonPointer ? `${source} ${diagnostic.jsonPointer}` : source;
};

export const DiagnosticsPanel = ({
	diagnostics,
	hostNotes,
	onSelect,
}: DiagnosticsPanelProps) => {
	const errors = diagnostics.filter((diagnostic) => diagnostic.severity === "error").length;
	const warnings = diagnostics.length - errors;

	return (
		<section className="pg-diagnostics" aria-label="Diagnostics">
			<div className="pg-diagnostics-head">
				<h2>Diagnostics</h2>
				{errors > 0 ? (
					<span className="pg-count pg-count-error">
						{errors} {errors === 1 ? "error" : "errors"}
					</span>
				) : null}
				{warnings > 0 ? (
					<span className="pg-count pg-count-warning">
						{warnings} {warnings === 1 ? "warning" : "warnings"}
					</span>
				) : null}
				{diagnostics.length === 0 ? <span className="pg-count pg-count-ok">No problems</span> : null}
			</div>

			{diagnostics.length > 0 ? (
				<ul className="pg-diagnostic-list">
					{diagnostics.map((diagnostic, index) => (
						<li key={`${diagnostic.code}-${index}`}>
							<button
								type="button"
								className="pg-diagnostic"
								onClick={() => onSelect(diagnostic)}
							>
								<span className={`pg-severity pg-severity-${diagnostic.severity}`}>
									{diagnostic.severity}
								</span>
								<code className="pg-code">{diagnostic.code}</code>
								<span className="pg-message">{diagnostic.message}</span>
								<span className="pg-where">{where(diagnostic)}</span>
							</button>
						</li>
					))}
				</ul>
			) : null}

			{hostNotes.length > 0 ? (
				<div className="pg-host-notes">
					<h3>About this browser build</h3>
					<ul>
						{hostNotes.map((note, index) => (
							<li key={`${note.code}-${index}`}>
								<code className="pg-code">{note.code}</code> {note.message}
							</li>
						))}
					</ul>
				</div>
			) : null}
		</section>
	);
};
