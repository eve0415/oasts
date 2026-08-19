import { useId, useMemo, useState } from "react";
import type { ConfigSchema, Field } from "../config/schema";
import { readAt, writeAt } from "../config/yaml";
import type { Diagnostic } from "../types";

/**
 * The options form and the YAML editor edit one document. Every control writes through the YAML
 * AST, so toggling a checkbox keeps comments, key order and formatting intact.
 *
 * Controls show the value that is SET, not the value in force: a field left alone stays absent
 * from the file, and its default is shown beside it. That distinction is the whole reason the
 * generated config and a hand-written one stay interchangeable.
 */

export interface OptionsFormProps {
	schema: ConfigSchema;
	config: string;
	diagnostics: Diagnostic[];
	onChange: (next: string) => void;
}

const describeDefault = (field: Field): string | null => {
	if (field.default === undefined) return null;
	if (typeof field.default === "boolean") return field.default ? "on" : "off";
	if (Array.isArray(field.default)) return field.default.length === 0 ? "empty" : null;
	if (typeof field.default === "object") return null;
	return String(field.default);
};

/** Diagnostics whose pointer names this field, so a refusal is shown at the control it is about. */
const pointerFor = (field: Field): string => `/${field.segments.join("/")}`;

export const OptionsForm = ({ schema, config, diagnostics, onChange }: OptionsFormProps) => {
	const [query, setQuery] = useState("");
	const searchId = useId();

	const problems = useMemo(() => {
		const byPointer = new Map<string, Diagnostic>();
		for (const diagnostic of diagnostics) {
			if (diagnostic.jsonPointer) byPointer.set(diagnostic.jsonPointer, diagnostic);
		}
		return byPointer;
	}, [diagnostics]);

	const sections = useMemo(() => {
		const needle = query.trim().toLowerCase();
		if (needle === "") return schema.sections;
		return schema.sections
			.map((section) => ({
				...section,
				fields: section.fields.filter(
					(field) =>
						field.path.toLowerCase().includes(needle) ||
						(field.description ?? "").toLowerCase().includes(needle),
				),
			}))
			.filter((section) => section.fields.length > 0);
	}, [schema.sections, query]);

	const setValue = (field: Field, value: unknown) => {
		onChange(writeAt(config, field.segments, value));
	};

	const total = schema.sections.reduce((count, section) => count + section.fields.length, 0);

	return (
		<div className="pg-options">
			<div className="pg-options-search">
				<label htmlFor={searchId} className="pg-visually-hidden">
					Search options
				</label>
				<input
					id={searchId}
					type="search"
					className="pg-input"
					placeholder={`Search ${total} options`}
					value={query}
					onChange={(event) => setQuery(event.target.value)}
					autoComplete="off"
					spellCheck={false}
				/>
			</div>

			<div className="pg-options-body">
				{sections.length === 0 ? (
					<p className="pg-empty-note">No option matches “{query}”.</p>
				) : (
					sections.map((section) => (
						<fieldset key={section.key} className="pg-fieldset">
							<legend className="pg-legend">{section.key}</legend>
							{section.description ? (
								<p className="pg-section-note">{section.description}</p>
							) : null}

							{section.fields.map((field) => {
								const current = readAt(config, field.segments);
								const isSet = current !== undefined && current !== null;
								const problem = problems.get(pointerFor(field));
								const fallback = describeDefault(field);
								const describedBy = [
									field.description ? `${field.path}-note` : null,
									problem ? `${field.path}-problem` : null,
								]
									.filter((id): id is string => id !== null)
									.join(" ");

								return (
									<div
										key={field.path}
										className={`pg-field${problem ? " pg-field-problem" : ""}`}
									>
										{field.kind === "boolean" ? (
											<label className="pg-check">
												<input
													type="checkbox"
													checked={current === true}
													aria-describedby={describedBy || undefined}
													onChange={(event) =>
														setValue(field, event.target.checked ? true : undefined)
													}
												/>
												<span className="pg-field-name">{field.path}</span>
											</label>
										) : (
											<>
												<label className="pg-field-name" htmlFor={`f-${field.path}`}>
													{field.path}
												</label>
												{field.kind === "enum" ? (
													<select
														id={`f-${field.path}`}
														className="pg-input pg-select"
														value={typeof current === "string" ? current : ""}
														aria-describedby={describedBy || undefined}
														onChange={(event) =>
															setValue(
																field,
																event.target.value === "" ? undefined : event.target.value,
															)
														}
													>
														<option value="">
															{fallback === null ? "not set" : `not set (${fallback})`}
														</option>
														{field.options.map((option) => (
															<option key={option} value={option}>
																{option}
															</option>
														))}
													</select>
												) : (
													<input
														id={`f-${field.path}`}
														type={field.kind === "number" ? "number" : "text"}
														inputMode={field.kind === "number" ? "numeric" : undefined}
														className="pg-input"
														value={
															typeof current === "string" || typeof current === "number"
																? String(current)
																: ""
														}
														placeholder={fallback ?? "not set"}
														aria-describedby={describedBy || undefined}
														onChange={(event) => {
															const raw = event.target.value;
															if (raw === "") return setValue(field, undefined);
															if (field.kind === "number") {
																const parsed = Number(raw);
																return setValue(field, Number.isFinite(parsed) ? parsed : raw);
															}
															return setValue(field, raw);
														}}
													/>
												)}
											</>
										)}

										{isSet ? <span className="pg-badge">set</span> : null}

										{field.description ? (
											<p id={`${field.path}-note`} className="pg-field-note">
												{field.description}
												{fallback === null ? null : (
													<span className="pg-default"> Default: {fallback}.</span>
												)}
											</p>
										) : null}

										{problem ? (
											<p id={`${field.path}-problem`} className="pg-field-error">
												<code>{problem.code}</code> {problem.message}
											</p>
										) : null}
									</div>
								);
							})}
						</fieldset>
					))
				)}
			</div>
		</div>
	);
};
