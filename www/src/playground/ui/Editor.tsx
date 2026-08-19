import { useEffect, useEffectEvent, useRef, useState } from "react";
import { Compartment, EditorState, StateEffect, StateField, type Extension } from "@codemirror/state";
import {
	Decoration,
	EditorView,
	drawSelection,
	highlightActiveLine,
	highlightActiveLineGutter,
	keymap,
	lineNumbers,
	type DecorationSet,
} from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { yaml } from "@codemirror/lang-yaml";
import { javascript } from "@codemirror/lang-javascript";
import { tags } from "@lezer/highlight";

/**
 * One editor for both panes. Extensions are composed by hand rather than pulling `basic-setup`,
 * which drags in search, folding, autocompletion and lint UI that this never uses.
 *
 * Colours come from the site's own CSS custom properties, so the editor follows the docs theme
 * without a second theme system or a re-render on toggle.
 */

export interface Marker {
	from: number;
	to: number;
	severity: "error" | "warning";
}

const setMarkers = StateEffect.define<Marker[]>();

const NO_MARKERS: Marker[] = [];

const markerField = StateField.define<DecorationSet>({
	create: () => Decoration.none,
	update(value, transaction) {
		let next = value.map(transaction.changes);
		for (const effect of transaction.effects) {
			if (!effect.is(setMarkers)) continue;
			const length = transaction.state.doc.length;
			next = Decoration.set(
				effect.value
					.filter((marker) => marker.from < marker.to && marker.to <= length)
					.map((marker) =>
						Decoration.mark({ class: `pg-squiggle pg-squiggle-${marker.severity}` }).range(
							marker.from,
							marker.to,
						),
					),
				true,
			);
		}
		return next;
	},
	provide: (field) => EditorView.decorations.from(field),
});

const highlight = HighlightStyle.define([
	{ tag: [tags.comment], color: "var(--pg-comment)", fontStyle: "italic" },
	{ tag: [tags.keyword, tags.modifier, tags.moduleKeyword], color: "var(--pg-keyword)" },
	{ tag: [tags.string, tags.special(tags.string)], color: "var(--pg-string)" },
	{ tag: [tags.number, tags.bool, tags.null], color: "var(--pg-number)" },
	{ tag: [tags.typeName, tags.className, tags.definition(tags.typeName)], color: "var(--pg-type)" },
	{ tag: [tags.propertyName, tags.definition(tags.propertyName)], color: "var(--pg-property)" },
	{ tag: [tags.punctuation, tags.separator, tags.bracket], color: "var(--pg-punct)" },
	{ tag: [tags.operator], color: "var(--pg-punct)" },
]);

const theme = EditorView.theme({
	"&": {
		height: "100%",
		fontSize: "12.5px",
		backgroundColor: "var(--nb-card)",
		color: "var(--nb-foreground)",
	},
	".cm-scroller": {
		fontFamily: "var(--nb-font-mono)",
		lineHeight: "1.65",
		overflow: "auto",
	},
	".cm-gutters": {
		backgroundColor: "var(--nb-card)",
		color: "var(--nb-muted-foreground)",
		border: "none",
		borderRight: "1px solid var(--nb-border)",
	},
	".cm-activeLineGutter": { backgroundColor: "var(--nb-muted)" },
	".cm-activeLine": { backgroundColor: "color-mix(in oklch, var(--nb-muted) 60%, transparent)" },
	".cm-content": { padding: "12px 0", caretColor: "var(--nb-foreground)" },
	"&.cm-focused": { outline: "2px solid var(--nb-ring)", outlineOffset: "-2px" },
	".cm-selectionBackground, ::selection": {
		backgroundColor: "color-mix(in oklch, var(--nb-primary) 14%, transparent)",
	},
	".cm-cursor": { borderLeftColor: "var(--nb-foreground)" },
});

export interface EditorProps {
	value: string;
	language: "yaml" | "typescript";
	readOnly?: boolean;
	markers?: Marker[];
	onChange?: (value: string) => void;
	ariaLabel: string;
	/** Soft-wrap long lines. Off means the editor scrolls horizontally, as an IDE does. */
	wrap?: boolean;
}

export const Editor = ({
	value,
	language,
	readOnly = false,
	markers = NO_MARKERS,
	onChange,
	ariaLabel,
	wrap = true,
}: EditorProps) => {
	const host = useRef<HTMLDivElement | null>(null);
	const view = useRef<EditorView | null>(null);
	// The document the editor is created with. Later changes arrive through the sync effect
	// below, so `value` must not rebuild the editor.
	const [initialDoc] = useState(() => value);
	// Wrapping is reconfigured rather than rebuilt, so toggling it keeps scroll and selection.
	const [wrapping] = useState(() => new Compartment());
	// Reads the latest handler without making the editor reactive to it.
	const emitChange = useEffectEvent((next: string) => {
		onChange?.(next);
	});

	useEffect(() => {
		if (!host.current) return;

		const extensions: Extension[] = [
			lineNumbers(),
			history(),
			drawSelection(),
			highlightActiveLine(),
			highlightActiveLineGutter(),
			keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
			syntaxHighlighting(highlight),
			markerField,
			theme,
			wrapping.of([]),
			// contenteditable alone leaves the content at tabIndex -1, so the scrolling region has
			// no keyboard route into it — worst for the read-only pane, which cannot be scrolled
			// any other way.
			EditorView.contentAttributes.of(
				readOnly
					? { "aria-label": ariaLabel, "aria-readonly": "true", tabindex: "0" }
					: { "aria-label": ariaLabel, tabindex: "0" },
			),
			language === "yaml" ? yaml() : javascript({ typescript: true }),
			EditorState.readOnly.of(readOnly),
			EditorView.updateListener.of((update) => {
				if (update.docChanged) emitChange(update.state.doc.toString());
			}),
		];

		const instance = new EditorView({
			state: EditorState.create({ doc: initialDoc, extensions }),
			parent: host.current,
		});
		view.current = instance;

		return () => {
			instance.destroy();
		};
	}, [language, readOnly, ariaLabel, initialDoc, wrapping]);

	// Replace the document only when it genuinely differs, so typing is never interrupted and
	// the cursor does not jump on a round-trip through shared state.
	useEffect(() => {
		const instance = view.current;
		if (!instance) return;
		const current = instance.state.doc.toString();
		if (current === value) return;
		instance.dispatch({ changes: { from: 0, to: current.length, insert: value } });
	}, [value]);

	useEffect(() => {
		view.current?.dispatch({ effects: setMarkers.of(markers) });
	}, [markers]);

	useEffect(() => {
		view.current?.dispatch({
			effects: wrapping.reconfigure(wrap ? EditorView.lineWrapping : []),
		});
	}, [wrap, wrapping]);

	return <div ref={host} className="pg-editor" />;
};
