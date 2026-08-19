import { useRef, type ReactNode } from "react";

/**
 * The ARIA tabs pattern, with the keyboard map that makes it one: arrows move between tabs,
 * Home and End jump to the ends, and only the selected tab is in the tab sequence.
 */

export interface TabDefinition {
	id: string;
	label: ReactNode;
	/** Announced instead of the visible label when the label carries a badge. */
	accessibleName?: string;
}

export interface TabsProps {
	label: string;
	tabs: TabDefinition[];
	active: string;
	onSelect: (id: string) => void;
}

export const Tabs = ({ label, tabs, active, onSelect }: TabsProps) => {
	const refs = useRef(new Map<string, HTMLButtonElement>());

	const focus = (id: string) => {
		onSelect(id);
		refs.current.get(id)?.focus();
	};

	const onKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>, index: number) => {
		const last = tabs.length - 1;
		const target =
			event.key === "ArrowRight"
				? tabs[index === last ? 0 : index + 1]
				: event.key === "ArrowLeft"
					? tabs[index === 0 ? last : index - 1]
					: event.key === "Home"
						? tabs[0]
						: event.key === "End"
							? tabs[last]
							: undefined;
		if (!target) return;
		event.preventDefault();
		focus(target.id);
	};

	return (
		<div role="tablist" aria-label={label} className="pg-tablist">
			{tabs.map((tab, index) => (
				<button
					key={tab.id}
					type="button"
					role="tab"
					id={`pg-tab-${tab.id}`}
					aria-selected={tab.id === active}
					aria-controls={`pg-panel-${tab.id}`}
					aria-label={tab.accessibleName}
					tabIndex={tab.id === active ? 0 : -1}
					className="pg-tab"
					ref={(node) => {
						if (node) refs.current.set(tab.id, node);
						else refs.current.delete(tab.id);
					}}
					onClick={() => onSelect(tab.id)}
					onKeyDown={(event) => onKeyDown(event, index)}
				>
					{tab.label}
				</button>
			))}
		</div>
	);
};
