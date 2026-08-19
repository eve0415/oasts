declare namespace App {
	interface Locals {
		/**
		 * Per-render counters keyed by component, so two blocks with identical props
		 * still get distinct ids. Lives on locals because it must reset per page and
		 * stay stable within a render — incremental builds have to match cold ones.
		 */
		__nbCounters?: Map<string, number>;
	}
}
