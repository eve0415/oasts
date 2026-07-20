# oasts

OpenAPI 3.0/3.1 → TypeScript compiler. Rust core in `crates/`, Node packaging via napi in `packages/oasts`.

- pnpm only. npm and npx are blocked here (devEngines pin, plus deny rules in `.claude/settings.json`).
- Generated files are gitignored and absent on a fresh checkout. Bootstrap in order: `pnpm install --frozen-lockfile`, then `cargo run -p oasts-gen`, then `pnpm -C packages/oasts build:napi`, then `pnpm -C packages/oasts build`.
- Done means every `scripts/*.sh` gate is green. `scripts/verify-ts.sh` needs `cargo build` first.
- Deterministic output is contractual: never run a formatter over generator output (`fixtures/*/generated*`, emitted code), and generating twice must be byte-identical. Repo source — including the embedded runtime TS under `crates/oasts-core/runtime/` — is formatted as usual; the gates enforce it.
- Feature branches squash-merge to main and their granular history is discarded — check main's log before assuming work is missing.
