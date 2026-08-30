# oasts

OpenAPI 3.0/3.1 → TypeScript compiler. Rust core in `crates/`, Node packaging via napi in `packages/oasts`.

- pnpm only. `npm` and `npx` are blocked here.
- Generated files are gitignored and absent on a fresh checkout. Bootstrap in order: `pnpm install --frozen-lockfile`, then `cargo run -p oasts-gen`, then `pnpm -C packages/oasts build:napi`, then `pnpm -C packages/oasts build`.
- Done means every `scripts/*.sh` gate is green. `scripts/verify-ts.sh` needs `cargo build` first. `scripts/playground-wasm.sh` is not a gate: it publishes the browser compiler, seeding the local bucket unless given `--remote`, and needs `pnpm -C www build` first. Run `scripts/gate.sh` (rustfmt + clippy + oxfmt + oxlint) before handing work back.
- Deterministic output is contractual: never run a formatter over generator output (`fixtures/*/generated*`, emitted code), and generating twice must be byte-identical. Repo source — including the embedded runtime TS under `crates/oasts-core/runtime/` — is formatted as usual; the gates enforce it.
- Rust is formatted with `cargo fmt` and linted with `cargo clippy --workspace --all-targets -- -D warnings`. TypeScript under `packages/oasts` and `crates/oasts-core/runtime` uses `pnpm exec oxfmt` and `pnpm exec oxlint`.
- Diagnostics are `OASTS<NNNN>` codes. Exit codes are categorical: 0 success, 1 input/semantic diagnostics, 2 configuration/I-O/internal failure.
- Never escape the type system: no `any`, no unchecked casts, no `unwrap` on external input.
- Conventional commits, tiny and atomic, one concern each.
