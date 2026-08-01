// The compiler is allocation-bound — a GitHub-scale spec makes roughly two million allocations
// across load, parse and emit — so the CLI binary carries its own allocator rather than taking
// whatever the platform provides. Scoped to the binary: `oasts-core` stays allocator-neutral so
// the Node binding keeps the host process's allocator.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[rustfmt::skip]
fn main() -> std::process::ExitCode { oasts::cli::run_from_env() }
