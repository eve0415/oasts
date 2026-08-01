//! Corpus fetch, conformance, and benchmark harness for the oasts generator.
//!
//! This crate is a measurement tool: its correctness gates are its own unit tests, and its
//! process-spawning pipeline is exercised by running the harness itself rather than by line
//! coverage (see `scripts/coverage.sh`).
//!
//! CPU profiles use release-equivalent code with symbols and forced frame pointers (needed for
//! reliable aarch64 unwinding): `RUSTFLAGS="-Cforce-frame-pointers=yes" cargo run --profile
//! profiling -p oasts-bench --features cpu-profile --bin oasts-cpu-profile -- github-3.0`. Pass
//! `stripe-3.0` for Stripe; SVGs default to `target/profiles/<fixture>-cpu.svg`. Heap profiles use
//! `cargo run --profile profiling -p oasts-bench --features heap-profile --bin oasts-heap-profile
//! -- github-3.0`; the command prints peak heap totals and the leading sites by bytes live at the
//! global peak and by allocation call count, and writes `target/profiles/github-3.0-heap.json` for
//! <https://nnethercote.github.io/dh_view/dh_view.html>.

pub mod alloc_track;
pub mod conformance;
pub mod fetch;
pub mod manifest;
pub mod results;
pub mod run;
pub mod sample;

#[cfg(any(feature = "cpu-profile", feature = "heap-profile"))]
pub mod profile;

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// The workspace root, resolved from this crate's compile-time location (`crates/oasts-bench`).
///
/// The harness reads `bench/manifest.yaml`, the committed fixtures, and the release binary relative
/// to this root, so it must run against the same checkout it was built from.
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate is nested two levels under the workspace root")
        .to_path_buf()
}

/// A descriptive harness error carrying a human-readable message.
///
/// The harness runs against user-supplied manifests, fixtures, and network resources, so every
/// failure names what went wrong and where — never a bare `unwrap` panic on external input.
#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    /// Builds an error from any displayable message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::new(error.to_string())
    }
}

/// Stages a pristine fixture into a fresh workdir, skipping any top-level `generated*` entry.
///
/// The pipeline copies a fixture into a temp workdir before generating so the source tree is never
/// mutated and each key measures from the same starting bytes. A developer who ran the CLI inside
/// `fixtures/<name>/` leaves gitignored `generated*` scratch trees there; copied verbatim they would
/// count into outputBytes/outputFiles, feed the tsc gate, and could false-pass double generation. So
/// every top-level entry whose name starts with `generated` is skipped, and the staged workdir is
/// checked to hold none before it is used — a hard error rather than a debug assertion, because the
/// harness runs release builds where `debug_assert!` is compiled out.
pub(crate) fn copy_fixture(source: &Path, destination: &Path) -> io::Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if is_generated(&name) {
            continue;
        }
        let target = destination.join(&name);
        if entry.file_type()?.is_dir() {
            copy_dir_all(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    ensure_no_generated(destination)?;
    Ok(())
}

/// Whether a directory entry name is a `generated*` scratch tree.
fn is_generated(name: &std::ffi::OsStr) -> bool {
    name.to_string_lossy().starts_with("generated")
}

/// Fails if any top-level `generated*` entry survived staging, so a stale scratch tree can never be
/// measured as fixture output.
fn ensure_no_generated(directory: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if is_generated(&entry.file_name()) {
            return Err(io::Error::other(format!(
                "staged workdir unexpectedly contains a generated entry: {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

/// Recursively copies `source`'s contents into `destination`, creating directories as needed.
pub(crate) fn copy_dir_all(source: &Path, destination: &Path) -> io::Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_fixture_skips_stale_generated_trees() {
        let source = tempfile::tempdir().expect("source");
        let root = source.path();
        std::fs::write(root.join("openapi.yaml"), b"openapi: 3.0.0\n").expect("spec");
        std::fs::write(root.join("oasts.yaml"), b"schemaVersion: 1\n").expect("config");
        std::fs::create_dir_all(root.join("generated/types")).expect("stale types");
        std::fs::write(
            root.join("generated/types/pet.ts"),
            b"export type Pet = {};\n",
        )
        .expect("stale ts");
        std::fs::create_dir_all(root.join("generated-client")).expect("stale client");
        std::fs::write(
            root.join("generated-client/client.ts"),
            b"export const c = 1;\n",
        )
        .expect("stale client ts");

        let destination = tempfile::tempdir().expect("destination");
        copy_fixture(root, destination.path()).expect("stage fixture");

        assert!(destination.path().join("openapi.yaml").is_file());
        assert!(destination.path().join("oasts.yaml").is_file());
        assert!(!destination.path().join("generated").exists());
        assert!(!destination.path().join("generated-client").exists());
    }

    #[test]
    fn ensure_no_generated_flags_a_leaked_tree() {
        let directory = tempfile::tempdir().expect("dir");
        std::fs::create_dir_all(directory.path().join("generated")).expect("leaked tree");
        let error = ensure_no_generated(directory.path()).expect_err("leak rejected");
        assert!(error.to_string().contains("generated"), "{error}");
    }
}
