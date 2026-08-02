//! Peer-version check for the `zod` the consumer has installed.
//!
//! Both flavors are one npm package — `zod/mini` is a subpath of `zod` — so the check is flavor
//! blind, and the range below covers either entry point.
//!
//! Emitted zod schemas import `zod` from the project that consumes them, and the emitted runtime
//! helpers are written against zod's 4.4 issue shape. That makes an out-of-range zod a *silent*
//! defect rather than a build failure: 4.0 through 4.3 typecheck clean and then disagree with the
//! standalone validators engine on required keys nested under `not`/`if`/`then`/`else`, so the
//! generated schemas accept payloads the same document rejects through the other engine.
//!
//! A *missing* zod needs no diagnostic — `tsc` already fails with `Cannot find module 'zod'`, which
//! is louder than anything emitted here. So this checks the version and nothing else, and stays
//! silent when no `node_modules/zod` is reachable at all: generating before install and resolving
//! through Yarn PnP are both legitimate, and a check that fires spuriously in CI is worse than none.

use std::fs;
use std::path::Path;

use crate::diag::{Diagnostic, Severity};

const CODE_ZOD_PEER: &str = "OASTS0241";

/// The `zod` the emitted schemas and runtime agree with, mirroring the `zod` peer range in
/// `packages/oasts/package.json`. `scripts/zod-gate.sh` pins the two together so they cannot drift,
/// which is why the human-readable range is derived from these rather than written out beside them.
const SUPPORTED_MAJOR: u64 = 4;
const MINIMUM_MINOR: u64 = 4;

/// Renders the supported versions as the npm range a reader can act on.
fn supported_range() -> String {
    format!("^{SUPPORTED_MAJOR}.{MINIMUM_MINOR}.0")
}

/// Warns when the reachable `zod` install falls outside [`SUPPORTED_RANGE`].
///
/// `output` is the emitted-file root rather than the working directory on purpose: the emitted
/// `import * as z from "zod"` resolves relative to the file that contains it, so a monorepo
/// generating into a sibling package must be judged against that package's `node_modules`.
#[must_use]
pub fn diagnose(output: &Path) -> Option<Diagnostic> {
    let installed = installed_version(output)?;
    let (major, minor) = major_minor(&installed.version)?;
    if major == SUPPORTED_MAJOR && minor >= MINIMUM_MINOR {
        return None;
    }
    let mut diagnostic = Diagnostic::config(
        CODE_ZOD_PEER,
        format!(
            "zod {} is installed at {}, but the emitted schemas need zod {}; \
             an out-of-range zod still typechecks and then disagrees on required keys nested \
             under not/if/then/else",
            installed.version,
            installed.manifest,
            supported_range(),
        ),
    );
    diagnostic.severity = Severity::Warning;
    Some(diagnostic)
}

/// The `zod` package manifest nearest to the emitted files, and the version it declares.
struct InstalledZod {
    version: String,
    manifest: String,
}

/// Walks up from the emitted-file root for the `node_modules/zod` that Node would resolve.
///
/// `read_to_string` follows symlinks, which is what pnpm's layout needs: `node_modules/zod` there
/// is a link into the content-addressed store rather than a real directory.
fn installed_version(output: &Path) -> Option<InstalledZod> {
    for ancestor in output.ancestors() {
        let manifest = ancestor
            .join("node_modules")
            .join("zod")
            .join("package.json");
        let Ok(text) = fs::read_to_string(&manifest) else {
            continue;
        };
        let parsed = serde_json::from_str::<serde_json::Value>(&text).ok()?;
        let version = parsed.get("version")?.as_str()?.to_owned();
        return Some(InstalledZod {
            version,
            manifest: manifest.display().to_string(),
        });
    }
    None
}

/// Reads the major and minor of a semantic version, discarding any prerelease or build metadata.
fn major_minor(version: &str) -> Option<(u64, u64)> {
    let core = version.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    fn install_zod(root: &Path, version: &str) {
        let package = root.join("node_modules").join("zod");
        fs::create_dir_all(&package).expect("package directory");
        fs::write(
            package.join("package.json"),
            format!("{{\"name\":\"zod\",\"version\":\"{version}\"}}"),
        )
        .expect("package manifest");
    }

    #[test]
    fn a_supported_zod_produces_no_diagnostic() {
        let temp = tempfile::tempdir().expect("temp dir");
        install_zod(temp.path(), "4.4.3");
        assert!(diagnose(&temp.path().join("generated")).is_none());
    }

    #[test]
    fn the_lowest_supported_zod_produces_no_diagnostic() {
        let temp = tempfile::tempdir().expect("temp dir");
        install_zod(temp.path(), "4.4.0");
        assert!(diagnose(&temp.path().join("generated")).is_none());
    }

    #[test]
    fn an_older_minor_warns_and_names_the_range() {
        let temp = tempfile::tempdir().expect("temp dir");
        install_zod(temp.path(), "4.3.0");
        let diagnostic = diagnose(&temp.path().join("generated")).expect("diagnostic");
        assert_eq!(diagnostic.code, CODE_ZOD_PEER);
        assert_eq!(diagnostic.severity, Severity::Warning);
        assert!(diagnostic.message.contains("zod 4.3.0 is installed"));
        assert!(diagnostic.message.contains(&supported_range()));
    }

    #[test]
    fn a_future_major_warns_because_the_emitted_code_targets_zod_4() {
        let temp = tempfile::tempdir().expect("temp dir");
        install_zod(temp.path(), "5.0.0");
        let diagnostic = diagnose(&temp.path().join("generated")).expect("diagnostic");
        assert_eq!(diagnostic.code, CODE_ZOD_PEER);
    }

    #[test]
    fn a_prerelease_is_judged_by_its_major_and_minor() {
        let temp = tempfile::tempdir().expect("temp dir");
        install_zod(temp.path(), "4.4.0-beta.1");
        assert!(diagnose(&temp.path().join("generated")).is_none());
    }

    #[test]
    fn the_walk_finds_zod_installed_above_the_output_root() {
        let temp = tempfile::tempdir().expect("temp dir");
        install_zod(temp.path(), "4.1.0");
        let nested = temp.path().join("packages").join("api").join("generated");
        fs::create_dir_all(&nested).expect("nested output");
        assert!(diagnose(&nested).is_some());
    }

    #[test]
    fn the_nearest_install_wins_over_one_further_up() {
        let temp = tempfile::tempdir().expect("temp dir");
        install_zod(temp.path(), "4.1.0");
        let package = temp.path().join("packages").join("api");
        fs::create_dir_all(&package).expect("package directory");
        install_zod(&package, "4.4.3");
        assert!(diagnose(&package.join("generated")).is_none());
    }

    #[test]
    fn no_reachable_zod_stays_silent() {
        let temp = tempfile::tempdir().expect("temp dir");
        assert!(diagnose(&temp.path().join("generated")).is_none());
    }

    #[test]
    fn an_unreadable_version_stays_silent() {
        let temp = tempfile::tempdir().expect("temp dir");
        install_zod(temp.path(), "not-a-version");
        assert!(diagnose(&temp.path().join("generated")).is_none());
    }
}
