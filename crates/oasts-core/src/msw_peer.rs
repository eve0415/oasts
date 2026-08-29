//! Peer-version check for the `msw` the consumer has installed.
//!
//! Emitted handlers import `msw` from the project that consumes them, and they are written against
//! the generic `HttpResponse<Body>` that arrived in 2.8 — supplying that type argument is the only
//! thing that makes MSW check a resolver's response body against the document.
//!
//! Below the supported range the emitted code does not compile at all, and `tsc` says so more
//! clearly than anything emitted here could. The case this check exists for is the opposite one: a
//! newer major, where the handlers may well typecheck and then behave differently, because MSW's
//! public TypeScript surface has changed inside 2.x before — `StrictResponse` was removed in 2.8
//! and reinstated as an alias in 2.9.
//!
//! It stays silent when no `node_modules/msw` is reachable at all: generating before install and
//! resolving through Yarn PnP are both legitimate, and a check that fires spuriously in CI is worse
//! than none.

use std::path::Path;

use crate::diag::{Diagnostic, Severity};
use crate::inputs::InputRecorder;
use crate::peer::{installed_version, major_minor};

const CODE_MSW_PEER: &str = "OASTS0242";

/// The `msw` the emitted handlers agree with, mirroring the `msw` peer range in
/// `packages/oasts/package.json`. `scripts/msw-gate.sh` pins the two together so they cannot drift,
/// which is why the human-readable range is derived from these rather than written out beside them.
const SUPPORTED_MAJOR: u64 = 2;
const MINIMUM_MINOR: u64 = 8;

/// Renders the supported versions as the npm range a reader can act on.
fn supported_range() -> String {
    format!("^{SUPPORTED_MAJOR}.{MINIMUM_MINOR}.0")
}

/// Warns when the reachable `msw` install falls outside the supported range.
#[must_use]
pub fn diagnose(output: &Path, inputs: &mut InputRecorder) -> Option<Diagnostic> {
    let installed = installed_version(output, "msw")?;
    // Only the manifest that answered. The ancestors that had no install were probed too, but
    // watching every `node_modules` above the output tree to catch an install appearing would
    // cost far more than the warning it could refresh.
    inputs.record(&installed.manifest);
    let (major, minor) = major_minor(&installed.version)?;
    if major == SUPPORTED_MAJOR && minor >= MINIMUM_MINOR {
        return None;
    }
    let mut diagnostic = Diagnostic::config(
        CODE_MSW_PEER,
        format!(
            "msw {} is installed at {}, but the emitted handlers are written against msw {}",
            installed.version,
            installed.manifest.display(),
            supported_range(),
        ),
    );
    diagnostic.severity = Severity::Warning;
    Some(diagnostic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn project_with_installed_msw(version: &str) -> TempDir {
        let temp = TempDir::new().expect("temp dir");
        let dir = temp.path().join("node_modules").join("msw");
        fs::create_dir_all(&dir).expect("create package dir");
        fs::write(
            dir.join("package.json"),
            format!("{{\"name\":\"msw\",\"version\":\"{version}\"}}"),
        )
        .expect("write manifest");
        temp
    }

    #[test]
    fn a_supported_install_is_silent() {
        for version in ["2.8.0", "2.9.0", "2.15.0", "2.15.3-rc.1"] {
            let temp = project_with_installed_msw(version);
            assert!(
                diagnose(temp.path(), &mut InputRecorder::off()).is_none(),
                "msw {version} should be accepted"
            );
        }
    }

    #[test]
    fn an_older_minor_warns() {
        let temp = project_with_installed_msw("2.7.6");
        let diagnostic = diagnose(temp.path(), &mut InputRecorder::off())
            .expect("2.7.6 predates the generic response type");
        assert_eq!(diagnostic.code, CODE_MSW_PEER);
        assert_eq!(diagnostic.severity, Severity::Warning);
        assert!(diagnostic.message.contains("^2.8.0"));
    }

    #[test]
    fn an_untested_major_warns() {
        let temp = project_with_installed_msw("3.0.0");
        let diagnostic =
            diagnose(temp.path(), &mut InputRecorder::off()).expect("a newer major is untested");
        assert_eq!(diagnostic.code, CODE_MSW_PEER);
    }

    #[test]
    fn no_install_is_silent() {
        let temp = TempDir::new().expect("temp dir");
        assert!(diagnose(temp.path(), &mut InputRecorder::off()).is_none());
    }

    #[test]
    fn an_unparseable_version_is_silent() {
        let temp = project_with_installed_msw("nightly");
        assert!(diagnose(temp.path(), &mut InputRecorder::off()).is_none());
    }
}
