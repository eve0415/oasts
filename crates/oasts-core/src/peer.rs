//! Locating the peer packages a consumer has installed beside the emitted files.
//!
//! Optional artifacts import a package the application owns rather than one Oasts ships. Whether
//! the installed copy agrees with what the emitter wrote is a per-artifact judgement, so the
//! version comparison lives with each artifact; finding the install and reading its version is the
//! same walk every time and lives here.

use std::fs;
use std::path::{Path, PathBuf};

/// A peer package manifest reachable from the emitted files, and the version it declares.
pub(crate) struct InstalledPeer {
    pub(crate) version: String,
    /// The manifest the version was read from — named in the warning, and watched by `oasts watch`.
    pub(crate) manifest: PathBuf,
}

/// Walks up from the emitted-file root for the `node_modules/{package}` that Node would resolve.
///
/// The emitted-file root rather than the working directory on purpose: an emitted bare import
/// resolves relative to the file that contains it, so a monorepo generating into a sibling package
/// must be judged against that package's `node_modules`.
///
/// `read_to_string` follows symlinks, which is what pnpm's layout needs: `node_modules/{package}`
/// there is a link into the content-addressed store rather than a real directory.
pub(crate) fn installed_version(output: &Path, package: &str) -> Option<InstalledPeer> {
    for ancestor in output.ancestors() {
        let manifest = ancestor
            .join("node_modules")
            .join(package)
            .join("package.json");
        let Ok(text) = fs::read_to_string(&manifest) else {
            continue;
        };
        let parsed = serde_json::from_str::<serde_json::Value>(&text).ok()?;
        let version = parsed.get("version")?.as_str()?.to_owned();
        return Some(InstalledPeer { version, manifest });
    }
    None
}

/// Reads the major and minor of a semantic version, discarding any prerelease or build metadata.
pub(crate) fn major_minor(version: &str) -> Option<(u64, u64)> {
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
    use tempfile::TempDir;

    fn install(root: &Path, package: &str, version: &str) {
        let dir = root.join("node_modules").join(package);
        fs::create_dir_all(&dir).expect("create package dir");
        fs::write(
            dir.join("package.json"),
            format!("{{\"name\":\"{package}\",\"version\":\"{version}\"}}"),
        )
        .expect("write manifest");
    }

    #[test]
    fn the_walk_finds_an_install_above_the_output_root() {
        let temp = TempDir::new().expect("temp dir");
        install(temp.path(), "msw", "2.15.0");
        let output = temp.path().join("packages").join("app").join("generated");
        fs::create_dir_all(&output).expect("create output");
        let found = installed_version(&output, "msw").expect("install is reachable");
        assert_eq!(found.version, "2.15.0");
    }

    #[test]
    fn the_nearest_install_wins_over_one_further_up() {
        let temp = TempDir::new().expect("temp dir");
        install(temp.path(), "msw", "2.8.0");
        let nested = temp.path().join("packages").join("app");
        fs::create_dir_all(&nested).expect("create nested");
        install(&nested, "msw", "2.15.0");
        let output = nested.join("generated");
        fs::create_dir_all(&output).expect("create output");
        assert_eq!(
            installed_version(&output, "msw")
                .expect("install is reachable")
                .version,
            "2.15.0"
        );
    }

    #[test]
    fn an_absent_install_is_not_an_error() {
        let temp = TempDir::new().expect("temp dir");
        assert!(installed_version(temp.path(), "msw").is_none());
    }

    #[test]
    fn prerelease_and_build_metadata_are_discarded() {
        assert_eq!(major_minor("2.15.0"), Some((2, 15)));
        assert_eq!(major_minor("2.8.0-rc.1"), Some((2, 8)));
        assert_eq!(major_minor("2.9.0+build.7"), Some((2, 9)));
        assert_eq!(major_minor("not-a-version"), None);
        assert_eq!(major_minor("2"), None);
    }
}
