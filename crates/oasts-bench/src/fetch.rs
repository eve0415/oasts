//! Corpus spec fetch with SHA-256 digest verification.
//!
//! Fetched specs are pinned by URL and digest in the manifest; a spec already on disk with the
//! pinned digest is left untouched. Downloads land in a temp file in the target directory and are
//! renamed into place only after the digest verifies, so the tree never holds a partial or wrong
//! file. Digest-and-rename logic is isolated behind the [`Fetcher`] trait so it is unit-testable
//! without a network.

use std::io::Write;
use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::Error;
use crate::manifest::{FixtureEntry, FixtureSource, Manifest, SpecSource};

/// Fetches a URL to a destination path.
pub trait Fetcher {
    /// Downloads `url` into `destination`, overwriting it. Returns an error on any transport failure.
    fn fetch(&self, url: &str, destination: &Path) -> Result<(), Error>;
}

/// The production fetcher: shells out to `curl`, which the runner image pins, so the harness adds no
/// TLS-client dependency.
pub struct CurlFetcher;

impl Fetcher for CurlFetcher {
    fn fetch(&self, url: &str, destination: &Path) -> Result<(), Error> {
        // `--` ends option parsing so the URL is always a single positional argument, never a flag.
        let status = Command::new("curl")
            .arg("-fsSL")
            .arg("--retry")
            .arg("3")
            .arg("-o")
            .arg(destination)
            .arg("--")
            .arg(url)
            .status()
            .map_err(|error| Error::new(format!("spawning curl for {url}: {error}")))?;
        if !status.success() {
            return Err(Error::new(format!("curl failed for {url} ({status})")));
        }
        Ok(())
    }
}

/// Whether a fixture's spec was already present or freshly downloaded.
#[derive(Debug)]
enum FetchStatus {
    Verified,
    Downloaded,
}

/// Fetches and verifies every fetched-spec fixture in the manifest.
///
/// Every fixture is attempted even when an earlier one fails; the returned error aggregates all
/// failures so the caller can exit nonzero. Verified/downloaded progress is written to `out`.
pub fn fetch_all(
    manifest: &Manifest,
    workspace_root: &Path,
    fetcher: &dyn Fetcher,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let fixtures_root = workspace_root.join("fixtures");
    let mut failures = Vec::new();
    for fixture in &manifest.fixtures {
        let FixtureSource::Spec(spec) = &fixture.source else {
            continue;
        };
        match fetch_one(fixture, spec, &fixtures_root, fetcher) {
            Ok(FetchStatus::Verified) => {
                let _ = writeln!(out, "verified: {}", fixture.name);
            }
            Ok(FetchStatus::Downloaded) => {
                let _ = writeln!(out, "downloaded: {}", fixture.name);
            }
            Err(error) => {
                let _ = writeln!(out, "FAILED: {} — {error}", fixture.name);
                failures.push(fixture.name.clone());
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Error::new(format!(
            "fetch failed for {} fixture(s): {}",
            failures.len(),
            failures.join(", ")
        )))
    }
}

fn fetch_one(
    fixture: &FixtureEntry,
    spec: &SpecSource,
    fixtures_root: &Path,
    fetcher: &dyn Fetcher,
) -> Result<FetchStatus, Error> {
    // `fixture.dir` and `spec.path` are validated relative at manifest load, so both joins stay
    // inside `fixtures/`.
    let directory = fixtures_root.join(&fixture.dir);
    let target = directory.join(&spec.path);

    if target.exists() && sha256_hex(&target)?.eq_ignore_ascii_case(&spec.sha256) {
        return Ok(FetchStatus::Verified);
    }

    std::fs::create_dir_all(&directory)
        .map_err(|error| Error::new(format!("creating {}: {error}", directory.display())))?;
    let temp = NamedTempFile::new_in(&directory).map_err(|error| {
        Error::new(format!(
            "creating temp file in {}: {error}",
            directory.display()
        ))
    })?;

    fetcher.fetch(&spec.url, temp.path())?;

    let actual = sha256_hex(temp.path())?;
    if !actual.eq_ignore_ascii_case(&spec.sha256) {
        // Dropping `temp` deletes the wrong file; the target tree is left untouched.
        return Err(Error::new(format!(
            "digest mismatch: expected {}, got {actual}",
            spec.sha256
        )));
    }

    temp.persist(&target)
        .map_err(|error| Error::new(format!("persisting {}: {error}", target.display())))?;
    Ok(FetchStatus::Downloaded)
}

fn sha256_hex(path: &Path) -> Result<String, Error> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| Error::new(format!("opening {}: {error}", path.display())))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)
        .map_err(|error| Error::new(format!("hashing {}: {error}", path.display())))?;
    Ok(to_hex(&hasher.finalize()))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn digest_of(bytes: &[u8]) -> String {
        to_hex(&Sha256::digest(bytes))
    }

    fn spec_fixture(dir: &str, path: &str, url: &str, sha256: &str) -> FixtureEntry {
        FixtureEntry {
            name: "test".to_owned(),
            class: crate::manifest::Class::Small,
            config: "oasts.yaml".to_owned(),
            dir: dir.to_owned(),
            source: FixtureSource::Spec(SpecSource {
                path: path.to_owned(),
                url: url.to_owned(),
                sha256: sha256.to_owned(),
            }),
        }
    }

    struct BytesFetcher {
        bytes: Vec<u8>,
        called: Cell<bool>,
    }

    impl Fetcher for BytesFetcher {
        fn fetch(&self, _url: &str, destination: &Path) -> Result<(), Error> {
            self.called.set(true);
            std::fs::write(destination, &self.bytes)?;
            Ok(())
        }
    }

    struct PanicFetcher;

    impl Fetcher for PanicFetcher {
        fn fetch(&self, _url: &str, _destination: &Path) -> Result<(), Error> {
            panic!("fetcher must not be called when the spec is already present");
        }
    }

    fn source(fixture: &FixtureEntry) -> &SpecSource {
        match &fixture.source {
            FixtureSource::Spec(spec) => spec,
            FixtureSource::Committed => unreachable!("test fixtures carry a spec"),
        }
    }

    #[test]
    fn matching_digest_downloads_and_persists() {
        let root = tempfile::tempdir().expect("tempdir");
        let bytes = b"openapi document bytes\n".to_vec();
        let fixture = spec_fixture(
            "corpus",
            "openapi.json",
            "https://ignored",
            &digest_of(&bytes),
        );
        let fetcher = BytesFetcher {
            bytes: bytes.clone(),
            called: Cell::new(false),
        };

        let status = fetch_one(&fixture, source(&fixture), root.path(), &fetcher)
            .expect("download succeeds");

        assert!(matches!(status, FetchStatus::Downloaded));
        assert!(fetcher.called.get());
        let target = root.path().join("corpus/openapi.json");
        assert_eq!(std::fs::read(&target).expect("target bytes"), bytes);
    }

    #[test]
    fn digest_mismatch_fails_and_leaves_no_file() {
        let root = tempfile::tempdir().expect("tempdir");
        let fixture = spec_fixture(
            "corpus",
            "openapi.json",
            "https://ignored",
            &digest_of(b"real"),
        );
        let fetcher = BytesFetcher {
            bytes: b"tampered".to_vec(),
            called: Cell::new(false),
        };

        let error = fetch_one(&fixture, source(&fixture), root.path(), &fetcher)
            .expect_err("digest mismatch rejected");

        assert!(error.to_string().contains("digest mismatch"), "{error}");
        let directory = root.path().join("corpus");
        assert!(!directory.join("openapi.json").exists());
        let leftovers: Vec<_> = std::fs::read_dir(&directory)
            .expect("read corpus dir")
            .collect();
        assert!(leftovers.is_empty(), "temp file should be cleaned up");
    }

    #[test]
    fn present_and_matching_spec_is_skipped_without_fetching() {
        let root = tempfile::tempdir().expect("tempdir");
        let bytes = b"already here\n";
        let directory = root.path().join("corpus");
        std::fs::create_dir_all(&directory).expect("create dir");
        std::fs::write(directory.join("openapi.json"), bytes).expect("seed target");
        let fixture = spec_fixture(
            "corpus",
            "openapi.json",
            "https://ignored",
            &digest_of(bytes),
        );

        let status = fetch_one(&fixture, source(&fixture), root.path(), &PanicFetcher)
            .expect("present spec verifies");

        assert!(matches!(status, FetchStatus::Verified));
    }

    #[test]
    fn present_but_wrong_digest_is_redownloaded() {
        let root = tempfile::tempdir().expect("tempdir");
        let directory = root.path().join("corpus");
        std::fs::create_dir_all(&directory).expect("create dir");
        std::fs::write(directory.join("openapi.json"), b"stale").expect("seed stale");
        let fresh = b"fresh document\n".to_vec();
        let fixture = spec_fixture(
            "corpus",
            "openapi.json",
            "https://ignored",
            &digest_of(&fresh),
        );
        let fetcher = BytesFetcher {
            bytes: fresh.clone(),
            called: Cell::new(false),
        };

        let status = fetch_one(&fixture, source(&fixture), root.path(), &fetcher)
            .expect("stale file is replaced");

        assert!(matches!(status, FetchStatus::Downloaded));
        assert!(fetcher.called.get());
        assert_eq!(
            std::fs::read(directory.join("openapi.json")).expect("target"),
            fresh
        );
    }

    #[test]
    fn fetch_all_reports_aggregated_failure_without_stopping() {
        let root = tempfile::tempdir().expect("tempdir");
        let good_bytes = b"good document\n".to_vec();
        // The fetcher writes `good_bytes` for every URL, so `good` verifies and `bad` (which pins a
        // different digest) fails — proving one failure does not stop the rest.
        let manifest_yaml = format!(
            concat!(
                "fixtures:\n",
                "  - name: good\n",
                "    class: small\n",
                "    config: oasts.yaml\n",
                "    spec:\n",
                "      path: openapi.json\n",
                "      url: https://ignored\n",
                "      sha256: {good}\n",
                "  - name: bad\n",
                "    class: small\n",
                "    config: oasts.yaml\n",
                "    spec:\n",
                "      path: openapi.json\n",
                "      url: https://ignored\n",
                "      sha256: {bad}\n",
                "procedure:\n",
                "  warmupRuns: 3\n",
                "  samples: 10\n",
                "  rounds: 2\n",
                "  repeatabilityBound: 0.1\n",
                "thresholds:\n",
                "  warmGenerateP50Ms: {{}}\n",
                "  rssCeilingBytes: {{ large: 1, small: 1 }}\n",
                "  tscCeilingMs: {{ large: 1, small: 1 }}\n",
            ),
            good = digest_of(&good_bytes),
            bad = digest_of(b"a different document"),
        );
        let manifest = Manifest::from_str(&manifest_yaml).expect("manifest parses");
        let fetcher = BytesFetcher {
            bytes: good_bytes.clone(),
            called: Cell::new(false),
        };
        let mut out = Vec::new();

        let error =
            fetch_all(&manifest, root.path(), &fetcher, &mut out).expect_err("aggregated failure");

        let message = error.to_string();
        assert!(message.contains("bad"), "{message}");
        assert!(!message.contains("good"), "only 'bad' failed: {message}");
        // The good fixture was still fetched despite the later failure.
        let good_target = root.path().join("fixtures/good/openapi.json");
        assert_eq!(
            std::fs::read(&good_target).expect("good written"),
            good_bytes
        );
        let log = String::from_utf8(out).expect("utf8 log");
        assert!(log.contains("downloaded: good"), "{log}");
        assert!(log.contains("FAILED: bad"), "{log}");
    }
}
