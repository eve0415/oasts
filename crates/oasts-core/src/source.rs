//! Where documents come from.
//!
//! The loader reads through this trait rather than through `std::fs` directly, so the same read
//! path serves a filesystem host and a host that has no filesystem at all. One path cannot drift
//! from itself, and emitted bytes are contractual across every front-end.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

/// Whether `path` starts at a root.
///
/// `Path::is_absolute` answers for the host platform, and `wasm32-unknown-unknown` has no path
/// semantics to answer with: std reports every path there as relative, including the synthetic
/// absolute paths a host with no filesystem mints. A leading root component is the question
/// actually being asked, and it agrees with `is_absolute` on every target that has an opinion.
#[must_use]
pub fn is_rooted(path: &Path) -> bool {
    path.has_root() && (path.is_absolute() || cfg!(target_family = "wasm"))
}

/// Supplies document bytes and the identities documents are deduplicated by.
///
/// `Send + Sync` because the document graph outlives loading and is read from rayon workers during
/// parse; `Debug` because the graph derives it.
pub trait DocumentSource: Debug + Send + Sync {
    /// Identity for dedup and `$ref` resolution — canonical on a real filesystem, minted from the
    /// in-memory key otherwise. Never re-derived into a location.
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf>;

    /// Byte length without materialising the document, so the size gate can reject before anything
    /// is buffered.
    fn byte_len(&self, path: &Path) -> io::Result<u64>;

    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
}

/// The real filesystem.
#[derive(Clone, Copy, Debug, Default)]
pub struct FsSource;

impl DocumentSource for FsSource {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::canonicalize(path)
    }

    fn byte_len(&self, path: &Path) -> io::Result<u64> {
        std::fs::metadata(path).map(|metadata| metadata.len())
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }
}

/// A shared handle to a document source.
///
/// The filesystem variant carries no data, so seating the ordinary hosts costs no allocation —
/// `bench/allocs.yaml` pins `loadGraph.allocs` exactly, and an `Arc<FsSource>` would move it.
#[derive(Clone, Debug)]
pub enum SourceHandle {
    /// The real filesystem.
    Fs,
    /// Anything else, shared across the graph and its rayon readers.
    Shared(Arc<dyn DocumentSource>),
}

impl SourceHandle {
    fn as_source(&self) -> &dyn DocumentSource {
        match self {
            Self::Fs => &FsSource,
            Self::Shared(source) => source.as_ref(),
        }
    }
}

impl From<Arc<dyn DocumentSource>> for SourceHandle {
    fn from(source: Arc<dyn DocumentSource>) -> Self {
        Self::Shared(source)
    }
}

impl DocumentSource for SourceHandle {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        self.as_source().canonicalize(path)
    }

    fn byte_len(&self, path: &Path) -> io::Result<u64> {
        self.as_source().byte_len(path)
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.as_source().read(path)
    }
}

/// What one request is permitted to do.
///
/// Only the two limits a host is the sole enforcer of. Authorization and redirect budget are not
/// here because they are not delegated: the core decides, hop by hop, which URI is requested next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchPolicy {
    /// Deadline for this one request, in milliseconds.
    pub timeout_ms: u64,
    /// Hard cap on the body, to be abandoned rather than buffered past.
    pub max_bytes: u64,
}

/// What one request answered with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FetchStep {
    /// The document's bytes.
    Body(Vec<u8>),
    /// A redirect, carrying the location as the response wrote it.
    Redirect(String),
}

/// Performs the individual requests the compiler cannot perform itself.
///
/// The core never links an HTTP client. Retrieval is a host capability so that a front-end with no
/// way to make a request — the WebAssembly build, whose module declares no imports at all — stays
/// buildable and simply seats nothing here.
///
/// One call is one request. A redirect is *reported*, never followed: the core resolves the
/// location, authorizes the host it names, and counts it against the redirect budget before asking
/// for it. Delegating that loop would make `remote.allowHosts` a request rather than a boundary,
/// because a redirect is how a retrieval reaches a host nobody listed.
///
/// The error is the message a diagnostic will print, so an implementation reports what failed in
/// its own vocabulary and the core never has to enumerate transport failures.
pub trait RemoteFetcher: Debug + Send + Sync {
    /// Performs exactly one request for `url`, without following what it answers.
    fn fetch_once(&self, url: &str, policy: &FetchPolicy) -> Result<FetchStep, String>;
}

/// A shared handle to the host's retrieval capability, if it has one.
#[derive(Clone, Debug, Default)]
pub enum FetcherHandle {
    /// The host cannot retrieve documents at all.
    #[default]
    None,
    /// The host's retriever, shared across the graph.
    Shared(Arc<dyn RemoteFetcher>),
}

impl FetcherHandle {
    /// The retriever, or `None` when this host has none.
    #[must_use]
    pub fn get(&self) -> Option<&dyn RemoteFetcher> {
        match self {
            Self::None => None,
            Self::Shared(fetcher) => Some(fetcher.as_ref()),
        }
    }
}

impl From<Arc<dyn RemoteFetcher>> for FetcherHandle {
    fn from(fetcher: Arc<dyn RemoteFetcher>) -> Self {
        Self::Shared(fetcher)
    }
}

/// Documents held in memory, rooted at a synthetic workspace.
///
/// A host with no filesystem still needs identities to deduplicate documents by and to resolve
/// `$ref`s against. Those identities are minted from the supplied keys: normalised lexically,
/// contained below the root, and never re-derived into a location. A `$ref` naming a document
/// nobody supplied fails as a missing document rather than reaching the host.
#[derive(Clone, Debug)]
pub struct MemorySource {
    root: PathBuf,
    documents: BTreeMap<PathBuf, Vec<u8>>,
}

impl MemorySource {
    /// Creates an empty source rooted at `root`, which is treated as an absolute directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            documents: BTreeMap::new(),
        }
    }

    /// Seats one document. A relative `path` is taken as relative to the root.
    pub fn insert(&mut self, path: impl AsRef<Path>, contents: Vec<u8>) {
        let path = self.normalize(path.as_ref());
        self.documents.insert(path, contents);
    }

    /// Resolves `.` and `..` against the root without asking anything about the world.
    fn normalize(&self, path: &Path) -> PathBuf {
        let mut resolved = if is_rooted(path) {
            PathBuf::new()
        } else {
            self.root.clone()
        };
        for component in path.components() {
            match component {
                // A prefix only occurs on Windows; both are roots, and both restart the path.
                Component::RootDir | Component::Prefix(_) => {
                    resolved.push(component.as_os_str());
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    resolved.pop();
                }
                Component::Normal(segment) => resolved.push(segment),
            }
        }
        resolved
    }

    /// The identity of `path`, or the reason it has none.
    fn locate(&self, path: &Path) -> io::Result<PathBuf> {
        let resolved = self.normalize(path);
        if !resolved.starts_with(&self.root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "'{}' resolves outside the workspace root '{}'",
                    resolved.display(),
                    self.root.display()
                ),
            ));
        }
        if resolved == self.root || self.documents.contains_key(&resolved) {
            return Ok(resolved);
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no document was supplied at '{}'", resolved.display()),
        ))
    }

    fn contents(&self, path: &Path) -> io::Result<&[u8]> {
        let resolved = self.locate(path)?;
        self.documents
            .get(&resolved)
            .map(Vec::as_slice)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "'{}' is the workspace root, not a document",
                        resolved.display()
                    ),
                )
            })
    }
}

impl DocumentSource for MemorySource {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        self.locate(path)
    }

    fn byte_len(&self, path: &Path) -> io::Result<u64> {
        self.contents(path).map(|contents| contents.len() as u64)
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.contents(path).map(<[u8]>::to_vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn fs_source_round_trips_a_document() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("openapi.yaml");
        let contents = b"openapi: 3.1.1\n";
        fs::write(&path, contents).expect("write document");

        let source = FsSource;
        let canonical = source.canonicalize(&path).expect("canonicalize");
        assert!(canonical.is_absolute(), "{}", canonical.display());
        assert_eq!(source.read(&canonical).expect("read"), contents);
        assert_eq!(
            source.byte_len(&canonical).expect("byte_len"),
            source.read(&canonical).expect("read").len() as u64
        );
    }

    #[test]
    fn fs_source_reports_the_underlying_error_for_an_absent_document() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("absent.yaml");

        let source = FsSource;
        assert_eq!(
            source.canonicalize(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            source.byte_len(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            source.read(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn a_shared_handle_answers_from_the_source_it_wraps() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("openapi.yaml");
        fs::write(&path, b"openapi: 3.1.1\n").expect("write document");

        let shared = SourceHandle::from(Arc::new(FsSource) as Arc<dyn DocumentSource>);
        let canonical = shared.canonicalize(&path).expect("canonicalize");
        assert_eq!(shared.byte_len(&canonical).expect("byte_len"), 15);
        assert_eq!(shared.read(&canonical).expect("read"), b"openapi: 3.1.1\n");
    }

    #[test]
    fn a_supplied_document_reads_back() {
        let mut source = MemorySource::new("/workspace");
        source.insert("/workspace/openapi.yaml", b"openapi: 3.1.1\n".to_vec());

        let canonical = source
            .canonicalize(Path::new("/workspace/openapi.yaml"))
            .expect("canonicalize");

        assert_eq!(canonical, PathBuf::from("/workspace/openapi.yaml"));
        assert_eq!(source.byte_len(&canonical).expect("byte_len"), 15);
        assert_eq!(source.read(&canonical).expect("read"), b"openapi: 3.1.1\n");
    }

    #[test]
    fn an_unsupplied_document_is_missing_rather_than_empty() {
        let source = MemorySource::new("/workspace");
        let absent = Path::new("/workspace/components.yaml");

        assert_eq!(
            source.canonicalize(absent).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            source.byte_len(absent).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            source.read(absent).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn the_root_is_its_own_identity() {
        // Config resolution canonicalizes the config's parent directory, and the graph builder
        // canonicalizes the workspace root. Neither is a document, and both must answer.
        let source = MemorySource::new("/workspace");

        assert_eq!(
            source.canonicalize(Path::new("/workspace")).expect("root"),
            PathBuf::from("/workspace")
        );
    }

    #[test]
    fn the_root_is_an_identity_but_not_a_document() {
        let source = MemorySource::new("/workspace");
        let root = Path::new("/workspace");

        assert!(source.canonicalize(root).is_ok());
        assert_eq!(
            source.byte_len(root).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            source.read(root).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn dot_segments_resolve_without_a_filesystem() {
        let mut source = MemorySource::new("/workspace");
        source.insert("/workspace/api/openapi.yaml", b"openapi: 3.1.1\n".to_vec());

        for written in [
            "/workspace/api/./openapi.yaml",
            "/workspace/api/nested/../openapi.yaml",
            "api/openapi.yaml",
            // Only a leading `.` survives `Path::components`; an interior one is folded away.
            "./api/openapi.yaml",
        ] {
            assert_eq!(
                source.canonicalize(Path::new(written)).expect(written),
                PathBuf::from("/workspace/api/openapi.yaml"),
                "{written}"
            );
        }
    }

    #[test]
    fn a_reference_climbing_out_of_the_root_is_refused() {
        let mut source = MemorySource::new("/workspace");
        source.insert("/workspace/openapi.yaml", b"openapi: 3.1.1\n".to_vec());

        let escaping = Path::new("/workspace/../etc/passwd");

        assert_eq!(
            source.canonicalize(escaping).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            source.byte_len(escaping).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            source.read(escaping).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn fs_source_refuses_to_read_a_directory_as_a_document() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = FsSource;

        assert!(source.canonicalize(temp.path()).is_ok());
        assert!(source.byte_len(temp.path()).is_ok());
        assert!(source.read(temp.path()).is_err());
    }
}
