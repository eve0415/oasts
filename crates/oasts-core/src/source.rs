//! Where documents come from.
//!
//! The loader reads through this trait rather than through `std::fs` directly, so the same read
//! path serves a filesystem host and a host that has no filesystem at all. One path cannot drift
//! from itself, and emitted bytes are contractual across every front-end.

use std::io;
use std::path::{Path, PathBuf};

/// Supplies document bytes and the identities documents are deduplicated by.
pub trait DocumentSource {
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
    fn fs_source_refuses_to_read_a_directory_as_a_document() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = FsSource;

        assert!(source.canonicalize(temp.path()).is_ok());
        assert!(source.byte_len(temp.path()).is_ok());
        assert!(source.read(temp.path()).is_err());
    }
}
