//! Per-key conformance checks: deterministic double generation and oxc-parseable output.
//!
//! Determinism is verified by generating the same fixture a second time in an independent workdir
//! and comparing every `generated*` output tree byte-for-byte, path-set equality both directions.
//! Emitted TypeScript is verified by parsing every `.ts` file with the oxc parser as a library, so a
//! syntactically broken emission fails the key without shelling out to a compiler.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

use crate::{Error, copy_fixture};

/// Runs both conformance checks for a key, given the file map of its already-generated first output
/// tree. The caller walks that tree once and threads the map in, so neither check re-walks it.
pub fn check_conformance(
    first_files: &BTreeMap<String, PathBuf>,
    source_dir: &Path,
    binary: &Path,
    config: &str,
) -> Result<(), Error> {
    check_double_generation(first_files, source_dir, binary, config)?;
    check_oxc_parse(first_files)?;
    Ok(())
}

fn check_double_generation(
    first_files: &BTreeMap<String, PathBuf>,
    source_dir: &Path,
    binary: &Path,
    config: &str,
) -> Result<(), Error> {
    let second = tempfile::tempdir()
        .map_err(|error| Error::new(format!("creating second workdir: {error}")))?;
    copy_fixture(source_dir, second.path()).map_err(|error| {
        Error::new(format!("copying fixture {}: {error}", source_dir.display()))
    })?;

    let output = Command::new(binary)
        .arg("generate")
        .arg("--config")
        .arg(config)
        .current_dir(second.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| Error::new(format!("spawning second generate: {error}")))?;
    if !output.status.success() {
        return Err(Error::new(format!(
            "double generation: second generate failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    compare_generated(first_files, second.path())
}

fn compare_generated(first: &BTreeMap<String, PathBuf>, second: &Path) -> Result<(), Error> {
    let b = generated_files(second)?;
    for (relative, path_a) in first {
        let Some(path_b) = b.get(relative) else {
            return Err(Error::new(format!(
                "double generation: {relative} present in the first generation but missing in the second"
            )));
        };
        if read_file(path_a)? != read_file(path_b)? {
            return Err(Error::new(format!(
                "double generation: {relative} differs between generations"
            )));
        }
    }
    for relative in b.keys() {
        if !first.contains_key(relative) {
            return Err(Error::new(format!(
                "double generation: {relative} present in the second generation but missing in the first"
            )));
        }
    }
    Ok(())
}

/// Maps each file under a `generated*` directory to its absolute path, keyed by the path relative to
/// `workdir` (sorted, so the first reported difference is deterministic).
pub fn generated_files(workdir: &Path) -> Result<BTreeMap<String, PathBuf>, Error> {
    let mut files = BTreeMap::new();
    for entry in read_dir(workdir)? {
        let entry =
            entry.map_err(|error| Error::new(format!("reading {}: {error}", workdir.display())))?;
        let is_generated = entry.file_name().to_string_lossy().starts_with("generated");
        if is_generated && file_type_is_dir(&entry)? {
            walk(workdir, &entry.path(), &mut files)?;
        }
    }
    Ok(files)
}

fn walk(root: &Path, directory: &Path, files: &mut BTreeMap<String, PathBuf>) -> Result<(), Error> {
    for entry in read_dir(directory)? {
        let entry = entry
            .map_err(|error| Error::new(format!("reading {}: {error}", directory.display())))?;
        let path = entry.path();
        if file_type_is_dir(&entry)? {
            walk(root, &path, files)?;
        } else {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| Error::new(format!("relativizing {}: {error}", path.display())))?
                .to_string_lossy()
                .replace('\\', "/");
            files.insert(relative, path);
        }
    }
    Ok(())
}

fn read_dir(path: &Path) -> Result<std::fs::ReadDir, Error> {
    std::fs::read_dir(path)
        .map_err(|error| Error::new(format!("reading {}: {error}", path.display())))
}

fn file_type_is_dir(entry: &std::fs::DirEntry) -> Result<bool, Error> {
    Ok(entry
        .file_type()
        .map_err(|error| Error::new(format!("stat {}: {error}", entry.path().display())))?
        .is_dir())
}

fn read_file(path: &Path) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|error| Error::new(format!("reading {}: {error}", path.display())))
}

fn check_oxc_parse(first_files: &BTreeMap<String, PathBuf>) -> Result<(), Error> {
    for (relative, path) in first_files {
        if !relative.ends_with(".ts") {
            continue;
        }
        let source = std::fs::read_to_string(path)
            .map_err(|error| Error::new(format!("reading {}: {error}", path.display())))?;
        parse_typescript(&source)
            .map_err(|message| Error::new(format!("oxc parse error in {relative}: {message}")))?;
    }
    Ok(())
}

/// Parses `source` as a TypeScript module with the oxc parser, returning the first parse error's
/// message on failure.
fn parse_typescript(source: &str) -> Result<(), String> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::ts()).parse();
    match parsed.diagnostics.errors().next() {
        Some(diagnostic) => Err(diagnostic.to_string()),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
        std::fs::write(path, contents).expect("write file");
    }

    #[test]
    fn identical_generated_trees_compare_equal() {
        let first = tempfile::tempdir().expect("first");
        let second = tempfile::tempdir().expect("second");
        for root in [first.path(), second.path()] {
            write(
                &root.join("generated/types/a.ts"),
                "export type A = string;\n",
            );
            write(&root.join("generated-client/b.ts"), "export const b = 1;\n");
        }
        compare_generated(
            &generated_files(first.path()).expect("walk first"),
            second.path(),
        )
        .expect("equal trees match");
    }

    #[test]
    fn differing_content_is_reported() {
        let first = tempfile::tempdir().expect("first");
        let second = tempfile::tempdir().expect("second");
        write(
            &first.path().join("generated/a.ts"),
            "export type A = string;\n",
        );
        write(
            &second.path().join("generated/a.ts"),
            "export type A = number;\n",
        );
        let error = compare_generated(
            &generated_files(first.path()).expect("walk first"),
            second.path(),
        )
        .expect_err("difference detected");
        assert!(error.to_string().contains("differs"), "{error}");
        assert!(error.to_string().contains("generated/a.ts"), "{error}");
    }

    #[test]
    fn missing_file_is_reported() {
        let first = tempfile::tempdir().expect("first");
        let second = tempfile::tempdir().expect("second");
        write(
            &first.path().join("generated/a.ts"),
            "export type A = string;\n",
        );
        write(
            &first.path().join("generated/b.ts"),
            "export type B = string;\n",
        );
        write(
            &second.path().join("generated/a.ts"),
            "export type A = string;\n",
        );
        let error = compare_generated(
            &generated_files(first.path()).expect("walk first"),
            second.path(),
        )
        .expect_err("missing file detected");
        assert!(
            error.to_string().contains("missing in the second"),
            "{error}"
        );
        assert!(error.to_string().contains("generated/b.ts"), "{error}");
    }

    #[test]
    fn extra_file_in_second_is_reported() {
        let first = tempfile::tempdir().expect("first");
        let second = tempfile::tempdir().expect("second");
        write(
            &first.path().join("generated/a.ts"),
            "export type A = string;\n",
        );
        write(
            &second.path().join("generated/a.ts"),
            "export type A = string;\n",
        );
        write(
            &second.path().join("generated/extra.ts"),
            "export type E = string;\n",
        );
        let error = compare_generated(
            &generated_files(first.path()).expect("walk first"),
            second.path(),
        )
        .expect_err("extra file detected");
        assert!(
            error.to_string().contains("missing in the first"),
            "{error}"
        );
    }

    #[test]
    fn valid_typescript_parses() {
        parse_typescript("export type Pet = { id: number; name: string };\n").expect("valid TS");
    }

    #[test]
    fn broken_typescript_reports_first_error() {
        let error = parse_typescript("export const x: = ;\n").expect_err("broken TS rejected");
        assert!(!error.is_empty(), "error message should be non-empty");
    }

    #[test]
    fn oxc_parse_walks_generated_ts_and_fails_on_broken_file() {
        let workdir = tempfile::tempdir().expect("workdir");
        write(
            &workdir.path().join("generated/types/good.ts"),
            "export type A = string;\n",
        );
        check_oxc_parse(&generated_files(workdir.path()).expect("walk generated"))
            .expect("all valid TS parses");

        write(&workdir.path().join("generated/types/bad.ts"), "type = \n");
        let error = check_oxc_parse(&generated_files(workdir.path()).expect("walk generated"))
            .expect_err("broken file fails");
        assert!(
            error.to_string().contains("generated/types/bad.ts"),
            "{error}"
        );
    }
}
