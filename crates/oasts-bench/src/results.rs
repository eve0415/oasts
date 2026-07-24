//! `bench/results.yaml` recording: one top-level environment/metadata block plus one measured entry
//! per key.
//!
//! Writing merges rather than overwrites: a filtered run (`run --fixture X`) records only the keys it
//! measured, so the file is read back, entries whose `(fixture, config)` match the current run are
//! replaced, and every other key is preserved — otherwise a filtered run would silently discard every
//! measurement it did not touch. The merged set is ordered by the manifest's fixture order so the file
//! stays stable regardless of which subset was run. The single top-level metadata block always
//! reflects the current run (the environment the file was last written from); a rewrite is atomic
//! (temp file in the same directory, then rename) so a crash never leaves a truncated file.
//!
//! YAML is hand-emitted in block style (never flow) so the file stays diffable and every string is
//! double-quoted for a lossless round-trip through a YAML loader. Floats are emitted with Rust's
//! round-trippable debug form, which always carries a decimal point so the loader reads them back as
//! reals rather than integers.

use std::io::Write as _;
use std::path::Path;
use std::process::Command;

use tempfile::NamedTempFile;
use yaml_rust2::YamlLoader;

use crate::Error;
use crate::manifest::{field, req_bool, req_f64, req_str, req_u64, req_usize};

/// The per-gate pass/fail outcome for a key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gates {
    pub warm_p50: bool,
    pub peak_rss: bool,
    pub tsc: bool,
    pub repeatability: bool,
}

impl Gates {
    /// Whether every gate passed.
    pub fn all_pass(self) -> bool {
        self.warm_p50 && self.peak_rss && self.tsc && self.repeatability
    }
}

/// One measured key's recorded metrics and gate outcomes.
#[derive(Clone, PartialEq, Debug)]
pub struct KeyResult {
    pub fixture: String,
    pub config: String,
    pub class: String,
    pub cold_ms: f64,
    pub warm_p50_round1: f64,
    pub warm_p50_round2: f64,
    pub warm_p50_gated: f64,
    pub peak_rss_bytes: u64,
    pub tsc_ms: f64,
    pub output_bytes: u64,
    pub output_files: usize,
    pub gates: Gates,
}

/// The measurement environment, identical across keys in a single run.
#[derive(Clone)]
pub struct EnvFingerprint {
    pub arch: String,
    pub nproc: String,
    pub mem_total_kb: String,
    pub os_id: String,
    pub os_version_id: String,
    pub rustc: String,
    pub node: String,
    pub tsc: String,
}

impl EnvFingerprint {
    /// Collects the live environment fingerprint.
    pub fn collect(workspace_root: &Path) -> Result<Self, Error> {
        Ok(Self {
            arch: capture("uname", &["-m"], None)?,
            nproc: capture("nproc", &[], None)?,
            mem_total_kb: mem_total_kb()?,
            os_id: os_release_field("ID")?,
            os_version_id: os_release_field("VERSION_ID")?,
            rustc: capture("rustc", &["--version"], None)?,
            node: capture("node", &["--version"], None)?,
            tsc: capture("pnpm", &["exec", "tsc", "--version"], Some(workspace_root))?,
        })
    }
}

/// Run-wide metadata recorded with every key.
pub struct RunMetadata {
    pub runner_label: String,
    pub env: EnvFingerprint,
    pub manifest_commit: String,
    pub measured_at: String,
}

impl RunMetadata {
    /// Collects the run-wide metadata (fingerprint, HEAD commit, UTC timestamp).
    pub fn collect(workspace_root: &Path, runner_label: &str) -> Result<Self, Error> {
        Ok(Self {
            runner_label: runner_label.to_owned(),
            env: EnvFingerprint::collect(workspace_root)?,
            manifest_commit: capture("git", &["rev-parse", "HEAD"], Some(workspace_root))?,
            measured_at: capture("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"], None)?,
        })
    }
}

/// Merges `keys` into the results file at `path` and rewrites it atomically.
///
/// Any existing entry sharing a `(fixture, config)` key with a measured key is replaced; every other
/// existing entry is preserved. The merged set is ordered by `manifest_order` (the manifest's
/// `(fixture, config)` sequence); any entry not named there — a fixture dropped from the manifest —
/// sorts after the known ones by key, so no measurement is silently lost. The metadata block is
/// rewritten to the current run.
pub fn write(
    path: &Path,
    keys: &[KeyResult],
    metadata: &RunMetadata,
    manifest_order: &[(String, String)],
) -> Result<(), Error> {
    let mut merged = if path.exists() {
        let text = std::fs::read_to_string(path)
            .map_err(|error| Error::new(format!("reading {}: {error}", path.display())))?;
        parse_existing(&text)?
    } else {
        Vec::new()
    };

    merged.retain(|existing| {
        !keys
            .iter()
            .any(|key| key.fixture == existing.fixture && key.config == existing.config)
    });
    merged.extend(keys.iter().cloned());

    let rank = |entry: &KeyResult| {
        manifest_order
            .iter()
            .position(|(fixture, config)| fixture == &entry.fixture && config == &entry.config)
    };
    merged.sort_by(|left, right| match (rank(left), rank(right)) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => (left.fixture.as_str(), left.config.as_str())
            .cmp(&(right.fixture.as_str(), right.config.as_str())),
    });

    atomic_write(path, &to_yaml(&merged, metadata))
}

/// Writes `contents` to `path` via a temp file in the same directory, then renames it into place, so
/// a crash mid-write never leaves a truncated results file. The temp file must share the directory so
/// the rename stays on one filesystem and is atomic.
pub(crate) fn atomic_write(path: &Path, contents: &str) -> Result<(), Error> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = NamedTempFile::new_in(directory).map_err(|error| {
        Error::new(format!(
            "creating temp file in {}: {error}",
            directory.display()
        ))
    })?;
    temp.write_all(contents.as_bytes())
        .map_err(|error| Error::new(format!("writing {}: {error}", path.display())))?;
    temp.persist(path)
        .map_err(|error| Error::new(format!("persisting {}: {error}", path.display())))?;
    Ok(())
}

/// Parses the measured entries out of an existing results file, keyed by their measurement fields.
///
/// Only the per-key measurement fields are read; any metadata (top-level or, from an older file, per
/// entry) is ignored, since the current run rewrites the metadata block.
fn parse_existing(text: &str) -> Result<Vec<KeyResult>, Error> {
    let documents = YamlLoader::load_from_str(text)
        .map_err(|error| Error::new(format!("parsing existing results: {error}")))?;
    let Some(root) = documents.first() else {
        return Ok(Vec::new());
    };
    let Some(entries) = root["results"].as_vec() else {
        return Ok(Vec::new());
    };
    let mut keys = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let context = format!("results[{index}]");
        let gates = field(entry, "gates", &context)?;
        let gates_context = format!("{context}.gates");
        keys.push(KeyResult {
            fixture: req_str(entry, "fixture", &context)?,
            config: req_str(entry, "config", &context)?,
            class: req_str(entry, "class", &context)?,
            cold_ms: req_f64(entry, "coldMs", &context)?,
            warm_p50_round1: req_f64(entry, "warmP50MsRound1", &context)?,
            warm_p50_round2: req_f64(entry, "warmP50MsRound2", &context)?,
            warm_p50_gated: req_f64(entry, "warmP50MsGated", &context)?,
            peak_rss_bytes: req_u64(entry, "peakRssBytes", &context)?,
            tsc_ms: req_f64(entry, "tscMs", &context)?,
            output_bytes: req_u64(entry, "outputBytes", &context)?,
            output_files: req_usize(entry, "outputFiles", &context)?,
            gates: Gates {
                warm_p50: req_bool(gates, "warmP50", &gates_context)?,
                peak_rss: req_bool(gates, "peakRss", &gates_context)?,
                tsc: req_bool(gates, "tsc", &gates_context)?,
                repeatability: req_bool(gates, "repeatability", &gates_context)?,
            },
        });
    }
    Ok(keys)
}

fn to_yaml(keys: &[KeyResult], metadata: &RunMetadata) -> String {
    let mut out = String::new();
    out.push_str("schemaVersion: 1\n");
    emit_metadata(&mut out, metadata);
    out.push_str("results:\n");
    for key in keys {
        emit_key(&mut out, key);
    }
    out
}

fn emit_metadata(out: &mut String, metadata: &RunMetadata) {
    let env = &metadata.env;
    out.push_str("metadata:\n");
    out.push_str(&format!(
        "  runnerLabel: {}\n",
        quote(&metadata.runner_label)
    ));
    out.push_str("  envFingerprint:\n");
    out.push_str(&format!("    arch: {}\n", quote(&env.arch)));
    out.push_str(&format!("    nproc: {}\n", quote(&env.nproc)));
    out.push_str(&format!("    memTotalKb: {}\n", quote(&env.mem_total_kb)));
    out.push_str(&format!("    osId: {}\n", quote(&env.os_id)));
    out.push_str(&format!("    osVersionId: {}\n", quote(&env.os_version_id)));
    out.push_str(&format!("    rustc: {}\n", quote(&env.rustc)));
    out.push_str(&format!("    node: {}\n", quote(&env.node)));
    out.push_str(&format!("    tsc: {}\n", quote(&env.tsc)));
    out.push_str(&format!(
        "  manifestCommit: {}\n",
        quote(&metadata.manifest_commit)
    ));
    out.push_str(&format!("  measuredAt: {}\n", quote(&metadata.measured_at)));
}

fn emit_key(out: &mut String, key: &KeyResult) {
    out.push_str(&format!("  - fixture: {}\n", quote(&key.fixture)));
    out.push_str(&format!("    config: {}\n", quote(&key.config)));
    out.push_str(&format!("    class: {}\n", quote(&key.class)));
    out.push_str(&format!("    coldMs: {}\n", float(key.cold_ms)));
    out.push_str(&format!(
        "    warmP50MsRound1: {}\n",
        float(key.warm_p50_round1)
    ));
    out.push_str(&format!(
        "    warmP50MsRound2: {}\n",
        float(key.warm_p50_round2)
    ));
    out.push_str(&format!(
        "    warmP50MsGated: {}\n",
        float(key.warm_p50_gated)
    ));
    out.push_str(&format!("    peakRssBytes: {}\n", key.peak_rss_bytes));
    out.push_str(&format!("    tscMs: {}\n", float(key.tsc_ms)));
    out.push_str(&format!("    outputBytes: {}\n", key.output_bytes));
    out.push_str(&format!("    outputFiles: {}\n", key.output_files));
    out.push_str("    gates:\n");
    out.push_str(&format!("      warmP50: {}\n", key.gates.warm_p50));
    out.push_str(&format!("      peakRss: {}\n", key.gates.peak_rss));
    out.push_str(&format!("      tsc: {}\n", key.gates.tsc));
    out.push_str(&format!(
        "      repeatability: {}\n",
        key.gates.repeatability
    ));
}

pub(crate) fn quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn float(value: f64) -> String {
    // Debug form is round-trippable and always carries a decimal point (e.g. `1234.0`), so the YAML
    // loader reads it back as a real rather than an integer.
    format!("{value:?}")
}

fn capture(program: &str, args: &[&str], cwd: Option<&Path>) -> Result<String, Error> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(directory) = cwd {
        command.current_dir(directory);
    }
    let output = command
        .output()
        .map_err(|error| Error::new(format!("running {program}: {error}")))?;
    if !output.status.success() {
        return Err(Error::new(format!(
            "{program} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn mem_total_kb() -> Result<String, Error> {
    let text = std::fs::read_to_string("/proc/meminfo")
        .map_err(|error| Error::new(format!("reading /proc/meminfo: {error}")))?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let value = rest
                .split_whitespace()
                .next()
                .ok_or_else(|| Error::new("MemTotal line is malformed"))?;
            return Ok(value.to_owned());
        }
    }
    Err(Error::new("MemTotal not found in /proc/meminfo"))
}

fn os_release_field(key: &str) -> Result<String, Error> {
    let text = std::fs::read_to_string("/etc/os-release")
        .map_err(|error| Error::new(format!("reading /etc/os-release: {error}")))?;
    let prefix = format!("{key}=");
    for line in text.lines() {
        if let Some(value) = line.strip_prefix(&prefix) {
            return Ok(value.trim_matches('"').to_owned());
        }
    }
    Err(Error::new(format!("{key} not found in /etc/os-release")))
}

#[cfg(test)]
mod tests {
    use yaml_rust2::YamlLoader;

    use super::*;

    fn sample_metadata() -> RunMetadata {
        RunMetadata {
            runner_label: "baseline".to_owned(),
            env: EnvFingerprint {
                arch: "aarch64".to_owned(),
                nproc: "18".to_owned(),
                mem_total_kb: "65796816".to_owned(),
                os_id: "debian".to_owned(),
                os_version_id: "13".to_owned(),
                rustc: "rustc 1.97.1 (8bab26f4f 2026-07-14)".to_owned(),
                node: "v24.18.0".to_owned(),
                tsc: "7.0.2".to_owned(),
            },
            manifest_commit: "deadbeefcafe".to_owned(),
            measured_at: "2026-07-20T11:37:16Z".to_owned(),
        }
    }

    fn sample_key() -> KeyResult {
        KeyResult {
            fixture: "petstore-3.0".to_owned(),
            config: "oasts.yaml".to_owned(),
            class: "small".to_owned(),
            cold_ms: 5.5,
            warm_p50_round1: 0.8,
            warm_p50_round2: 0.9,
            warm_p50_gated: 0.9,
            peak_rss_bytes: 4_404_019,
            tsc_ms: 1234.0,
            output_bytes: 4096,
            output_files: 6,
            gates: Gates {
                warm_p50: true,
                peak_rss: true,
                tsc: false,
                repeatability: true,
            },
        }
    }

    fn key_named(fixture: &str, config: &str) -> KeyResult {
        let mut key = sample_key();
        key.fixture = fixture.to_owned();
        key.config = config.to_owned();
        key
    }

    fn order_of(fixtures: &[(&str, &str)]) -> Vec<(String, String)> {
        fixtures
            .iter()
            .map(|(fixture, config)| ((*fixture).to_owned(), (*config).to_owned()))
            .collect()
    }

    fn fixtures(documents: &[yaml_rust2::Yaml]) -> Vec<String> {
        documents[0]["results"]
            .as_vec()
            .expect("results sequence")
            .iter()
            .map(|entry| entry["fixture"].as_str().expect("fixture").to_owned())
            .collect()
    }

    #[test]
    fn emitted_yaml_round_trips_through_a_loader() {
        let yaml = to_yaml(&[sample_key()], &sample_metadata());
        let documents = YamlLoader::load_from_str(&yaml).expect("emitted YAML parses");
        let metadata = &documents[0]["metadata"];
        let entry = &documents[0]["results"][0];

        assert_eq!(documents[0]["schemaVersion"].as_i64(), Some(1));
        assert_eq!(metadata["runnerLabel"].as_str(), Some("baseline"));
        assert_eq!(
            metadata["envFingerprint"]["rustc"].as_str(),
            Some("rustc 1.97.1 (8bab26f4f 2026-07-14)")
        );
        assert_eq!(
            metadata["envFingerprint"]["osVersionId"].as_str(),
            Some("13")
        );
        assert_eq!(
            metadata["envFingerprint"]["memTotalKb"].as_str(),
            Some("65796816")
        );
        assert_eq!(metadata["manifestCommit"].as_str(), Some("deadbeefcafe"));
        assert_eq!(
            metadata["measuredAt"].as_str(),
            Some("2026-07-20T11:37:16Z")
        );

        assert_eq!(entry["fixture"].as_str(), Some("petstore-3.0"));
        assert_eq!(entry["config"].as_str(), Some("oasts.yaml"));
        assert_eq!(entry["class"].as_str(), Some("small"));
        assert_eq!(entry["coldMs"].as_f64(), Some(5.5));
        assert_eq!(entry["warmP50MsGated"].as_f64(), Some(0.9));
        assert_eq!(entry["peakRssBytes"].as_i64(), Some(4_404_019));
        assert_eq!(entry["tscMs"].as_f64(), Some(1234.0));
        assert_eq!(entry["outputFiles"].as_i64(), Some(6));
        assert_eq!(entry["gates"]["tsc"].as_bool(), Some(false));
        assert_eq!(entry["gates"]["warmP50"].as_bool(), Some(true));
    }

    #[test]
    fn results_are_emitted_in_the_given_order() {
        let yaml = to_yaml(
            &[key_named("b", "c"), key_named("a", "c")],
            &sample_metadata(),
        );
        let documents = YamlLoader::load_from_str(&yaml).expect("parses");
        assert_eq!(fixtures(&documents), ["b", "a"]);
    }

    #[test]
    fn emitted_entries_round_trip_back_through_the_parser() {
        let key = sample_key();
        let yaml = to_yaml(std::slice::from_ref(&key), &sample_metadata());
        let parsed = parse_existing(&yaml).expect("re-parses");
        assert_eq!(parsed, [key]);
    }

    #[test]
    fn fresh_file_is_written_when_none_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("results.yaml");
        write(
            &path,
            &[key_named("petstore-3.0", "oasts.yaml")],
            &sample_metadata(),
            &order_of(&[("petstore-3.0", "oasts.yaml")]),
        )
        .expect("fresh write");
        let text = std::fs::read_to_string(&path).expect("read back");
        let documents = YamlLoader::load_from_str(&text).expect("parses");
        assert_eq!(fixtures(&documents), ["petstore-3.0"]);
    }

    #[test]
    fn merge_preserves_keys_the_run_did_not_touch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("results.yaml");
        let order = order_of(&[("a", "oasts.yaml"), ("b", "oasts.yaml")]);

        write(
            &path,
            &[key_named("a", "oasts.yaml"), key_named("b", "oasts.yaml")],
            &sample_metadata(),
            &order,
        )
        .expect("seed both");

        // A filtered run measuring only 'b' must leave 'a' untouched.
        write(
            &path,
            &[key_named("b", "oasts.yaml")],
            &sample_metadata(),
            &order,
        )
        .expect("filtered write");

        let text = std::fs::read_to_string(&path).expect("read back");
        let documents = YamlLoader::load_from_str(&text).expect("parses");
        assert_eq!(fixtures(&documents), ["a", "b"]);
    }

    #[test]
    fn merge_replaces_a_same_key_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("results.yaml");
        let order = order_of(&[("a", "oasts.yaml")]);

        let mut old = key_named("a", "oasts.yaml");
        old.cold_ms = 1.0;
        write(&path, &[old], &sample_metadata(), &order).expect("seed");

        let mut fresh = key_named("a", "oasts.yaml");
        fresh.cold_ms = 2.0;
        write(&path, &[fresh], &sample_metadata(), &order).expect("replace");

        let text = std::fs::read_to_string(&path).expect("read back");
        let entries = parse_existing(&text).expect("parses");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cold_ms, 2.0);
    }

    #[test]
    fn merged_entries_follow_manifest_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("results.yaml");
        let order = order_of(&[
            ("first", "oasts.yaml"),
            ("second", "oasts.yaml"),
            ("third", "oasts.yaml"),
        ]);

        // Seed out of manifest order; the file must still come back in manifest order.
        write(
            &path,
            &[
                key_named("third", "oasts.yaml"),
                key_named("first", "oasts.yaml"),
            ],
            &sample_metadata(),
            &order,
        )
        .expect("seed");
        write(
            &path,
            &[key_named("second", "oasts.yaml")],
            &sample_metadata(),
            &order,
        )
        .expect("add middle");

        let text = std::fs::read_to_string(&path).expect("read back");
        let documents = YamlLoader::load_from_str(&text).expect("parses");
        assert_eq!(fixtures(&documents), ["first", "second", "third"]);
    }

    #[test]
    fn entries_absent_from_the_manifest_sort_after_known_ones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("results.yaml");
        let order = order_of(&[("known", "oasts.yaml")]);

        // Two dropped fixtures exercise the manifest-tie-break of unknown entries; the known one
        // exercises the known-before-unknown ordering in both comparison directions.
        write(
            &path,
            &[
                key_named("dropped-b", "oasts.yaml"),
                key_named("known", "oasts.yaml"),
                key_named("dropped-a", "oasts.yaml"),
            ],
            &sample_metadata(),
            &order,
        )
        .expect("seed");

        let text = std::fs::read_to_string(&path).expect("read back");
        let documents = YamlLoader::load_from_str(&text).expect("parses");
        assert_eq!(fixtures(&documents), ["known", "dropped-a", "dropped-b"]);
    }
}
