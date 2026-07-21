//! `bench/allocs.yaml` snapshot: data model, deterministic YAML (de)serialization, merge-by-key,
//! and drift comparison for the per-stage allocation tracker.
//!
//! One key is one `(fixture, config)` pair from `bench/manifest.yaml`. Each key carries an
//! ordered list of pipeline-stage counter samples (`loadGraph`, `parse`, `analyze`, optionally
//! `clientModel`, `emit`) plus an `informational` block holding the key's peak live-heap bytes.
//!
//! Only `allocs` and `deallocs` are gated by [`compare_keys`]. The loader canonicalizes source
//! paths into absolute strings, so `allocBytes` — and, via string-capacity growth, `reallocs` —
//! embed the checkout's absolute path length and differ between two checkouts of the same commit
//! (measured: two same-machine checkouts agreed on every count but drifted on byte totals).
//! Allocation and deallocation counts are length-independent, so they are the portable drift
//! signal; `reallocs`/`allocBytes` stay recorded per stage as same-machine evidence, and
//! `informational.peakBytes` (a transient heap high-water mark) is likewise never compared.
//!
//! Like `bench/results.yaml` (see `results.rs`), writing merges rather than overwrites: an
//! `--update` run only measures fixtures present on the machine (large fetched specs are
//! gitignored and often absent), so the file is read back, entries whose `(fixture, config)`
//! match the current run are replaced, and every other key is preserved. The merged set is
//! ordered by the manifest's fixture order so the file stays stable regardless of which subset
//! ran. A rewrite is atomic (temp file in the same directory, then rename) so a crash never
//! leaves a truncated file.
//!
//! YAML is hand-emitted in strict block style (never flow `{}`/`[]`) so the file stays diffable;
//! every string is double-quoted for a lossless round-trip through a YAML loader. There are no
//! timestamps or environment fields anywhere in this file — unlike `results.yaml`, an allocation
//! count does not depend on when or where it was measured, so `--update` run twice must produce a
//! byte-identical file.

use std::cmp::Ordering as CmpOrdering;
use std::fmt;
use std::path::Path;

use yaml_rust2::YamlLoader;

use crate::Error;
use crate::manifest::{field, req_str, req_u64};
use crate::results::{atomic_write, quote};

/// One stage's counting-allocator snapshot: the counters accumulated between a reset immediately
/// before the stage call and a read immediately after it returns.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StageCounters {
    pub allocs: u64,
    pub reallocs: u64,
    pub deallocs: u64,
    pub alloc_bytes: u64,
}

/// One named pipeline stage's counters, in the order the stage ran.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageSample {
    pub stage: String,
    pub counters: StageCounters,
}

/// One `(fixture, config)` key's full snapshot. Whether a key is gated is not stored:
/// the manifest's `committed: true` flag is the single source of truth, and a stored
/// copy would go stale in rows `merge` preserves from runs that no longer measure them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySnapshot {
    pub fixture: String,
    pub config: String,
    pub stages: Vec<StageSample>,
    /// Peak live bytes observed across the whole key's compile; excluded from `--check`.
    pub peak_bytes: u64,
}

/// A single drifted field between the committed snapshot and a freshly measured gated key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mismatch {
    pub key: String,
    pub field: String,
    pub before: String,
    pub after: String,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {}: {} -> {}",
            self.key, self.field, self.before, self.after
        )
    }
}

/// Reads and parses the snapshot at `path`, or an empty snapshot if the file does not exist yet
/// (the state before the first `--update`).
pub fn read(path: &Path) -> Result<Vec<KeySnapshot>, Error> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)
        .map_err(|error| Error::new(format!("reading {}: {error}", path.display())))?;
    parse_existing(&text)
}

/// Merges `measured` into `existing` by `(fixture, config)` and orders the result by
/// `manifest_order` (the manifest's `(fixture, config)` sequence), so a key not measured this run
/// (e.g. a large fetched fixture absent on this machine) persists unchanged and the file stays
/// stable regardless of which subset was measured. Any entry not named in `manifest_order` — a
/// fixture dropped from the manifest — sorts after the known ones by key, so no measurement is
/// silently lost.
pub fn merge(
    existing: Vec<KeySnapshot>,
    measured: &[KeySnapshot],
    manifest_order: &[(String, String)],
) -> Vec<KeySnapshot> {
    let mut merged = existing;
    merged.retain(|entry| {
        !measured
            .iter()
            .any(|key| key.fixture == entry.fixture && key.config == entry.config)
    });
    merged.extend(measured.iter().cloned());

    let rank = |entry: &KeySnapshot| {
        manifest_order
            .iter()
            .position(|(fixture, config)| fixture == &entry.fixture && config == &entry.config)
    };
    merged.sort_by(|left, right| match (rank(left), rank(right)) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => CmpOrdering::Less,
        (None, Some(_)) => CmpOrdering::Greater,
        (None, None) => (left.fixture.as_str(), left.config.as_str())
            .cmp(&(right.fixture.as_str(), right.config.as_str())),
    });
    merged
}

/// Writes `keys` to `path` via a temp file in the same directory, then renames it into place, so
/// a crash mid-write never leaves a truncated snapshot.
pub fn write(path: &Path, keys: &[KeySnapshot]) -> Result<(), Error> {
    atomic_write(path, &to_yaml(keys))
}

/// Compares each `measured` key against its committed counterpart in `committed`.
///
/// The caller chooses which keys to gate — `--check` passes only the manifest's
/// `committed: true` keys; passing a broader set would gate informational keys or
/// hard-error on rows absent from the file. Only stage presence, stage order, and the
/// path-length-independent counters (`allocs`, `deallocs`) are compared; `reallocs`,
/// `allocBytes`, and `informational` are intentionally never read here (see the module
/// doc). Every drifted field is collected — rather than stopping at the first
/// difference — so `--check` can print a complete before/after report.
///
/// A measured key entirely absent from `committed` is a hard error, not a mismatch: it means the
/// committed file itself is incomplete (never `--update`d for this key), not that a measured
/// value moved.
pub fn compare_keys(
    committed: &[KeySnapshot],
    measured: &[KeySnapshot],
) -> Result<Vec<Mismatch>, Error> {
    let mut mismatches = Vec::new();
    for key in measured {
        let key_label = format!("{}/{}", key.fixture, key.config);
        let found = committed
            .iter()
            .find(|entry| entry.fixture == key.fixture && entry.config == key.config)
            .ok_or_else(|| {
                Error::new(format!(
                    "check: gated key {key_label} is missing from the committed snapshot; run `--update` first"
                ))
            })?;
        compare_key(&key_label, found, key, &mut mismatches);
    }
    Ok(mismatches)
}

fn compare_key(
    key_label: &str,
    committed: &KeySnapshot,
    measured: &KeySnapshot,
    mismatches: &mut Vec<Mismatch>,
) {
    if committed.stages.len() != measured.stages.len() {
        mismatches.push(Mismatch {
            key: key_label.to_owned(),
            field: "stages (count)".to_owned(),
            before: committed.stages.len().to_string(),
            after: measured.stages.len().to_string(),
        });
    }
    for (index, (committed_stage, measured_stage)) in committed
        .stages
        .iter()
        .zip(measured.stages.iter())
        .enumerate()
    {
        if committed_stage.stage != measured_stage.stage {
            mismatches.push(Mismatch {
                key: key_label.to_owned(),
                field: format!("stages[{index}] (name)"),
                before: committed_stage.stage.clone(),
                after: measured_stage.stage.clone(),
            });
            continue;
        }
        compare_counters(
            key_label,
            &committed_stage.stage,
            committed_stage.counters,
            measured_stage.counters,
            mismatches,
        );
    }
}

fn compare_counters(
    key_label: &str,
    stage: &str,
    committed: StageCounters,
    measured: StageCounters,
    mismatches: &mut Vec<Mismatch>,
) {
    // Exhaustive destructure: adding a field to StageCounters must fail to compile here
    // until it is explicitly classified as gated (in `fields`) or informational (`_`).
    let StageCounters {
        allocs: committed_allocs,
        reallocs: _,
        deallocs: committed_deallocs,
        alloc_bytes: _,
    } = committed;
    let StageCounters {
        allocs: measured_allocs,
        reallocs: _,
        deallocs: measured_deallocs,
        alloc_bytes: _,
    } = measured;
    let fields: [(&str, u64, u64); 2] = [
        ("allocs", committed_allocs, measured_allocs),
        ("deallocs", committed_deallocs, measured_deallocs),
    ];
    for (field_name, before, after) in fields {
        if before != after {
            mismatches.push(Mismatch {
                key: key_label.to_owned(),
                field: format!("{stage}.{field_name}"),
                before: before.to_string(),
                after: after.to_string(),
            });
        }
    }
}

fn to_yaml(keys: &[KeySnapshot]) -> String {
    let mut out = String::new();
    out.push_str("schemaVersion: 1\n");
    out.push_str("keys:\n");
    for key in keys {
        emit_key(&mut out, key);
    }
    out
}

fn emit_key(out: &mut String, key: &KeySnapshot) {
    out.push_str(&format!("  - fixture: {}\n", quote(&key.fixture)));
    out.push_str(&format!("    config: {}\n", quote(&key.config)));
    out.push_str("    stages:\n");
    for stage in &key.stages {
        emit_stage(out, stage);
    }
    out.push_str("    informational:\n");
    out.push_str(&format!("      peakBytes: {}\n", key.peak_bytes));
}

fn emit_stage(out: &mut String, stage: &StageSample) {
    out.push_str(&format!("      - stage: {}\n", quote(&stage.stage)));
    out.push_str(&format!("        allocs: {}\n", stage.counters.allocs));
    out.push_str(&format!("        reallocs: {}\n", stage.counters.reallocs));
    out.push_str(&format!("        deallocs: {}\n", stage.counters.deallocs));
    out.push_str(&format!(
        "        allocBytes: {}\n",
        stage.counters.alloc_bytes
    ));
}

/// Parses the keys out of an existing snapshot file.
fn parse_existing(text: &str) -> Result<Vec<KeySnapshot>, Error> {
    let documents = YamlLoader::load_from_str(text)
        .map_err(|error| Error::new(format!("parsing allocs snapshot: {error}")))?;
    let Some(root) = documents.first() else {
        return Ok(Vec::new());
    };
    let Some(entries) = root["keys"].as_vec() else {
        return Ok(Vec::new());
    };
    let mut keys = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let context = format!("keys[{index}]");
        let stage_node = field(entry, "stages", &context)?;
        let stage_entries = stage_node
            .as_vec()
            .ok_or_else(|| Error::new(format!("{context}.stages: must be a sequence")))?;
        let mut stages = Vec::with_capacity(stage_entries.len());
        for (stage_index, stage_entry) in stage_entries.iter().enumerate() {
            let stage_context = format!("{context}.stages[{stage_index}]");
            stages.push(StageSample {
                stage: req_str(stage_entry, "stage", &stage_context)?,
                counters: StageCounters {
                    allocs: req_u64(stage_entry, "allocs", &stage_context)?,
                    reallocs: req_u64(stage_entry, "reallocs", &stage_context)?,
                    deallocs: req_u64(stage_entry, "deallocs", &stage_context)?,
                    alloc_bytes: req_u64(stage_entry, "allocBytes", &stage_context)?,
                },
            });
        }
        let informational_context = format!("{context}.informational");
        let informational = field(entry, "informational", &context)?;
        keys.push(KeySnapshot {
            fixture: req_str(entry, "fixture", &context)?,
            config: req_str(entry, "config", &context)?,
            stages,
            peak_bytes: req_u64(informational, "peakBytes", &informational_context)?,
        });
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> KeySnapshot {
        KeySnapshot {
            fixture: "petstore-3.0".to_owned(),
            config: "oasts.yaml".to_owned(),
            stages: vec![
                StageSample {
                    stage: "loadGraph".to_owned(),
                    counters: StageCounters {
                        allocs: 10,
                        reallocs: 1,
                        deallocs: 8,
                        alloc_bytes: 1000,
                    },
                },
                StageSample {
                    stage: "parse".to_owned(),
                    counters: StageCounters {
                        allocs: 20,
                        reallocs: 2,
                        deallocs: 18,
                        alloc_bytes: 2000,
                    },
                },
            ],
            peak_bytes: 5000,
        }
    }

    #[test]
    fn serialization_is_byte_stable_across_runs() {
        let keys = [sample_key()];
        assert_eq!(to_yaml(&keys), to_yaml(&keys));
    }

    #[test]
    fn serialized_yaml_matches_the_documented_block_style() {
        let yaml = to_yaml(&[sample_key()]);
        assert_eq!(
            yaml,
            concat!(
                "schemaVersion: 1\n",
                "keys:\n",
                "  - fixture: \"petstore-3.0\"\n",
                "    config: \"oasts.yaml\"\n",
                "    stages:\n",
                "      - stage: \"loadGraph\"\n",
                "        allocs: 10\n",
                "        reallocs: 1\n",
                "        deallocs: 8\n",
                "        allocBytes: 1000\n",
                "      - stage: \"parse\"\n",
                "        allocs: 20\n",
                "        reallocs: 2\n",
                "        deallocs: 18\n",
                "        allocBytes: 2000\n",
                "    informational:\n",
                "      peakBytes: 5000\n",
            )
        );
    }

    #[test]
    fn emitted_yaml_round_trips_through_the_parser() {
        let key = sample_key();
        let yaml = to_yaml(std::slice::from_ref(&key));
        let parsed = parse_existing(&yaml).expect("re-parses");
        assert_eq!(parsed, [key]);
    }

    #[test]
    fn merge_preserves_keys_the_run_did_not_measure() {
        let a = sample_key();
        let mut b = sample_key();
        b.fixture = "tictactoe-3.1".to_owned();
        let order = vec![
            (a.fixture.clone(), a.config.clone()),
            (b.fixture.clone(), b.config.clone()),
        ];

        let mut b_updated = b.clone();
        b_updated.stages[0].counters.allocs = 999;

        // Only `b` was measured; `a` must survive the merge untouched.
        let merged = merge(vec![a.clone(), b], &[b_updated.clone()], &order);
        assert_eq!(merged, vec![a, b_updated]);
    }

    #[test]
    fn merge_orders_by_manifest_order_regardless_of_input_order() {
        let mut first = sample_key();
        first.fixture = "first".to_owned();
        let mut second = sample_key();
        second.fixture = "second".to_owned();
        let order = vec![
            (first.fixture.clone(), first.config.clone()),
            (second.fixture.clone(), second.config.clone()),
        ];

        let merged = merge(Vec::new(), &[second, first], &order);
        assert_eq!(
            merged
                .iter()
                .map(|key| key.fixture.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
    }

    #[test]
    fn merge_places_manifest_dropped_entries_after_known_ones() {
        let known = sample_key();
        let mut dropped = sample_key();
        dropped.fixture = "dropped".to_owned();
        let order = vec![(known.fixture.clone(), known.config.clone())];

        let merged = merge(vec![dropped.clone(), known.clone()], &[], &order);
        assert_eq!(merged, vec![known, dropped]);
    }

    #[test]
    fn compare_detects_a_changed_counter() {
        let committed = sample_key();
        let mut measured = committed.clone();
        measured.stages[0].counters.allocs += 1;

        let mismatches = compare_keys(&[committed], &[measured]).expect("gated key is present");
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].field, "loadGraph.allocs");
        assert_eq!(mismatches[0].before, "10");
        assert_eq!(mismatches[0].after, "11");
    }

    #[test]
    fn compare_detects_a_stage_count_and_name_drift() {
        let committed = sample_key();
        let mut measured = committed.clone();
        measured.stages.push(StageSample {
            stage: "clientModel".to_owned(),
            counters: StageCounters::default(),
        });
        measured.stages.swap(0, 1);

        let mismatches = compare_keys(&[committed], &[measured]).expect("gated key is present");
        assert!(
            mismatches
                .iter()
                .any(|mismatch| mismatch.field == "stages (count)")
        );
        assert!(
            mismatches
                .iter()
                .any(|mismatch| mismatch.field == "stages[0] (name)")
        );
    }

    #[test]
    fn compare_ignores_informational_peak_bytes() {
        let committed = sample_key();
        let mut measured = committed.clone();
        measured.peak_bytes += 12345;

        let mismatches = compare_keys(&[committed], &[measured]).expect("gated key is present");
        assert!(mismatches.is_empty());
    }

    #[test]
    fn compare_ignores_path_length_dependent_counters() {
        // reallocs and allocBytes embed the checkout's absolute path length (module doc), so a
        // drift in either must not fail the gate.
        let committed = sample_key();
        let mut measured = committed.clone();
        measured.stages[0].counters.reallocs += 3;
        measured.stages[1].counters.alloc_bytes += 9534;

        let mismatches = compare_keys(&[committed], &[measured]).expect("gated key is present");
        assert!(mismatches.is_empty());
    }

    #[test]
    fn compare_errors_on_a_gated_key_missing_from_committed() {
        let measured = sample_key();
        let error = compare_keys(&[], &[measured]).expect_err("missing key is a hard error");
        assert!(error.to_string().contains("petstore-3.0"), "{error}");
    }
}
