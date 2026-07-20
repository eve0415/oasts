//! Per-key generate pipeline: cold/warm timing, conformance, tsc typecheck, gates, and recording.
//!
//! Each key copies its pristine fixture into a fresh temp workdir, times one cold generate, then
//! runs the manifest's warm rounds (untimed warmups then timed samples) regenerating in place. Peak
//! RSS is the max child RSS across every invocation. After conformance passes, every emitted `.ts`
//! file is typechecked with the pinned tsc, and the key's warm p50, peak RSS, tsc wall, and
//! repeatability are gated against the manifest. Measured keys — including gate-failing ones — are
//! recorded to `bench/results.yaml`; a hard failure (generate/conformance/typecheck error) or any
//! failed gate makes the command exit nonzero.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

use crate::manifest::{FixtureEntry, FixtureSource, Manifest, Procedure, Thresholds};
use crate::results::{self, Gates, KeyResult, RunMetadata};
use crate::sample::{SampleOutcome, nearest_rank_ms, timed_sample};
use crate::{Error, copy_fixture};

/// Runs the full per-key pipeline for the selected fixtures and records the measured keys.
///
/// Every key is attempted; the returned error aggregates the keys that hard-failed or failed a gate
/// so the caller exits nonzero. Progress is written to `out`.
pub fn run(
    manifest: &Manifest,
    workspace_root: &Path,
    filters: &[String],
    runner_label: &str,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let binary = workspace_root.join("target/release/oasts");
    if !binary.is_file() {
        return Err(Error::new(
            "release binary target/release/oasts not found; run `cargo build --release -p oasts` first",
        ));
    }
    let fixtures_root = workspace_root.join("fixtures");
    let selected = select_fixtures(manifest, filters)?;
    let context = KeyContext {
        binary: &binary,
        fixtures_root: &fixtures_root,
        workspace_root,
        thresholds: &manifest.thresholds,
        procedure: &manifest.procedure,
    };

    let _ = writeln!(out, "runner: {runner_label}");
    let mut results = Vec::new();
    let mut failures = Vec::new();
    for fixture in selected {
        match measure_key(fixture, &context) {
            Ok(result) => {
                let _ = writeln!(out, "{}", progress_line(&result));
                if !result.gates.all_pass() {
                    failures.push(format!("{}/{} (gate)", result.fixture, result.config));
                }
                results.push(result);
            }
            Err(error) => {
                let _ = writeln!(out, "FAILED: {} — {error}", fixture.threshold_key());
                failures.push(fixture.threshold_key());
            }
        }
    }

    if !results.is_empty() {
        let metadata = RunMetadata::collect(workspace_root, runner_label)?;
        let path = workspace_root.join("bench/results.yaml");
        let manifest_order: Vec<(String, String)> = manifest
            .fixtures
            .iter()
            .map(|fixture| (fixture.name.clone(), fixture.config.clone()))
            .collect();
        results::write(&path, &results, &metadata, &manifest_order)?;
        let _ = writeln!(out, "wrote {}", path.display());
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(Error::new(format!(
            "run failed for {} key(s): {}",
            failures.len(),
            failures.join(", ")
        )))
    }
}

struct KeyContext<'a> {
    binary: &'a Path,
    fixtures_root: &'a Path,
    workspace_root: &'a Path,
    thresholds: &'a Thresholds,
    procedure: &'a Procedure,
}

fn select_fixtures<'a>(
    manifest: &'a Manifest,
    filters: &[String],
) -> Result<Vec<&'a FixtureEntry>, Error> {
    if filters.is_empty() {
        return Ok(manifest.fixtures.iter().collect());
    }
    for name in filters {
        if !manifest
            .fixtures
            .iter()
            .any(|fixture| &fixture.name == name)
        {
            return Err(Error::new(format!(
                "unknown fixture '{name}' (not in manifest)"
            )));
        }
    }
    // Manifest order regardless of filter order, so results stay stable.
    Ok(manifest
        .fixtures
        .iter()
        .filter(|fixture| filters.iter().any(|name| name == &fixture.name))
        .collect())
}

fn measure_key(fixture: &FixtureEntry, ctx: &KeyContext) -> Result<KeyResult, Error> {
    let source_dir = ctx.fixtures_root.join(&fixture.dir);
    if let FixtureSource::Spec(spec) = &fixture.source {
        let spec_path = source_dir.join(&spec.path);
        if !spec_path.is_file() {
            return Err(Error::new(format!(
                "spec file {} is missing; run `oasts-bench fetch` first",
                spec_path.display()
            )));
        }
    }

    let workdir = fresh_workdir(&source_dir)?;
    let mut peak_rss_bytes = 0u64;

    let cold = generate_once(ctx.binary, &fixture.config, workdir.path())?;
    ensure_generate_ok(&cold, "cold generate")?;
    peak_rss_bytes = peak_rss_bytes.max(cold.peak_rss_bytes);
    let cold_ms = wall_ms(&cold);

    let mut round_p50 = Vec::with_capacity(ctx.procedure.rounds);
    for _round in 0..ctx.procedure.rounds {
        for _ in 0..ctx.procedure.warmup_runs {
            let warmup = generate_once(ctx.binary, &fixture.config, workdir.path())?;
            ensure_generate_ok(&warmup, "warmup generate")?;
            peak_rss_bytes = peak_rss_bytes.max(warmup.peak_rss_bytes);
        }
        let mut samples = Vec::with_capacity(ctx.procedure.samples);
        for _ in 0..ctx.procedure.samples {
            let sample = generate_once(ctx.binary, &fixture.config, workdir.path())?;
            ensure_generate_ok(&sample, "warm generate")?;
            peak_rss_bytes = peak_rss_bytes.max(sample.peak_rss_bytes);
            samples.push(wall_ms(&sample));
        }
        round_p50.push(nearest_rank_ms(&mut samples, 0.5));
    }

    // Walk the first generated tree once and thread the file map through both the
    // conformance checks and the byte/file accounting below, instead of re-walking
    // the same tree in each. The double-generation check still walks its own second
    // tree separately.
    let outputs = crate::conformance::generated_files(workdir.path())?;

    crate::conformance::check_conformance(&outputs, &source_dir, ctx.binary, &fixture.config)?;

    let mut output_bytes = 0u64;
    let mut ts_files = Vec::new();
    for (relative, path) in &outputs {
        output_bytes += file_len(path)?;
        if relative.ends_with(".ts") {
            ts_files.push(path.clone());
        }
    }
    let output_files = outputs.len();

    let tsc = run_tsc(ctx.workspace_root, &ts_files)?;
    ensure_tsc_ok(&tsc)?;
    let tsc_ms = wall_ms(&tsc);

    let warm_p50_round1 = round_p50.first().copied().unwrap_or(0.0);
    let warm_p50_round2 = round_p50.get(1).copied().unwrap_or(warm_p50_round1);
    let warm_p50_gated = round_p50.iter().copied().fold(0.0_f64, f64::max);

    let gates = evaluate_gates(&GateInputs {
        warm_p50_ceiling: ctx.thresholds.warm_p50_ms(&fixture.threshold_key()),
        warm_p50_gated,
        warm_p50_round1,
        warm_p50_round2,
        rss_ceiling: ctx.thresholds.rss_ceiling(fixture.class),
        peak_rss_bytes,
        tsc_ceiling: ctx.thresholds.tsc_ceiling(fixture.class),
        tsc_ms,
        repeatability_bound: ctx.procedure.repeatability_bound,
    });

    Ok(KeyResult {
        fixture: fixture.name.clone(),
        config: fixture.config.clone(),
        class: fixture.class.as_str().to_owned(),
        cold_ms,
        warm_p50_round1,
        warm_p50_round2,
        warm_p50_gated,
        peak_rss_bytes,
        tsc_ms,
        output_bytes,
        output_files,
        gates,
    })
}

struct GateInputs {
    warm_p50_ceiling: Option<u64>,
    warm_p50_gated: f64,
    warm_p50_round1: f64,
    warm_p50_round2: f64,
    rss_ceiling: u64,
    peak_rss_bytes: u64,
    tsc_ceiling: u64,
    tsc_ms: f64,
    repeatability_bound: f64,
}

fn evaluate_gates(input: &GateInputs) -> Gates {
    let warm_p50 = match input.warm_p50_ceiling {
        Some(ceiling) => input.warm_p50_gated <= ceiling as f64,
        None => true,
    };
    Gates {
        warm_p50,
        peak_rss: input.peak_rss_bytes <= input.rss_ceiling,
        tsc: input.tsc_ms <= input.tsc_ceiling as f64,
        repeatability: repeatability_within(
            input.warm_p50_round1,
            input.warm_p50_round2,
            input.repeatability_bound,
        ),
    }
}

fn repeatability_within(round1: f64, round2: f64, bound: f64) -> bool {
    let min = round1.min(round2);
    if min <= 0.0 {
        return true;
    }
    ((round1 - round2).abs() / min) <= bound
}

fn progress_line(result: &KeyResult) -> String {
    let flag = |name: &str, pass: bool| {
        if pass {
            String::new()
        } else {
            format!(" {name}")
        }
    };
    let gate_summary = if result.gates.all_pass() {
        "gates OK".to_owned()
    } else {
        format!(
            "gates FAIL:{}{}{}{}",
            flag("warmP50", result.gates.warm_p50),
            flag("peakRss", result.gates.peak_rss),
            flag("tsc", result.gates.tsc),
            flag("repeatability", result.gates.repeatability),
        )
    };
    format!(
        "{}/{} [{}]: cold {:.1}ms  warm p50 {:.1}/{:.1}ms (gated {:.1}ms)  peak RSS {}  tsc {:.1}ms  {} files {}B  {}",
        result.fixture,
        result.config,
        result.class,
        result.cold_ms,
        result.warm_p50_round1,
        result.warm_p50_round2,
        result.warm_p50_gated,
        format_bytes(result.peak_rss_bytes),
        result.tsc_ms,
        result.output_files,
        result.output_bytes,
        gate_summary,
    )
}

fn fresh_workdir(source_dir: &Path) -> Result<TempDir, Error> {
    let workdir =
        tempfile::tempdir().map_err(|error| Error::new(format!("creating workdir: {error}")))?;
    copy_fixture(source_dir, workdir.path()).map_err(|error| {
        Error::new(format!("copying fixture {}: {error}", source_dir.display()))
    })?;
    Ok(workdir)
}

fn generate_once(binary: &Path, config: &str, workdir: &Path) -> Result<SampleOutcome, Error> {
    let mut command = Command::new(binary);
    command
        .arg("generate")
        .arg("--config")
        .arg(config)
        .current_dir(workdir);
    timed_sample(command).map_err(|error| Error::new(format!("spawning generate: {error}")))
}

fn run_tsc(workspace_root: &Path, ts_files: &[PathBuf]) -> Result<SampleOutcome, Error> {
    let mut command = Command::new("pnpm");
    command
        .arg("exec")
        .arg("tsc")
        .arg("--strict")
        .arg("--noEmit")
        .arg("--skipLibCheck")
        .arg("false")
        .arg("--target")
        .arg("es2022")
        .arg("--module")
        .arg("esnext")
        .arg("--moduleResolution")
        .arg("bundler");
    for file in ts_files {
        command.arg(file);
    }
    command.current_dir(workspace_root);
    timed_sample(command).map_err(|error| Error::new(format!("spawning tsc: {error}")))
}

fn ensure_generate_ok(outcome: &SampleOutcome, phase: &str) -> Result<(), Error> {
    if outcome.exit_code != 0 {
        return Err(Error::new(format!(
            "{phase} exited {}: {}",
            outcome.exit_code,
            head_lines(&outcome.stderr, 50)
        )));
    }
    Ok(())
}

fn ensure_tsc_ok(outcome: &SampleOutcome) -> Result<(), Error> {
    if outcome.exit_code != 0 {
        return Err(Error::new(format!(
            "tsc typecheck failed (exit {}):\n{}\n{}",
            outcome.exit_code,
            head_lines(&outcome.stdout, 50),
            head_lines(&outcome.stderr, 50)
        )));
    }
    Ok(())
}

fn head_lines(text: &str, max: usize) -> String {
    text.lines().take(max).collect::<Vec<_>>().join("\n")
}

fn wall_ms(outcome: &SampleOutcome) -> f64 {
    outcome.wall.as_secs_f64() * 1000.0
}

fn file_len(path: &Path) -> Result<u64, Error> {
    Ok(std::fs::metadata(path)
        .map_err(|error| Error::new(format!("stat {}: {error}", path.display())))?
        .len())
}

fn format_bytes(bytes: u64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    format!("{:.1} MiB", bytes as f64 / MIB)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;

    fn real_manifest() -> Manifest {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/manifest.yaml");
        Manifest::load(&path).expect("real manifest loads")
    }

    fn passing_inputs() -> GateInputs {
        GateInputs {
            warm_p50_ceiling: Some(1000),
            warm_p50_gated: 10.0,
            warm_p50_round1: 10.0,
            warm_p50_round2: 10.5,
            rss_ceiling: 2_147_483_648,
            peak_rss_bytes: 4_404_019,
            tsc_ceiling: 60_000,
            tsc_ms: 1234.0,
            repeatability_bound: 0.10,
        }
    }

    #[test]
    fn empty_filter_selects_every_fixture() {
        let manifest = real_manifest();
        let selected = select_fixtures(&manifest, &[]).expect("select all");
        assert_eq!(selected.len(), manifest.fixtures.len());
    }

    #[test]
    fn filters_select_in_manifest_order_and_reject_typos() {
        let manifest = real_manifest();
        let selected = select_fixtures(
            &manifest,
            &["tictactoe-3.1".to_owned(), "petstore-3.0".to_owned()],
        )
        .expect("select subset");
        let names: Vec<&str> = selected
            .iter()
            .map(|fixture| fixture.name.as_str())
            .collect();
        assert_eq!(names, ["petstore-3.0", "tictactoe-3.1"]);

        let error =
            select_fixtures(&manifest, &["nope".to_owned()]).expect_err("unknown fixture rejected");
        assert!(error.to_string().contains("nope"), "{error}");
    }

    #[test]
    fn head_lines_truncates() {
        let text = "a\nb\nc\nd";
        assert_eq!(head_lines(text, 2), "a\nb");
    }

    #[test]
    fn gates_pass_when_all_metrics_are_within_limits() {
        assert!(evaluate_gates(&passing_inputs()).all_pass());
    }

    #[test]
    fn warm_p50_breach_fails_only_that_gate() {
        let mut input = passing_inputs();
        input.warm_p50_gated = 2000.0;
        let gates = evaluate_gates(&input);
        assert!(!gates.warm_p50);
        assert!(gates.peak_rss && gates.tsc && gates.repeatability);
    }

    #[test]
    fn absent_threshold_passes_warm_p50() {
        let mut input = passing_inputs();
        input.warm_p50_ceiling = None;
        input.warm_p50_gated = 9_999_999.0;
        assert!(evaluate_gates(&input).warm_p50);
    }

    #[test]
    fn rss_breach_fails_the_rss_gate() {
        let mut input = passing_inputs();
        input.peak_rss_bytes = u64::MAX;
        assert!(!evaluate_gates(&input).peak_rss);
    }

    #[test]
    fn tsc_breach_fails_the_tsc_gate() {
        let mut input = passing_inputs();
        input.tsc_ms = 120_000.0;
        assert!(!evaluate_gates(&input).tsc);
    }

    #[test]
    fn repeatability_breach_fails_that_gate() {
        let mut input = passing_inputs();
        input.warm_p50_round1 = 10.0;
        input.warm_p50_round2 = 20.0;
        assert!(!evaluate_gates(&input).repeatability);
    }
}
