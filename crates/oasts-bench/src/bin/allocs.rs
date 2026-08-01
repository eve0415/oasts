//! Per-stage allocation tracker for the `oasts-core` compile pipeline.
//!
//! Runs `oasts_core::pipeline::compile`'s stages in-process (`loadGraph`, `parse`, `analyze`,
//! optionally `clientModel`, `emit`) under a counting `#[global_allocator]`, recording
//! allocs/reallocs/deallocs/bytes per stage plus one peak-live-bytes figure per key. `--update`
//! measures every present, non-`cloudflare-3.0` fixture and merges the result into the committed
//! `bench/allocs.yaml`; `--check` re-measures only the manifest's gated (`committed: true`) keys
//! and fails on any alloc/dealloc-count drift from that file (byte and realloc counters are
//! path-length-dependent and stay ungated — see `alloc_track`) — see `scripts/allocs-gate.sh`.
//!
//! Modeled on oxc's `tasks/track_memory_allocations`: a counting global allocator, a per-stage
//! committed snapshot, and a hard drift gate. Unlike oxc, `oasts-core` allocates only through
//! the system allocator (no arena to exclude), so every system allocation the pipeline makes is
//! in scope.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::Parser;
use oasts_bench::alloc_track::{self, KeySnapshot, StageCounters, StageSample};
use oasts_bench::manifest::{FixtureEntry, FixtureSource, Manifest};
use oasts_bench::{Error, workspace_root};
use oasts_core::client_model::build_client_model;
use oasts_core::config::load_config;
use oasts_core::diag::{self, DiagnosticSink};
use oasts_core::emit::emit_artifacts;
use oasts_core::loader::load_graph;
use oasts_core::parse::parse;
use oasts_core::semantic::analyze;

/// Fixtures that are never measured. cloudflare-3.0 does not compile (schema-name
/// collisions in the spec), and `run_update` propagates any `measure_key` error with
/// `?` — without this skip, an `--update` on a checkout that fetched it would abort
/// before writing the snapshot.
const ALWAYS_SKIP: &str = "cloudflare-3.0";

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static REALLOCS: AtomicU64 = AtomicU64::new(0);
static DEALLOCS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
static PEAK_LIVE_BYTES: AtomicU64 = AtomicU64::new(0);

/// Counting wrapper over the system allocator: every alloc/realloc/dealloc updates the atomics
/// above before delegating to `System`, so the pipeline's allocation profile can be read back
/// stage-by-stage without instrumenting `oasts-core` itself. All accounting logic lives in the
/// safe helper functions below; this impl only pairs each `System` call with one counter update.
struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            on_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        on_dealloc(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            on_realloc(layout.size(), new_size);
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn on_alloc(size: usize) {
    let size = size as u64;
    ALLOCS.fetch_add(1, Ordering::Relaxed);
    ALLOC_BYTES.fetch_add(size, Ordering::Relaxed);
    grow_live(size);
}

fn on_dealloc(size: usize) {
    DEALLOCS.fetch_add(1, Ordering::Relaxed);
    shrink_live(size as u64);
}

fn on_realloc(old_size: usize, new_size: usize) {
    let old_size = old_size as u64;
    let new_size = new_size as u64;
    REALLOCS.fetch_add(1, Ordering::Relaxed);
    // "allocated bytes" counts fresh allocation plus reallocation growth, not shrinkage — the
    // metric is bytes newly requested from the allocator, following oxc's
    // tasks/track_memory_allocations convention for its equivalent `sys alloc bytes` field.
    if new_size > old_size {
        let growth = new_size - old_size;
        ALLOC_BYTES.fetch_add(growth, Ordering::Relaxed);
        grow_live(growth);
    } else if old_size > new_size {
        shrink_live(old_size - new_size);
    }
}

fn grow_live(amount: u64) {
    let updated = LIVE_BYTES.fetch_add(amount, Ordering::Relaxed) + amount;
    PEAK_LIVE_BYTES.fetch_max(updated, Ordering::Relaxed);
}

/// Saturating: live tracking resets per key while the allocator counts process-wide, so
/// freeing a pre-reset allocation inside a window would otherwise wrap the gauge to
/// ~2^64 and poison `peakBytes` silently.
fn shrink_live(amount: u64) {
    let mut live = LIVE_BYTES.load(Ordering::Relaxed);
    loop {
        let next = live.saturating_sub(amount);
        match LIVE_BYTES.compare_exchange_weak(live, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => live = observed,
        }
    }
}

/// Resets the four per-stage counters; called immediately before each stage call.
fn reset_stage_counters() {
    ALLOCS.store(0, Ordering::Relaxed);
    REALLOCS.store(0, Ordering::Relaxed);
    DEALLOCS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
}

/// Runs one stage inside a counter window: reset, run, read the counters, and only then
/// allocate the stage label and record the sample. Owning the whole protocol here means a
/// call site cannot mis-order the window — the counters must be read before the label's
/// `to_owned` (or the sample Vec's growth) allocates, or the sample would count itself.
fn run_stage<T>(stages: &mut Vec<StageSample>, name: &str, stage: impl FnOnce() -> T) -> T {
    reset_stage_counters();
    let result = stage();
    let counters = StageCounters {
        allocs: ALLOCS.load(Ordering::Relaxed),
        reallocs: REALLOCS.load(Ordering::Relaxed),
        deallocs: DEALLOCS.load(Ordering::Relaxed),
        alloc_bytes: ALLOC_BYTES.load(Ordering::Relaxed),
    };
    stages.push(StageSample {
        stage: name.to_owned(),
        counters,
    });
    result
}

/// Resets live/peak tracking once per key, immediately before the `loadGraph` stage.
fn reset_live_tracking() {
    LIVE_BYTES.store(0, Ordering::Relaxed);
    PEAK_LIVE_BYTES.store(0, Ordering::Relaxed);
}

fn peak_live_bytes() -> u64 {
    PEAK_LIVE_BYTES.load(Ordering::Relaxed)
}

#[derive(Debug, Parser)]
#[command(
    name = "allocs",
    about = "Per-stage allocation tracker for the oasts-core compile pipeline."
)]
#[group(required = true, multiple = false)]
struct Cli {
    /// Measure every present, non-cloudflare fixture and merge the result into bench/allocs.yaml.
    #[arg(long)]
    update: bool,
    /// Measure only the gated (committed) keys and compare them against bench/allocs.yaml.
    #[arg(long)]
    check: bool,
}

enum Mode {
    Update,
    Check,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // The derive-level group makes --update/--check required and mutually exclusive,
    // so reaching here means exactly one flag is set.
    let mode = if cli.update {
        Mode::Update
    } else {
        Mode::Check
    };

    // rayon builds its global pool lazily on first use, and that construction allocates. Left
    // alone, the pool is built inside whichever fixture is measured first -- and `--update`
    // walks every present fixture while `--check` walks only the committed ones, so the two do
    // not start on the same key and their counters disagree by the pool's allocations. Force the
    // pool into existence outside every measurement window so the recorded numbers describe the
    // pipeline rather than the key set.
    rayon::broadcast(|_| ());

    let root = workspace_root();
    let manifest = match Manifest::load(&root.join("bench/manifest.yaml")) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
    };
    let allocs_path = root.join("bench/allocs.yaml");
    let fixtures_root = root.join("fixtures");

    let result = match mode {
        Mode::Update => run_update(&manifest, &fixtures_root, &allocs_path),
        Mode::Check => run_check(&manifest, &fixtures_root, &allocs_path),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_update(manifest: &Manifest, fixtures_root: &Path, allocs_path: &Path) -> Result<(), Error> {
    let mut measured = Vec::new();
    for entry in &manifest.fixtures {
        if entry.name == ALWAYS_SKIP || !fixture_present(entry, fixtures_root) {
            continue;
        }
        measured.push(measure_key(entry, &fixtures_root.join(&entry.dir))?);
    }

    let existing = alloc_track::read(allocs_path)?;
    let manifest_order = manifest_order(manifest);
    let merged = alloc_track::merge(existing, &measured, &manifest_order);
    alloc_track::write(allocs_path, &merged)?;
    println!(
        "allocs --update: wrote {} ({} key(s), {} measured this run)",
        allocs_path.display(),
        merged.len(),
        measured.len()
    );
    Ok(())
}

fn run_check(manifest: &Manifest, fixtures_root: &Path, allocs_path: &Path) -> Result<(), Error> {
    if !allocs_path.is_file() {
        return Err(Error::new(format!(
            "check: committed snapshot {} not found; run `--update` first",
            allocs_path.display()
        )));
    }

    let mut measured = Vec::new();
    for entry in &manifest.fixtures {
        if entry.name == ALWAYS_SKIP || !matches!(entry.source, FixtureSource::Committed) {
            continue;
        }
        measured.push(measure_key(entry, &fixtures_root.join(&entry.dir))?);
    }

    let committed = alloc_track::read(allocs_path)?;
    let mismatches = alloc_track::compare_keys(&committed, &measured)?;
    if mismatches.is_empty() {
        println!("allocs --check: {} gated key(s) match", measured.len());
        Ok(())
    } else {
        for mismatch in &mismatches {
            eprintln!("{mismatch}");
        }
        Err(Error::new(format!(
            "allocs --check: {} field(s) drifted from {}",
            mismatches.len(),
            allocs_path.display()
        )))
    }
}

fn manifest_order(manifest: &Manifest) -> Vec<(String, String)> {
    manifest
        .fixtures
        .iter()
        .map(|fixture| (fixture.name.clone(), fixture.config.clone()))
        .collect()
}

/// Whether a fixture's document is available to read on this machine: fetched specs are
/// gitignored and often absent, while committed fixtures always ship with the checkout.
fn fixture_present(entry: &FixtureEntry, fixtures_root: &Path) -> bool {
    match &entry.source {
        FixtureSource::Committed => true,
        FixtureSource::Spec(spec) => fixtures_root.join(&entry.dir).join(&spec.path).is_file(),
    }
}

/// Runs one key's compile pipeline stage-by-stage, mirroring `oasts_core::pipeline::compile`
/// exactly (same call sequence and the same two `has_errors` checkpoints), reading `fixture_dir`
/// read-only and dropping the emitted files without writing them.
fn measure_key(entry: &FixtureEntry, fixture_dir: &Path) -> Result<KeySnapshot, Error> {
    let key_label = format!("{}/{}", entry.name, entry.config);

    // Config loading is not measured: it is host setup, not a pipeline stage.
    let config_path = fixture_dir.join(&entry.config);
    let config = load_config(Some(&config_path), fixture_dir).map_err(|diagnostics| {
        Error::new(format!(
            "{key_label}: config load failed:\n{}",
            diag::render_to_string(diagnostics)
        ))
    })?;

    reset_live_tracking();
    let mut sink = DiagnosticSink::new();
    let mut stages = Vec::new();

    let graph = run_stage(&mut stages, "loadGraph", || load_graph(&config, &mut sink));
    let Some(graph) = graph else {
        return Err(stage_failure(&key_label, "loadGraph", sink));
    };

    let ir = run_stage(&mut stages, "parse", || parse(&graph, &mut sink));
    let Some(ir) = ir else {
        return Err(stage_failure(&key_label, "parse", sink));
    };

    // Production retains only the owned source digest inputs after parse, so mirror that lifetime
    // here before measuring analysis. `source_tuples` historically belongs to the emit allocation
    // snapshot; the equivalent clone in that window below keeps the gated counters comparable.
    let source_tuples = graph.source_tuples();
    drop(graph);

    let analyzed = run_stage(&mut stages, "analyze", || analyze(ir, &config, &mut sink));

    let client_model = if config.artifacts.client.enabled {
        Some(run_stage(&mut stages, "clientModel", || {
            build_client_model(&analyzed, &config, &mut sink)
        }))
    } else {
        None
    };

    if sink.has_errors() {
        return Err(stage_failure(&key_label, "analyze/clientModel", sink));
    }

    let files = run_stage(&mut stages, "emit", || {
        // Cloning performs the same Vec/String allocations as `DocumentGraph::source_tuples` did
        // in the historical emit snapshot, without retaining the document graph through emit.
        let source_tuples = source_tuples.clone();
        emit_artifacts(
            &analyzed,
            &config,
            &source_tuples,
            client_model.as_ref(),
            &mut sink,
        )
    });
    drop(files); // never written to disk

    if sink.has_errors() {
        return Err(stage_failure(&key_label, "emit", sink));
    }

    Ok(KeySnapshot {
        fixture: entry.name.clone(),
        config: entry.config.clone(),
        stages,
        peak_bytes: peak_live_bytes(),
    })
}

fn stage_failure(key_label: &str, stage: &str, sink: DiagnosticSink) -> Error {
    Error::new(format!(
        "{key_label}: pipeline failed at {stage}:\n{}",
        diag::render_to_string(sink.into_sorted_vec())
    ))
}
