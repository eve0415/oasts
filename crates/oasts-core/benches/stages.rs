use std::fmt;
use std::path::Path;

use divan::Bencher;
use oasts_core::client_model::build_client_model as run_build_client_model;
use oasts_core::config::{ResolvedConfig, load_config};
use oasts_core::diag::DiagnosticSink;
use oasts_core::emit::emit_artifacts as run_emit_artifacts;
use oasts_core::inputs::InputRecorder;
use oasts_core::ir::Ir;
use oasts_core::loader::{DocumentGraph, load_graph as run_load_graph};
use oasts_core::parse::parse as run_parse;
use oasts_core::pipeline::compile as run_compile;
use oasts_core::semantic::{Analyzed, analyze as run_analyze};
use oasts_core::source::FetcherHandle;
use oasts_core::writer::{check_drift as run_check_drift, write as run_write};

const SAMPLE_COUNT: u32 = 10;

const FIXTURES: &[FixtureSpec] = &[
    FixtureSpec::committed("petstore-3.0", "../../fixtures/petstore-3.0"),
    FixtureSpec::committed("pathological-3.1", "../../fixtures/pathological-3.1"),
    FixtureSpec::committed("client-showcase-3.1", "../../fixtures/client-showcase-3.1"),
    FixtureSpec::fetched("github-3.0", "../../fixtures/github-3.0"),
    FixtureSpec::fetched("stripe-3.0", "../../fixtures/stripe-3.0"),
    FixtureSpec::fetched(
        "kubernetes-core-v1-3.0",
        "../../fixtures/kubernetes-core-v1-3.0",
    ),
];

#[derive(Clone, Copy)]
struct FixtureSpec {
    name: &'static str,
    relative_dir: &'static str,
    fetched: bool,
}

impl FixtureSpec {
    const fn committed(name: &'static str, relative_dir: &'static str) -> Self {
        Self {
            name,
            relative_dir,
            fetched: false,
        }
    }

    const fn fetched(name: &'static str, relative_dir: &'static str) -> Self {
        Self {
            name,
            relative_dir,
            fetched: true,
        }
    }
}

struct Fixture {
    name: &'static str,
    config: ResolvedConfig,
}

impl fmt::Display for Fixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name)
    }
}

fn main() {
    divan::main();
}

fn fixtures() -> Vec<Fixture> {
    FIXTURES
        .iter()
        .filter_map(|spec| {
            let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(spec.relative_dir);
            if spec.fetched && !dir.join("openapi.json").is_file() {
                return None;
            }
            let config =
                load_config(Some(&dir.join("oasts.yaml")), &dir).unwrap_or_else(|diagnostics| {
                    panic!("failed to load {}: {diagnostics:#?}", spec.name)
                });
            Some(Fixture {
                name: spec.name,
                config,
            })
        })
        .collect()
}

/// The same fixtures under their non-default artifact configs. `fixtures()` reads only
/// `oasts.yaml`, which for github is types-only, so the `emit` bench never sees the msw or zod
/// emitters at that scale. This keeps the existing benches' argument set — and therefore their
/// baselines — untouched.
const ARTIFACT_CONFIGS: &[(&str, &str, &str)] = &[
    (
        "github-3.0-msw",
        "../../fixtures/github-3.0",
        "oasts-msw.yaml",
    ),
    (
        "github-3.0-zod",
        "../../fixtures/github-3.0",
        "oasts-zod.yaml",
    ),
];

fn artifact_fixtures() -> Vec<Fixture> {
    ARTIFACT_CONFIGS
        .iter()
        .filter_map(|(name, relative_dir, config_file)| {
            let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_dir);
            if !dir.join("openapi.json").is_file() {
                return None;
            }
            let config = load_config(Some(&dir.join(config_file)), &dir)
                .unwrap_or_else(|diagnostics| panic!("failed to load {name}: {diagnostics:#?}"));
            Some(Fixture { name, config })
        })
        .collect()
}

fn client_fixtures() -> Vec<Fixture> {
    fixtures()
        .into_iter()
        .filter(|fixture| fixture.config.artifacts.client.enabled)
        .collect()
}

fn prepared_graph(fixture: &Fixture) -> DocumentGraph {
    let mut sink = DiagnosticSink::new();
    let graph = run_load_graph(&fixture.config, &mut InputRecorder::off(), &mut sink)
        .unwrap_or_else(|| {
            panic!(
                "failed to load graph for {}: {:#?}",
                fixture.name,
                sink.as_slice()
            )
        });
    assert!(
        !sink.has_errors(),
        "graph diagnostics for {}: {:#?}",
        fixture.name,
        sink.as_slice()
    );
    graph
}

fn prepared_ir(fixture: &Fixture) -> Ir {
    let graph = prepared_graph(fixture);
    let mut sink = DiagnosticSink::new();
    let ir = run_parse(&graph, &mut sink)
        .unwrap_or_else(|| panic!("failed to parse {}: {:#?}", fixture.name, sink.as_slice()));
    assert!(
        !sink.has_errors(),
        "parse diagnostics for {}: {:#?}",
        fixture.name,
        sink.as_slice()
    );
    ir
}

fn prepared_analysis(fixture: &Fixture) -> Analyzed {
    let mut sink = DiagnosticSink::new();
    let analyzed = run_analyze(prepared_ir(fixture), &fixture.config, &mut sink);
    assert!(
        !sink.has_errors(),
        "analysis diagnostics for {}: {:#?}",
        fixture.name,
        sink.as_slice()
    );
    analyzed
}

fn prepared_files(fixture: &Fixture) -> Vec<oasts_core::emit::GeneratedFile> {
    let mut sink = DiagnosticSink::new();
    let files = run_compile(
        &fixture.config,
        FetcherHandle::None,
        true,
        &mut InputRecorder::off(),
        &mut sink,
    )
    .unwrap_or_else(|| panic!("failed to compile {}: {:#?}", fixture.name, sink.as_slice()));
    assert!(
        !sink.has_errors(),
        "compile diagnostics for {}: {:#?}",
        fixture.name,
        sink.as_slice()
    );
    files
}

#[divan::bench(args = fixtures(), sample_count = SAMPLE_COUNT)]
fn load_graph(bencher: Bencher, fixture: &Fixture) {
    bencher
        .with_inputs(DiagnosticSink::new)
        .bench_values(|mut sink| {
            let graph = run_load_graph(&fixture.config, &mut InputRecorder::off(), &mut sink);
            (graph, sink)
        });
}

#[divan::bench(args = fixtures(), sample_count = SAMPLE_COUNT)]
fn parse(bencher: Bencher, fixture: &Fixture) {
    let graph = prepared_graph(fixture);
    bencher
        .with_inputs(DiagnosticSink::new)
        .bench_values(|mut sink| {
            let ir = run_parse(&graph, &mut sink);
            (ir, sink)
        });
}

#[divan::bench(args = fixtures(), sample_count = SAMPLE_COUNT)]
fn analyze(bencher: Bencher, fixture: &Fixture) {
    let ir = prepared_ir(fixture);
    bencher
        .with_inputs(|| (ir.clone(), DiagnosticSink::new()))
        .bench_values(|(ir, mut sink)| {
            let analyzed = run_analyze(ir, &fixture.config, &mut sink);
            (analyzed, sink)
        });
}

#[divan::bench(args = client_fixtures(), sample_count = SAMPLE_COUNT)]
fn build_client_model(bencher: Bencher, fixture: &Fixture) {
    let analyzed = prepared_analysis(fixture);
    bencher
        .with_inputs(DiagnosticSink::new)
        .bench_values(|mut sink| {
            let model = run_build_client_model(&analyzed, &fixture.config, &mut sink);
            (model, sink)
        });
}

#[divan::bench(args = fixtures(), sample_count = SAMPLE_COUNT)]
fn emit(bencher: Bencher, fixture: &Fixture) {
    bench_emit(bencher, fixture);
}

/// Emission cost for the artifacts the default config leaves off. Emission only — the files are
/// returned and dropped, never written, so this is emitter CPU with the writer excluded.
#[divan::bench(args = artifact_fixtures(), sample_count = SAMPLE_COUNT)]
fn emit_artifact_configs(bencher: Bencher, fixture: &Fixture) {
    bench_emit(bencher, fixture);
}

fn bench_emit(bencher: Bencher, fixture: &Fixture) {
    let graph = prepared_graph(fixture);
    let mut sink = DiagnosticSink::new();
    let ir = run_parse(&graph, &mut sink)
        .unwrap_or_else(|| panic!("failed to parse {}: {:#?}", fixture.name, sink.as_slice()));
    let analyzed = run_analyze(ir, &fixture.config, &mut sink);
    let client_model = fixture
        .config
        .artifacts
        .client
        .enabled
        .then(|| run_build_client_model(&analyzed, &fixture.config, &mut sink));
    assert!(
        !sink.has_errors(),
        "emission preparation diagnostics for {}: {:#?}",
        fixture.name,
        sink.as_slice()
    );
    let source_tuples = graph.source_tuples();

    bencher
        .with_inputs(DiagnosticSink::new)
        .bench_values(|mut sink| {
            let files = run_emit_artifacts(
                &analyzed,
                &fixture.config,
                &source_tuples,
                client_model.as_ref(),
                &mut InputRecorder::off(),
                &mut sink,
            );
            (files, sink)
        });
}

#[divan::bench(args = fixtures(), sample_count = SAMPLE_COUNT)]
fn compile(bencher: Bencher, fixture: &Fixture) {
    bencher
        .with_inputs(DiagnosticSink::new)
        .bench_values(|mut sink| {
            let files = run_compile(
                &fixture.config,
                FetcherHandle::None,
                true,
                &mut InputRecorder::off(),
                &mut sink,
            );
            (files, sink)
        });
}

#[divan::bench(args = fixtures(), sample_count = SAMPLE_COUNT)]
fn write(bencher: Bencher, fixture: &Fixture) {
    let files = prepared_files(fixture);

    // The CLI's important write case is steady-state regeneration. Set up a
    // fresh output tree outside the timer, then measure the unchanged write.
    bencher
        .with_inputs(|| {
            let temp = tempfile::tempdir().expect("benchmark tempdir");
            let output = temp.path().join("generated");
            run_write(&output, files.clone()).unwrap_or_else(|diagnostics| {
                panic!("failed to prepare {}: {diagnostics:#?}", fixture.name)
            });
            (temp, output, files.clone())
        })
        .bench_values(|(temp, output, files)| {
            let report = run_write(&output, files);
            (temp, report)
        });
}

#[divan::bench(args = fixtures(), sample_count = SAMPLE_COUNT)]
fn check_drift(bencher: Bencher, fixture: &Fixture) {
    let files = prepared_files(fixture);

    bencher
        .with_inputs(|| {
            let temp = tempfile::tempdir().expect("benchmark tempdir");
            let output = temp.path().join("generated");
            run_write(&output, files.clone()).unwrap_or_else(|diagnostics| {
                panic!("failed to prepare {}: {diagnostics:#?}", fixture.name)
            });
            (temp, output, files.clone())
        })
        .bench_values(|(temp, output, files)| {
            let report = run_check_drift(&output, files);
            (temp, report)
        });
}
