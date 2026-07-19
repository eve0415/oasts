//! Compilation pipeline shared by every CLI host.
//!
//! Orchestrates loading, parsing, semantic analysis, and emission for one
//! resolved configuration so the standalone binary and the Node binding run
//! the identical sequence.

use crate::config::ResolvedConfig;
use crate::diag::DiagnosticSink;
use crate::emit::{GeneratedFile, emit};
use crate::loader::load_graph;
use crate::parse::parse;
use crate::semantic::analyze;

/// Compiles one resolved configuration into generated files.
///
/// Returns `Some(files)` only when the pipeline reached emission and
/// `should_emit` is true; diagnostics accumulate in `sink` either way.
pub fn compile(
    config: &ResolvedConfig,
    should_emit: bool,
    sink: &mut DiagnosticSink,
) -> Option<Vec<GeneratedFile>> {
    let graph = load_graph(config, sink)?;
    let ir = parse(&graph, sink)?;
    let analyzed = analyze(ir, config, sink);
    if sink.has_errors() {
        return None;
    }
    let source_tuples = graph.source_tuples();
    let files = emit(&analyzed, config, &source_tuples, sink);
    should_emit.then_some(files)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::config::load_config;

    #[test]
    fn compile_emits_files_only_when_requested() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/petstore-3.0");
        for file_name in ["openapi.yaml", "oasts.yaml"] {
            fs::copy(source.join(file_name), temp.path().join(file_name)).expect("copy fixture");
        }
        let config = load_config(None, temp.path()).expect("resolved config");

        let mut sink = DiagnosticSink::new();
        let files = compile(&config, true, &mut sink).expect("emitted files");
        assert!(!files.is_empty());
        assert!(!sink.has_errors());

        let mut sink = DiagnosticSink::new();
        assert!(compile(&config, false, &mut sink).is_none());
        assert!(!sink.has_errors());
    }

    #[test]
    fn compile_stops_on_load_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("oasts.yaml"),
            "schemaVersion: 1\ninput: { path: ./missing.yaml }\noutput: ./generated\n",
        )
        .expect("config");
        let config = load_config(None, temp.path()).expect("resolved config");

        let mut sink = DiagnosticSink::new();
        assert!(compile(&config, true, &mut sink).is_none());
        assert!(sink.has_errors());
    }
}
