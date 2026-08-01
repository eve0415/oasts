//! Shared fixture setup for the feature-gated in-process profilers.

use std::path::{Path, PathBuf};

use oasts_core::config::{ResolvedConfig, load_config};
use oasts_core::diag::{self, DiagnosticSink};
use oasts_core::emit::GeneratedFile;
use oasts_core::pipeline::compile;

use crate::{Error, workspace_root};

/// Loads one fixture's resolved config before a profiler starts, keeping config parsing out of the
/// compile profile just as the stage benchmark does.
pub fn load_fixture(fixture: &str) -> Result<ResolvedConfig, Error> {
    let directory = workspace_root().join("fixtures").join(fixture);
    let config_path = directory.join("oasts.yaml");
    if !config_path.is_file() {
        return Err(Error::new(format!(
            "fixture '{fixture}' is unavailable at {}; fetch it before profiling",
            directory.display()
        )));
    }
    load_config(Some(&config_path), &directory).map_err(|diagnostics| {
        Error::new(format!(
            "loading {fixture} config failed:\n{}",
            diag::render_to_string(diagnostics)
        ))
    })
}

/// Runs the full in-process compile and retains the generated files until the caller has sampled
/// peak heap state.
pub fn compile_fixture(
    fixture: &str,
    config: &ResolvedConfig,
) -> Result<Vec<GeneratedFile>, Error> {
    let mut sink = DiagnosticSink::new();
    let Some(files) = compile(config, true, &mut sink) else {
        return Err(Error::new(format!(
            "compiling {fixture} failed:\n{}",
            diag::render_to_string(sink.into_sorted_vec())
        )));
    };
    if sink.has_errors() {
        return Err(Error::new(format!(
            "compiling {fixture} reported errors:\n{}",
            diag::render_to_string(sink.into_sorted_vec())
        )));
    }
    Ok(files)
}

/// Resolves an explicit output path or the standard `target/profiles` artifact path and creates
/// its parent directory.
pub fn prepare_output(
    fixture: &str,
    suffix: &str,
    output: Option<&Path>,
) -> Result<PathBuf, Error> {
    let output = output.map_or_else(
        || {
            workspace_root()
                .join("target/profiles")
                .join(format!("{fixture}-{suffix}"))
        },
        Path::to_path_buf,
    );
    let parent = output
        .parent()
        .ok_or_else(|| Error::new(format!("output path {} has no parent", output.display())))?;
    std::fs::create_dir_all(parent).map_err(|error| {
        Error::new(format!(
            "creating profile directory {}: {error}",
            parent.display()
        ))
    })?;
    Ok(output)
}
