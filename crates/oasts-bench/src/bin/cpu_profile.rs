//! CPU sampling profile entry point. Run instructions live in the `oasts_bench` crate docs.

use std::fs::File;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use oasts_bench::Error;
use oasts_bench::profile::{compile_fixture, load_fixture, prepare_output};

#[derive(Debug, Parser)]
#[command(
    name = "oasts-cpu-profile",
    about = "Sample one full oasts-core compile and emit a flamegraph SVG."
)]
struct Cli {
    /// Fixture directory name under fixtures/.
    #[arg(default_value = "github-3.0")]
    fixture: String,
    /// Flamegraph destination; defaults to target/profiles/<fixture>-cpu.svg.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// SIGPROF samples per second.
    #[arg(long, default_value_t = 1_000)]
    frequency: i32,
}

fn main() -> ExitCode {
    match run(&Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: &Cli) -> Result<(), Error> {
    if cli.frequency <= 0 {
        return Err(Error::new("frequency must be greater than zero"));
    }
    let config = load_fixture(&cli.fixture)?;
    let output = prepare_output(&cli.fixture, "cpu.svg", cli.output.as_deref())?;
    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(cli.frequency)
        .blocklist(&["libc", "libgcc_s", "pthread", "vdso"])
        .build()
        .map_err(|error| Error::new(format!("starting CPU profiler: {error}")))?;
    let files = compile_fixture(&cli.fixture, &config)?;
    let report = guard
        .report()
        .build()
        .map_err(|error| Error::new(format!("building CPU profile: {error}")))?;
    let samples = report.data.values().sum::<isize>();
    let file = File::create(&output)
        .map_err(|error| Error::new(format!("creating {}: {error}", output.display())))?;
    report
        .flamegraph(file)
        .map_err(|error| Error::new(format!("writing {}: {error}", output.display())))?;
    println!(
        "cpu profile: fixture={} files={} samples={} output={}",
        cli.fixture,
        files.len(),
        samples,
        output.display()
    );
    Ok(())
}
