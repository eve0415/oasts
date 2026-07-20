//! Command-line entry point for the oasts benchmark harness.

use std::io;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use oasts_bench::fetch::{self, CurlFetcher};
use oasts_bench::manifest::Manifest;
use oasts_bench::{run, workspace_root};

#[derive(Debug, Parser)]
#[command(
    name = "oasts-bench",
    about = "Corpus fetch, conformance, and benchmark harness for the oasts generator.",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Download and verify the corpus specs pinned in bench/manifest.yaml.
    Fetch,
    /// Run the per-key generate pipeline and gates over the fixtures.
    Run {
        /// Restrict the run to the named fixture; repeatable. Omit to run every fixture.
        #[arg(long = "fixture", value_name = "NAME")]
        fixtures: Vec<String>,
        /// The runner label recorded with the results.
        #[arg(long, value_name = "LABEL", default_value = "baseline")]
        runner: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let root = workspace_root();
    let manifest = match Manifest::load(&root.join("bench/manifest.yaml")) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
    };

    match cli.command {
        Command::Fetch => {
            let mut stdout = io::stdout().lock();
            match fetch::fetch_all(&manifest, &root, &CurlFetcher, &mut stdout) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::from(1)
                }
            }
        }
        Command::Run { fixtures, runner } => {
            let mut stdout = io::stdout().lock();
            match run::run(&manifest, &root, &fixtures, &runner, &mut stdout) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::from(1)
                }
            }
        }
    }
}
