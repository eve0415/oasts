//! DHAT heap profile entry point. Run instructions live in the `oasts_bench` crate docs.

use std::cmp::Reverse;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use oasts_bench::Error;
use oasts_bench::profile::{compile_fixture, load_fixture, prepare_output};
use serde_json::Value;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

#[derive(Debug, Parser)]
#[command(
    name = "oasts-heap-profile",
    about = "Attribute one full oasts-core compile with DHAT."
)]
struct Cli {
    /// Fixture directory name under fixtures/.
    #[arg(default_value = "github-3.0")]
    fixture: String,
    /// DHAT JSON destination; defaults to target/profiles/<fixture>-heap.json.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Number of allocation sites printed in each ranking.
    #[arg(long, default_value_t = 10)]
    top: usize,
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
    if cli.top == 0 {
        return Err(Error::new("top must be greater than zero"));
    }
    let config = load_fixture(&cli.fixture)?;
    let output = prepare_output(&cli.fixture, "heap.json", cli.output.as_deref())?;
    let profiler = dhat::Profiler::builder().file_name(&output).build();
    let files = compile_fixture(&cli.fixture, &config)?;
    let stats = dhat::HeapStats::get();
    let file_count = files.len();
    drop(files);
    drop(profiler);

    println!(
        "heap profile: fixture={} files={} peak_bytes={} peak_blocks={} total_bytes={} total_blocks={} output={}",
        cli.fixture,
        file_count,
        stats.max_bytes,
        stats.max_blocks,
        stats.total_bytes,
        stats.total_blocks,
        output.display()
    );
    print_top_sites(&output, cli.top)
}

#[derive(Clone)]
struct Site {
    at_peak_bytes: u64,
    total_calls: u64,
    total_bytes: u64,
    location: String,
}

fn print_top_sites(path: &Path, top: usize) -> Result<(), Error> {
    let bytes = std::fs::read(path)
        .map_err(|error| Error::new(format!("reading {}: {error}", path.display())))?;
    let root: Value = serde_json::from_slice(&bytes)
        .map_err(|error| Error::new(format!("parsing {}: {error}", path.display())))?;
    let frames = root
        .get("ftbl")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new(format!("{} has no DHAT frame table", path.display())))?;
    let points = root
        .get("pps")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new(format!("{} has no DHAT program points", path.display())))?;
    let mut sites = points
        .iter()
        .map(|point| parse_site(point, frames))
        .collect::<Result<Vec<_>, _>>()?;

    sites.sort_unstable_by_key(|site| {
        Reverse((site.at_peak_bytes, site.total_bytes, site.total_calls))
    });
    println!("top allocation sites by bytes live at global peak:");
    for (rank, site) in sites
        .iter()
        .filter(|site| site.at_peak_bytes > 0)
        .take(top)
        .enumerate()
    {
        println!(
            "  {}. peak_bytes={} total_calls={} total_bytes={} site={}",
            rank + 1,
            site.at_peak_bytes,
            site.total_calls,
            site.total_bytes,
            site.location
        );
    }

    sites.sort_unstable_by_key(|site| Reverse((site.total_calls, site.total_bytes)));
    println!("top allocation sites by call count:");
    for (rank, site) in sites.iter().take(top).enumerate() {
        println!(
            "  {}. total_calls={} total_bytes={} peak_bytes={} site={}",
            rank + 1,
            site.total_calls,
            site.total_bytes,
            site.at_peak_bytes,
            site.location
        );
    }
    Ok(())
}

fn parse_site(point: &Value, frames: &[Value]) -> Result<Site, Error> {
    let stack = point
        .get("fs")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new("DHAT program point has no frame indices"))?
        .iter()
        .map(|index| {
            let index = index
                .as_u64()
                .and_then(|index| usize::try_from(index).ok())
                .ok_or_else(|| Error::new("DHAT frame index is not a usize"))?;
            frames
                .get(index)
                .and_then(Value::as_str)
                .ok_or_else(|| Error::new(format!("DHAT frame index {index} is out of bounds")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Site {
        at_peak_bytes: point.get("gb").and_then(Value::as_u64).unwrap_or(0),
        total_calls: point.get("tbk").and_then(Value::as_u64).unwrap_or(0),
        total_bytes: point.get("tb").and_then(Value::as_u64).unwrap_or(0),
        location: allocation_site(&stack),
    })
}

fn allocation_site(stack: &[&str]) -> String {
    let frame = stack
        .iter()
        .find(|frame| {
            frame.contains("oasts_core::")
                || frame.contains("oasts_bench::")
                || frame.contains("oasts-core/src/")
                || frame.contains("oasts-bench/src/")
        })
        .or_else(|| {
            stack.iter().find(|frame| {
                !frame.contains("alloc/src/")
                    && !frame.contains("core/src/")
                    && !frame.contains("dhat-")
            })
        })
        .copied()
        .unwrap_or("unknown");
    frame
        .strip_prefix("0x")
        .and_then(|frame| frame.split_once(": "))
        .map_or(frame, |(_, location)| location)
        .to_owned()
}
