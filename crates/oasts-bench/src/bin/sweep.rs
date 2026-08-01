//! Vendor-corpus diagnostic sweep for the release Oasts CLI.
//!
//! Generation failures are measurements rather than harness failures: the report preserves every
//! diagnostic and every output line the parser did not recognize, so renderer drift or unsupported
//! corpus constructs cannot disappear behind a successful sweep process.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::time::Duration;

use clap::{Parser, Subcommand};
use oasts_bench::conformance::{check_conformance, generated_files};
use oasts_bench::fetch::{CurlFetcher, Fetcher, sha256_hex};
use oasts_bench::results::atomic_write;
use oasts_bench::sample::{SampleOutcome, timed_sample};
use oasts_bench::{Error, workspace_root};
use tempfile::NamedTempFile;
use yaml_rust2::{Yaml, YamlLoader};

#[derive(Debug, Parser)]
#[command(
    name = "oasts-sweep",
    about = "Sweep vendor OpenAPI documents for Oasts diagnostics.",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Download corpus documents, verifying pinned SHA-256 digests before replacing files.
    Fetch {
        /// Restrict the fetch to a named corpus entry; repeatable.
        #[arg(long = "name", value_name = "NAME")]
        names: Vec<String>,
    },
    /// Run the release compiler over the selected corpus documents.
    Run {
        /// Restrict the run to a named corpus entry; repeatable.
        #[arg(long = "name", value_name = "NAME")]
        names: Vec<String>,
        /// Number of corpus entries to process concurrently.
        #[arg(long, value_name = "N")]
        jobs: Option<usize>,
        /// Machine-readable YAML report path, relative to the workspace root unless absolute.
        #[arg(long, value_name = "PATH", default_value = "bench/sweep-report.yaml")]
        report: PathBuf,
        /// Record per-spec harness failures and finish the rest of the sweep.
        #[arg(long)]
        keep_going: bool,
        /// Typecheck each successfully generated config with the workspace-pinned compiler.
        #[arg(long)]
        typecheck: bool,
    },
}

#[derive(Clone, Debug)]
struct CorpusSpec {
    name: String,
    title: String,
    url: String,
    file: String,
    sha256: Option<String>,
    client: bool,
}

#[derive(Debug)]
struct CorpusManifest {
    specs: Vec<CorpusSpec>,
}

impl CorpusManifest {
    /// Keeps manifest errors at the command boundary, where a missing curated file is actionable.
    fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            Error::new(format!(
                "reading corpus manifest {}: {error}; create bench/corpus.yaml before running the sweep",
                path.display()
            ))
        })?;
        Self::from_str(&text)
    }

    fn from_str(text: &str) -> Result<Self, Error> {
        let documents = YamlLoader::load_from_str(text)
            .map_err(|error| Error::new(format!("corpus manifest YAML parse error: {error}")))?;
        let root = documents
            .first()
            .ok_or_else(|| Error::new("corpus manifest is empty"))?;
        ensure_only_keys(root, &["schemaVersion", "specs"], "corpus manifest")?;

        let schema_version = required_i64(root, "schemaVersion", "corpus manifest")?;
        if schema_version != 1 {
            return Err(Error::new(format!(
                "corpus manifest: unsupported schemaVersion {schema_version} (expected 1)"
            )));
        }
        let entries = field(root, "specs", "corpus manifest")?
            .as_vec()
            .ok_or_else(|| Error::new("corpus manifest: 'specs' must be a sequence"))?;
        if entries.is_empty() {
            return Err(Error::new(
                "corpus manifest: 'specs' must contain at least one entry",
            ));
        }

        let mut names = HashSet::new();
        let mut specs = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let context = format!("specs[{index}]");
            ensure_only_keys(
                entry,
                &["name", "title", "url", "file", "sha256", "client"],
                &context,
            )?;
            let name = required_string(entry, "name", &context)?;
            if !is_kebab_case(&name) {
                return Err(Error::new(format!(
                    "{context}: name '{name}' must be kebab-case"
                )));
            }
            if !names.insert(name.clone()) {
                return Err(Error::new(format!(
                    "{context}: duplicate corpus name '{name}'"
                )));
            }
            let title = required_nonempty_string(entry, "title", &context)?;
            let url = required_nonempty_string(entry, "url", &context)?;
            let file = required_nonempty_string(entry, "file", &context)?;
            validate_basename(&file, &context)?;
            let sha256 = optional_string(entry, "sha256", &context)?;
            if let Some(digest) = &sha256
                && (digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
            {
                return Err(Error::new(format!(
                    "{context}: sha256 must contain exactly 64 hexadecimal digits"
                )));
            }
            let client = optional_bool(entry, "client", &context)?.unwrap_or(true);
            specs.push(CorpusSpec {
                name,
                title,
                url,
                file,
                sha256,
                client,
            });
        }
        Ok(Self { specs })
    }
}

fn field<'a>(node: &'a Yaml, key: &str, context: &str) -> Result<&'a Yaml, Error> {
    let hash = node
        .as_hash()
        .ok_or_else(|| Error::new(format!("{context}: expected a mapping")))?;
    hash.get(&Yaml::String(key.to_owned()))
        .filter(|value| !matches!(value, Yaml::BadValue))
        .ok_or_else(|| Error::new(format!("{context}: missing key '{key}'")))
}

fn optional_field<'a>(node: &'a Yaml, key: &str, context: &str) -> Result<Option<&'a Yaml>, Error> {
    let hash = node
        .as_hash()
        .ok_or_else(|| Error::new(format!("{context}: expected a mapping")))?;
    Ok(hash
        .get(&Yaml::String(key.to_owned()))
        .filter(|value| !matches!(value, Yaml::BadValue | Yaml::Null)))
}

fn ensure_only_keys(node: &Yaml, allowed: &[&str], context: &str) -> Result<(), Error> {
    let hash = node
        .as_hash()
        .ok_or_else(|| Error::new(format!("{context}: expected a mapping")))?;
    for key in hash.keys() {
        let key = key
            .as_str()
            .ok_or_else(|| Error::new(format!("{context}: keys must be strings")))?;
        if !allowed.contains(&key) {
            return Err(Error::new(format!("{context}: unknown key '{key}'")));
        }
    }
    Ok(())
}

fn required_string(node: &Yaml, key: &str, context: &str) -> Result<String, Error> {
    field(node, key, context)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::new(format!("{context}: key '{key}' must be a string")))
}

fn required_nonempty_string(node: &Yaml, key: &str, context: &str) -> Result<String, Error> {
    let value = required_string(node, key, context)?;
    if value.is_empty() {
        return Err(Error::new(format!(
            "{context}: key '{key}' must not be empty"
        )));
    }
    Ok(value)
}

fn required_i64(node: &Yaml, key: &str, context: &str) -> Result<i64, Error> {
    field(node, key, context)?
        .as_i64()
        .ok_or_else(|| Error::new(format!("{context}: key '{key}' must be an integer")))
}

fn optional_string(node: &Yaml, key: &str, context: &str) -> Result<Option<String>, Error> {
    optional_field(node, key, context)?
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::new(format!("{context}: key '{key}' must be a string")))
        })
        .transpose()
}

fn optional_bool(node: &Yaml, key: &str, context: &str) -> Result<Option<bool>, Error> {
    optional_field(node, key, context)?
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| Error::new(format!("{context}: key '{key}' must be a boolean")))
        })
        .transpose()
}

fn is_kebab_case(value: &str) -> bool {
    !value.is_empty()
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn validate_basename(value: &str, context: &str) -> Result<(), Error> {
    let path = Path::new(value);
    let mut components = path.components();
    let valid = matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
        && !value.contains('\\');
    if !valid {
        return Err(Error::new(format!(
            "{context}: file '{value}' must be a basename"
        )));
    }
    Ok(())
}

#[derive(Debug)]
enum FetchStatus {
    Verified,
    Downloaded,
    Unpinned(String),
}

fn fetch_selected(
    manifest: &CorpusManifest,
    root: &Path,
    names: &[String],
    fetcher: &dyn Fetcher,
    out: &mut dyn io::Write,
) -> Result<(), Error> {
    let selected = select_specs(&manifest.specs, names)?;
    let mut failures = Vec::new();
    for spec in selected {
        match fetch_one(spec, &root.join("corpus"), fetcher) {
            Ok(FetchStatus::Verified) => {
                let _ = writeln!(out, "verified: {}", spec.name);
            }
            Ok(FetchStatus::Downloaded) => {
                let _ = writeln!(out, "downloaded: {}", spec.name);
            }
            Ok(FetchStatus::Unpinned(digest)) => {
                let _ = writeln!(out, "{}  {digest}", spec.name);
            }
            Err(error) => {
                let _ = writeln!(out, "FAILED: {} — {error}", spec.name);
                failures.push(spec.name.clone());
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Error::new(format!(
            "fetch failed for {} corpus spec(s): {}",
            failures.len(),
            failures.join(", ")
        )))
    }
}

fn fetch_one(
    spec: &CorpusSpec,
    corpus_root: &Path,
    fetcher: &dyn Fetcher,
) -> Result<FetchStatus, Error> {
    let directory = corpus_root.join(&spec.name);
    let target = directory.join(&spec.file);
    if let Some(expected) = &spec.sha256
        && target.is_file()
        && sha256_hex(&target)?.eq_ignore_ascii_case(expected)
    {
        return Ok(FetchStatus::Verified);
    }

    std::fs::create_dir_all(&directory)
        .map_err(|error| Error::new(format!("creating {}: {error}", directory.display())))?;
    let temp = NamedTempFile::new_in(&directory).map_err(|error| {
        Error::new(format!(
            "creating temp file in {}: {error}",
            directory.display()
        ))
    })?;
    fetcher.fetch(&spec.url, temp.path())?;
    let actual = sha256_hex(temp.path())?;
    if let Some(expected) = &spec.sha256
        && !actual.eq_ignore_ascii_case(expected)
    {
        return Err(Error::new(format!(
            "digest mismatch: expected {expected}, got {actual}"
        )));
    }
    temp.persist(&target)
        .map_err(|error| Error::new(format!("persisting {}: {error}", target.display())))?;

    if spec.sha256.is_some() {
        Ok(FetchStatus::Downloaded)
    } else {
        Ok(FetchStatus::Unpinned(actual))
    }
}

fn select_specs<'a>(
    specs: &'a [CorpusSpec],
    names: &[String],
) -> Result<Vec<&'a CorpusSpec>, Error> {
    for name in names {
        if !specs.iter().any(|spec| &spec.name == name) {
            return Err(Error::new(format!(
                "unknown corpus spec '{name}' (not in bench/corpus.yaml)"
            )));
        }
    }
    if names.is_empty() {
        Ok(specs.iter().collect())
    } else {
        Ok(specs
            .iter()
            .filter(|spec| names.iter().any(|name| name == &spec.name))
            .collect())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigKind {
    Types,
    Full,
}

impl ConfigKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Types => "types",
            Self::Full => "full",
        }
    }

    const fn filename(self) -> &'static str {
        match self {
            Self::Types => "types.yaml",
            Self::Full => "full.yaml",
        }
    }

    const fn output_glob(self) -> &'static str {
        match self {
            Self::Types => "generated/**/*.ts",
            Self::Full => "generated-full/**/*.ts",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Severity {
    Error,
    Warning,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedDiagnostic {
    severity: Severity,
    code: String,
    message: String,
    pointer: Option<String>,
}

#[derive(Debug, Default)]
struct ParsedOutput {
    diagnostics: Vec<ParsedDiagnostic>,
    unparsed_lines: usize,
    emitted_files: Option<usize>,
}

impl ParsedOutput {
    fn merge(&mut self, mut other: Self) {
        self.diagnostics.append(&mut other.diagnostics);
        self.unparsed_lines += other.unparsed_lines;
        if other.emitted_files.is_some() {
            self.emitted_files = other.emitted_files;
        }
    }
}

fn parse_output(stdout: &str, stderr: &str) -> ParsedOutput {
    let mut parsed = ParsedOutput::default();
    let mut pending_location = None;
    for line in stderr.lines().chain(stdout.lines()) {
        if let Some((severity, code, message)) = parse_header(line) {
            parsed.diagnostics.push(ParsedDiagnostic {
                severity,
                code,
                message,
                pointer: None,
            });
            pending_location = Some(parsed.diagnostics.len() - 1);
        } else if let Some(location) = line.strip_prefix("  --> ") {
            if let Some(index) = pending_location.take() {
                if let Some((_, pointer)) = location.rsplit_once(' ')
                    && pointer.starts_with('/')
                {
                    parsed.diagnostics[index].pointer = Some(pointer.to_owned());
                }
            } else {
                parsed.unparsed_lines += 1;
            }
        } else if let Some(count) = parse_generated_summary(line) {
            parsed.emitted_files = Some(count);
        } else {
            parsed.unparsed_lines += 1;
        }
    }
    parsed
}

fn parse_header(line: &str) -> Option<(Severity, String, String)> {
    let (severity, rest) = if let Some(rest) = line.strip_prefix("error[") {
        (Severity::Error, rest)
    } else {
        (Severity::Warning, line.strip_prefix("warning[")?)
    };
    let (code, message) = rest.split_once("]: ")?;
    let suffix = code.strip_prefix("OASTS")?;
    if suffix.len() != 4 || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some((severity, code.to_owned(), message.to_owned()))
}

fn parse_generated_summary(line: &str) -> Option<usize> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "generated" {
        return None;
    }
    let count = parts.next()?.parse().ok()?;
    if parts.next()? != "files" || parts.next().is_some() {
        return None;
    }
    Some(count)
}

#[derive(Debug)]
struct ConfigReport {
    config: ConfigKind,
    exit_code: i32,
    wall_ms: u64,
    emitted_file_count: usize,
    determinism_passed: Option<bool>,
    oxc_parse_passed: Option<bool>,
    conformance_failure: Option<String>,
    error_count: usize,
    warning_count: usize,
    unparsed_lines: usize,
    base_url_fallback_used: bool,
    diagnostics: Vec<ParsedDiagnostic>,
    typecheck: Option<TypecheckReport>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TypeScriptDiagnostic {
    code: String,
    file: Option<String>,
    line: Option<usize>,
    column: Option<usize>,
    message: String,
}

#[derive(Debug)]
struct TypecheckReport {
    exit_code: i32,
    diagnostics: Vec<TypeScriptDiagnostic>,
    failure: Option<String>,
}

impl TypecheckReport {
    const fn passed(&self) -> bool {
        self.exit_code == 0
    }
}

#[derive(Debug)]
struct SpecReport {
    name: String,
    title: String,
    client: bool,
    configs: Vec<ConfigReport>,
    harness_error: Option<String>,
}

impl SpecReport {
    fn harness_failure(spec: &CorpusSpec, error: &Error) -> Self {
        Self {
            name: spec.name.clone(),
            title: spec.title.clone(),
            client: spec.client,
            configs: Vec::new(),
            harness_error: Some(error.to_string()),
        }
    }
}

struct RunContext<'a> {
    binary: &'a Path,
    corpus_root: &'a Path,
    workspace_root: &'a Path,
    typecheck: bool,
}

struct RunOptions<'a> {
    jobs: Option<usize>,
    report_path: &'a Path,
    keep_going: bool,
    typecheck: bool,
}

fn run_sweep(
    manifest: &CorpusManifest,
    root: &Path,
    names: &[String],
    options: &RunOptions<'_>,
    out: &mut dyn io::Write,
) -> Result<(), Error> {
    let binary = root.join("target/release/oasts");
    if !binary.is_file() {
        return Err(Error::new(
            "release binary target/release/oasts not found; run `cargo build --release -p oasts` first",
        ));
    }
    let selected = select_specs(&manifest.specs, names)?;
    let job_count = resolve_jobs(options.jobs)?.min(selected.len().max(1));
    let context = RunContext {
        binary: &binary,
        corpus_root: &root.join("corpus"),
        workspace_root: root,
        typecheck: options.typecheck,
    };
    let measured = measure_parallel(&selected, &context, job_count)?;

    let mut reports = Vec::with_capacity(measured.len());
    let mut failures = Vec::new();
    for (spec, result) in selected.iter().zip(measured) {
        match result {
            Ok(report) => reports.push(report),
            Err(error) => {
                failures.push(format!("{}: {error}", spec.name));
                if options.keep_going {
                    reports.push(SpecReport::harness_failure(spec, &error));
                }
            }
        }
    }
    if !failures.is_empty() && !options.keep_going {
        return Err(Error::new(format!(
            "run hit {} harness failure(s): {}",
            failures.len(),
            failures.join("; ")
        )));
    }

    let codes = aggregate_codes(&reports);
    let ts_codes = aggregate_ts_codes(&reports);
    let path = resolve_report_path(root, options.report_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| Error::new(format!("creating {}: {error}", parent.display())))?;
    }
    atomic_write(
        &path,
        &report_yaml(&reports, &codes, &ts_codes, options.typecheck),
    )?;
    print_summary(&reports, &codes, &ts_codes, out);
    let _ = writeln!(out, "wrote {}", path.display());
    Ok(())
}

fn resolve_jobs(jobs: Option<usize>) -> Result<usize, Error> {
    match jobs {
        Some(0) => Err(Error::new("--jobs must be greater than zero")),
        Some(value) => Ok(value),
        None => Ok(std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1)
            .min(8)),
    }
}

fn resolve_report_path(root: &Path, report: &Path) -> PathBuf {
    if report.is_absolute() {
        report.to_path_buf()
    } else {
        root.join(report)
    }
}

fn measure_parallel(
    specs: &[&CorpusSpec],
    context: &RunContext<'_>,
    jobs: usize,
) -> Result<Vec<Result<SpecReport, Error>>, Error> {
    std::thread::scope(|scope| {
        let worker_count = jobs.min(specs.len().max(1));
        let mut handles = Vec::with_capacity(worker_count);
        for worker in 0..worker_count {
            handles.push(scope.spawn(move || {
                let mut results = Vec::new();
                for index in (worker..specs.len()).step_by(worker_count) {
                    results.push((index, measure_spec(specs[index], context)));
                }
                results
            }));
        }

        let mut indexed = Vec::with_capacity(specs.len());
        for handle in handles {
            match handle.join() {
                Ok(mut results) => indexed.append(&mut results),
                Err(_) => return Err(Error::new("sweep worker thread panicked")),
            }
        }
        indexed.sort_by_key(|(index, _)| *index);
        Ok(indexed.into_iter().map(|(_, result)| result).collect())
    })
}

fn measure_spec(spec: &CorpusSpec, context: &RunContext<'_>) -> Result<SpecReport, Error> {
    let source = context.corpus_root.join(&spec.name).join(&spec.file);
    if !source.is_file() {
        return Err(Error::new(format!(
            "corpus document {} is missing; run `oasts-sweep fetch --name {}` first",
            source.display(),
            spec.name
        )));
    }

    let workdir =
        tempfile::tempdir().map_err(|error| Error::new(format!("creating workdir: {error}")))?;
    oasts_bench::link_node_modules(workdir.path(), context.workspace_root)?;
    let staged = workdir.path().join(&spec.file);
    std::fs::copy(&source, &staged).map_err(|error| {
        Error::new(format!(
            "staging corpus document {}: {error}",
            source.display()
        ))
    })?;
    write_config(
        &workdir.path().join(ConfigKind::Types.filename()),
        spec,
        ConfigKind::Types,
        false,
    )?;
    write_config(
        &workdir.path().join(ConfigKind::Full.filename()),
        spec,
        ConfigKind::Full,
        false,
    )?;

    let mut configs = vec![measure_config(
        spec,
        workdir.path(),
        ConfigKind::Types,
        context.binary,
        context.workspace_root,
        context.typecheck,
    )?];
    if spec.client {
        remove_output(workdir.path(), "generated")?;
        configs.push(measure_config(
            spec,
            workdir.path(),
            ConfigKind::Full,
            context.binary,
            context.workspace_root,
            context.typecheck,
        )?);
    }
    Ok(SpecReport {
        name: spec.name.clone(),
        title: spec.title.clone(),
        client: spec.client,
        configs,
        harness_error: None,
    })
}

fn measure_config(
    spec: &CorpusSpec,
    workdir: &Path,
    config: ConfigKind,
    binary: &Path,
    workspace_root: &Path,
    typecheck: bool,
) -> Result<ConfigReport, Error> {
    let config_path = workdir.join(config.filename());

    let first = generate_once(binary, config.filename(), workdir)?;
    let mut wall = first.wall;
    let mut exit_code = first.exit_code;
    let mut parsed = parse_output(&first.stdout, &first.stderr);
    let mut fallback_used = false;

    if config == ConfigKind::Full && should_retry_base_url(exit_code, &parsed.diagnostics) {
        write_config(&config_path, spec, config, true)?;
        let retry = generate_once(binary, config.filename(), workdir)?;
        wall += retry.wall;
        exit_code = retry.exit_code;
        parsed.merge(parse_output(&retry.stdout, &retry.stderr));
        fallback_used = true;
    }

    let (
        emitted_file_count,
        determinism_passed,
        oxc_parse_passed,
        conformance_failure,
        typecheck_report,
    ) = if exit_code == 0 {
        let files = generated_files(workdir)?;
        let count = parsed.emitted_files.unwrap_or(files.len());
        let conformance = match check_conformance(&files, workdir, binary, config.filename()) {
            Ok(()) => (count, Some(true), Some(true), None),
            Err(error) => {
                let message = error.to_string();
                if message.starts_with("oxc parse error") {
                    (count, Some(true), Some(false), Some(message))
                } else {
                    (count, Some(false), None, Some(message))
                }
            }
        };
        let typecheck_report = typecheck
            .then(|| run_typecheck(workspace_root, workdir, config))
            .transpose()?;
        (
            conformance.0,
            conformance.1,
            conformance.2,
            conformance.3,
            typecheck_report,
        )
    } else {
        (parsed.emitted_files.unwrap_or(0), None, None, None, None)
    };

    let error_count = parsed
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == Severity::Error)
        .count();
    let warning_count = parsed.diagnostics.len() - error_count;
    Ok(ConfigReport {
        config,
        exit_code,
        wall_ms: duration_ms(wall),
        emitted_file_count,
        determinism_passed,
        oxc_parse_passed,
        conformance_failure,
        error_count,
        warning_count,
        unparsed_lines: parsed.unparsed_lines,
        base_url_fallback_used: fallback_used,
        diagnostics: parsed.diagnostics,
        typecheck: typecheck_report,
    })
}

fn run_typecheck(
    workspace_root: &Path,
    workdir: &Path,
    config: ConfigKind,
) -> Result<TypecheckReport, Error> {
    let project_path = workdir.join("tsconfig.sweep.json");
    let project = format!("{{\n  \"include\": [\"{}\"]\n}}\n", config.output_glob());
    std::fs::write(&project_path, project)
        .map_err(|error| Error::new(format!("writing {}: {error}", project_path.display())))?;

    let mut command = ProcessCommand::new("pnpm");
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
        .arg("bundler")
        .arg("--project")
        .arg(&project_path)
        .current_dir(workspace_root);
    let outcome = timed_sample(command)
        .map_err(|error| Error::new(format!("spawning pnpm exec tsc: {error}")))?;
    let mut diagnostics = parse_typescript_output(&outcome.stdout, &outcome.stderr);
    for diagnostic in &mut diagnostics {
        if let Some(file) = &diagnostic.file {
            diagnostic.file = Some(normalize_typecheck_file(file, workspace_root, workdir));
        }
    }
    let failure = if outcome.exit_code == 0 || !diagnostics.is_empty() {
        None
    } else {
        let output = outcome
            .stderr
            .lines()
            .chain(outcome.stdout.lines())
            .filter(|line| !line.trim().is_empty())
            .take(3)
            .collect::<Vec<_>>()
            .join("\n");
        Some(if output.is_empty() {
            format!(
                "tsc exited with code {} without diagnostics",
                outcome.exit_code
            )
        } else {
            output
        })
    };
    Ok(TypecheckReport {
        exit_code: outcome.exit_code,
        diagnostics,
        failure,
    })
}

fn parse_typescript_output(stdout: &str, stderr: &str) -> Vec<TypeScriptDiagnostic> {
    let mut diagnostics = parse_typescript_stream(stderr);
    diagnostics.extend(parse_typescript_stream(stdout));
    diagnostics
}

fn parse_typescript_stream(output: &str) -> Vec<TypeScriptDiagnostic> {
    let mut diagnostics = Vec::new();
    let mut current = None;
    for line in output.lines() {
        if let Some(diagnostic) = parse_typescript_diagnostic(line) {
            diagnostics.push(diagnostic);
            current = Some(diagnostics.len() - 1);
        } else if let Some(index) = current
            && (line.starts_with(' ') || line.starts_with('\t'))
            && !line.trim().is_empty()
        {
            diagnostics[index].message.push('\n');
            diagnostics[index].message.push_str(line.trim());
        } else {
            current = None;
        }
    }
    diagnostics
}

fn parse_typescript_diagnostic(line: &str) -> Option<TypeScriptDiagnostic> {
    let (location, rest) = if let Some(rest) = line.strip_prefix("error TS") {
        (None, rest)
    } else {
        let (location, rest) = line.rsplit_once(": error TS")?;
        (Some(location), rest)
    };
    let (digits, message) = rest.split_once(": ")?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let (file, diagnostic_line, column) = match location {
        Some(location) => {
            let location = location.strip_suffix(')')?;
            let (file, position) = location.rsplit_once('(')?;
            let (line, column) = position.split_once(',')?;
            (
                Some(file.to_owned()),
                Some(line.parse().ok()?),
                Some(column.parse().ok()?),
            )
        }
        None => (None, None, None),
    };
    Some(TypeScriptDiagnostic {
        code: format!("TS{digits}"),
        file,
        line: diagnostic_line,
        column,
        message: message.to_owned(),
    })
}

fn normalize_typecheck_file(file: &str, workspace_root: &Path, workdir: &Path) -> String {
    let path = Path::new(file);
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace_root.join(path)
    };
    let normalized = std::fs::canonicalize(&candidate).unwrap_or(candidate);
    normalized
        .strip_prefix(workdir)
        .unwrap_or(&normalized)
        .to_string_lossy()
        .replace('\\', "/")
}

fn remove_output(workdir: &Path, name: &str) -> Result<(), Error> {
    let path = workdir.join(name);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(Error::new(format!("stat {}: {error}", path.display())));
        }
    };
    if metadata.is_dir() {
        std::fs::remove_dir_all(&path)
    } else {
        std::fs::remove_file(&path)
    }
    .map_err(|error| {
        Error::new(format!(
            "removing staged output {}: {error}",
            path.display()
        ))
    })
}

fn write_config(
    path: &Path,
    spec: &CorpusSpec,
    config: ConfigKind,
    literal_base_url: bool,
) -> Result<(), Error> {
    let input = yaml_quote(&format!("./{}", spec.file));
    let contents = match config {
        ConfigKind::Types => {
            format!("schemaVersion: 1\ninput:\n  path: {input}\noutput: ./generated\n")
        }
        ConfigKind::Full => {
            let base_url = if literal_base_url {
                "    source: literal\n    value: \"https://example.invalid\"\n"
            } else {
                "    source: server\n    index: 0\n"
            };
            format!(
                // zod rides the full config as a standalone artifact rather than as the bound
                // engine: the client binds one engine, and generating both here is what makes the
                // sweep report any construct one emitter rejects and the other accepts.
                "schemaVersion: 1\ninput:\n  path: {input}\noutput: ./generated-full\nartifacts:\n  types: true\n  client: true\n  validators: true\n  zod: true\nclient:\n  baseUrl:\n{base_url}validation:\n  engine: generated\n  request: true\n  response: true\n  unchecked: allow\n"
            )
        }
    };
    std::fs::write(path, contents)
        .map_err(|error| Error::new(format!("writing {}: {error}", path.display())))
}

fn generate_once(binary: &Path, config: &str, workdir: &Path) -> Result<SampleOutcome, Error> {
    let mut command = ProcessCommand::new(binary);
    command
        .arg("generate")
        .arg("--config")
        .arg(config)
        .current_dir(workdir);
    timed_sample(command).map_err(|error| Error::new(format!("spawning generate: {error}")))
}

fn should_retry_base_url(exit_code: i32, diagnostics: &[ParsedDiagnostic]) -> bool {
    exit_code == 1
        && diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == Severity::Error
                && diagnostic.code == "OASTS1420"
                && diagnostic
                    .message
                    .contains("no effective server at index 0")
        })
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CodeSample {
    spec: String,
    config: String,
    pointer: Option<String>,
    message: String,
}

#[derive(Debug, Eq, PartialEq)]
struct CodeReport {
    severity: String,
    spec_count: usize,
    occurrence_count: usize,
    samples: Vec<CodeSample>,
}

#[derive(Default)]
struct CodeAccumulator {
    errors: bool,
    warnings: bool,
    specs: BTreeSet<String>,
    occurrence_count: usize,
    samples: Vec<CodeSample>,
}

fn aggregate_codes(reports: &[SpecReport]) -> BTreeMap<String, CodeReport> {
    let mut accumulators: BTreeMap<String, CodeAccumulator> = BTreeMap::new();
    for spec in reports {
        for config in &spec.configs {
            for diagnostic in &config.diagnostics {
                let entry = accumulators.entry(diagnostic.code.clone()).or_default();
                match diagnostic.severity {
                    Severity::Error => entry.errors = true,
                    Severity::Warning => entry.warnings = true,
                }
                entry.specs.insert(spec.name.clone());
                entry.occurrence_count += 1;
                if entry.samples.len() < 3 {
                    entry.samples.push(CodeSample {
                        spec: spec.name.clone(),
                        config: config.config.name().to_owned(),
                        pointer: diagnostic.pointer.clone(),
                        message: diagnostic.message.clone(),
                    });
                }
            }
        }
    }
    accumulators
        .into_iter()
        .map(|(code, entry)| {
            let severity = match (entry.errors, entry.warnings) {
                (true, true) => "both",
                (true, false) => "error",
                (false, true) => "warning",
                (false, false) => unreachable!("an aggregate exists only after a diagnostic"),
            };
            (
                code,
                CodeReport {
                    severity: severity.to_owned(),
                    spec_count: entry.specs.len(),
                    occurrence_count: entry.occurrence_count,
                    samples: entry.samples,
                },
            )
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TypeScriptCodeSample {
    spec: String,
    config: String,
    file: Option<String>,
    line: Option<usize>,
    column: Option<usize>,
    message: String,
}

#[derive(Debug, Eq, PartialEq)]
struct TypeScriptCodeReport {
    spec_count: usize,
    occurrence_count: usize,
    samples: Vec<TypeScriptCodeSample>,
}

#[derive(Default)]
struct TypeScriptCodeAccumulator {
    specs: BTreeSet<String>,
    occurrence_count: usize,
    samples: Vec<TypeScriptCodeSample>,
}

fn aggregate_ts_codes(reports: &[SpecReport]) -> BTreeMap<String, TypeScriptCodeReport> {
    let mut accumulators: BTreeMap<String, TypeScriptCodeAccumulator> = BTreeMap::new();
    for spec in reports {
        for config in &spec.configs {
            let Some(typecheck) = &config.typecheck else {
                continue;
            };
            for diagnostic in &typecheck.diagnostics {
                let entry = accumulators.entry(diagnostic.code.clone()).or_default();
                entry.specs.insert(spec.name.clone());
                entry.occurrence_count += 1;
                if entry.samples.len() < 3 {
                    entry.samples.push(TypeScriptCodeSample {
                        spec: spec.name.clone(),
                        config: config.config.name().to_owned(),
                        file: diagnostic.file.clone(),
                        line: diagnostic.line,
                        column: diagnostic.column,
                        message: diagnostic.message.clone(),
                    });
                }
            }
        }
    }
    accumulators
        .into_iter()
        .map(|(code, entry)| {
            (
                code,
                TypeScriptCodeReport {
                    spec_count: entry.specs.len(),
                    occurrence_count: entry.occurrence_count,
                    samples: entry.samples,
                },
            )
        })
        .collect()
}

fn human_code_order(codes: &BTreeMap<String, CodeReport>) -> Vec<(&String, &CodeReport)> {
    let mut ordered: Vec<_> = codes.iter().collect();
    ordered.sort_by(|(left_code, left), (right_code, right)| {
        right
            .spec_count
            .cmp(&left.spec_count)
            .then_with(|| left_code.cmp(right_code))
    });
    ordered
}

fn human_ts_code_order(
    codes: &BTreeMap<String, TypeScriptCodeReport>,
) -> Vec<(&String, &TypeScriptCodeReport)> {
    let mut ordered: Vec<_> = codes.iter().collect();
    ordered.sort_by(|(left_code, left), (right_code, right)| {
        right
            .spec_count
            .cmp(&left.spec_count)
            .then_with(|| left_code.cmp(right_code))
    });
    ordered
}

fn report_yaml(
    reports: &[SpecReport],
    codes: &BTreeMap<String, CodeReport>,
    ts_codes: &BTreeMap<String, TypeScriptCodeReport>,
    typecheck_ran: bool,
) -> String {
    let mut out = String::from("schemaVersion: 1\n");
    let _ = writeln!(out, "typecheckRan: {typecheck_ran}");
    out.push_str("specs:\n");
    for spec in reports {
        let _ = writeln!(out, "  - name: {}", yaml_quote(&spec.name));
        let _ = writeln!(out, "    title: {}", yaml_quote(&spec.title));
        let _ = writeln!(out, "    client: {}", spec.client);
        match &spec.harness_error {
            Some(error) => {
                let _ = writeln!(out, "    harnessError: {}", yaml_quote(error));
            }
            None => out.push_str("    harnessError: null\n"),
        }
        if spec.configs.is_empty() {
            out.push_str("    configs: {}\n");
        } else {
            out.push_str("    configs:\n");
            for config in &spec.configs {
                let _ = writeln!(out, "      {}:", config.config.name());
                let _ = writeln!(out, "        exitCode: {}", config.exit_code);
                let _ = writeln!(out, "        wallMs: {}", config.wall_ms);
                let _ = writeln!(
                    out,
                    "        emittedFileCount: {}",
                    config.emitted_file_count
                );
                emit_optional_bool(
                    &mut out,
                    "        determinismPassed",
                    config.determinism_passed,
                );
                emit_optional_bool(&mut out, "        oxcParsePassed", config.oxc_parse_passed);
                match &config.conformance_failure {
                    Some(failure) => {
                        let _ =
                            writeln!(out, "        conformanceFailure: {}", yaml_quote(failure));
                    }
                    None => out.push_str("        conformanceFailure: null\n"),
                }
                let _ = writeln!(out, "        errorCount: {}", config.error_count);
                let _ = writeln!(out, "        warningCount: {}", config.warning_count);
                let _ = writeln!(out, "        unparsedLines: {}", config.unparsed_lines);
                let _ = writeln!(
                    out,
                    "        baseUrlFallbackUsed: {}",
                    config.base_url_fallback_used
                );
                emit_optional_bool(
                    &mut out,
                    "        typecheckPassed",
                    config.typecheck.as_ref().map(TypecheckReport::passed),
                );
                match &config.typecheck {
                    Some(typecheck) => {
                        let _ = writeln!(out, "        typecheckExitCode: {}", typecheck.exit_code);
                        let _ = writeln!(
                            out,
                            "        typecheckDiagnosticCount: {}",
                            typecheck.diagnostics.len()
                        );
                        match &typecheck.failure {
                            Some(failure) => {
                                let _ = writeln!(
                                    out,
                                    "        typecheckFailure: {}",
                                    yaml_quote(failure)
                                );
                            }
                            None => out.push_str("        typecheckFailure: null\n"),
                        }
                        if typecheck.diagnostics.is_empty() {
                            out.push_str("        typecheckDiagnostics: []\n");
                        } else {
                            out.push_str("        typecheckDiagnostics:\n");
                            for diagnostic in typecheck.diagnostics.iter().take(5) {
                                let _ = writeln!(
                                    out,
                                    "          - code: {}",
                                    yaml_quote(&diagnostic.code)
                                );
                                emit_optional_string(
                                    &mut out,
                                    "            file",
                                    diagnostic.file.as_deref(),
                                );
                                emit_optional_usize(&mut out, "            line", diagnostic.line);
                                emit_optional_usize(
                                    &mut out,
                                    "            column",
                                    diagnostic.column,
                                );
                                let _ = writeln!(
                                    out,
                                    "            message: {}",
                                    yaml_quote(&diagnostic.message)
                                );
                            }
                        }
                    }
                    None => {
                        out.push_str("        typecheckExitCode: null\n");
                        out.push_str("        typecheckDiagnosticCount: 0\n");
                        out.push_str("        typecheckFailure: null\n");
                        out.push_str("        typecheckDiagnostics: []\n");
                    }
                }
            }
        }
    }

    if codes.is_empty() {
        out.push_str("codes: {}\n");
    } else {
        out.push_str("codes:\n");
        for (code, report) in codes {
            let _ = writeln!(out, "  {}:", yaml_quote(code));
            let _ = writeln!(out, "    severity: {}", report.severity);
            let _ = writeln!(out, "    specCount: {}", report.spec_count);
            let _ = writeln!(out, "    occurrenceCount: {}", report.occurrence_count);
            out.push_str("    sample:\n");
            for sample in &report.samples {
                let _ = writeln!(out, "      - spec: {}", yaml_quote(&sample.spec));
                let _ = writeln!(out, "        config: {}", yaml_quote(&sample.config));
                match &sample.pointer {
                    Some(pointer) => {
                        let _ = writeln!(out, "        pointer: {}", yaml_quote(pointer));
                    }
                    None => out.push_str("        pointer: null\n"),
                }
                let _ = writeln!(out, "        message: {}", yaml_quote(&sample.message));
            }
        }
    }
    if ts_codes.is_empty() {
        out.push_str("tsCodes: {}\n");
    } else {
        out.push_str("tsCodes:\n");
        for (code, report) in ts_codes {
            let _ = writeln!(out, "  {}:", yaml_quote(code));
            out.push_str("    severity: error\n");
            let _ = writeln!(out, "    specCount: {}", report.spec_count);
            let _ = writeln!(out, "    occurrenceCount: {}", report.occurrence_count);
            out.push_str("    sample:\n");
            for sample in &report.samples {
                let _ = writeln!(out, "      - spec: {}", yaml_quote(&sample.spec));
                let _ = writeln!(out, "        config: {}", yaml_quote(&sample.config));
                emit_optional_string(&mut out, "        file", sample.file.as_deref());
                emit_optional_usize(&mut out, "        line", sample.line);
                emit_optional_usize(&mut out, "        column", sample.column);
                let _ = writeln!(out, "        message: {}", yaml_quote(&sample.message));
            }
        }
    }
    out
}

fn emit_optional_bool(out: &mut String, key: &str, value: Option<bool>) {
    match value {
        Some(value) => {
            let _ = writeln!(out, "{key}: {value}");
        }
        None => {
            let _ = writeln!(out, "{key}: null");
        }
    }
}

fn emit_optional_string(out: &mut String, key: &str, value: Option<&str>) {
    match value {
        Some(value) => {
            let _ = writeln!(out, "{key}: {}", yaml_quote(value));
        }
        None => {
            let _ = writeln!(out, "{key}: null");
        }
    }
}

fn emit_optional_usize(out: &mut String, key: &str, value: Option<usize>) {
    match value {
        Some(value) => {
            let _ = writeln!(out, "{key}: {value}");
        }
        None => {
            let _ = writeln!(out, "{key}: null");
        }
    }
}

fn yaml_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            character if character.is_control() => {
                let _ = write!(quoted, "\\u{:04x}", u32::from(character));
            }
            character => quoted.push(character),
        }
    }
    quoted.push('"');
    quoted
}

fn print_summary(
    reports: &[SpecReport],
    codes: &BTreeMap<String, CodeReport>,
    ts_codes: &BTreeMap<String, TypeScriptCodeReport>,
    out: &mut dyn io::Write,
) {
    for spec in reports {
        if let Some(error) = &spec.harness_error {
            let _ = writeln!(out, "{}  HARNESS ERROR: {error}", spec.name);
            continue;
        }
        let mut line = spec.name.clone();
        for config in &spec.configs {
            let _ = write!(
                line,
                "  {} exit={} files={} det/parse={}/{} tsc={} e/w={}/{}",
                config.config.name(),
                config.exit_code,
                config.emitted_file_count,
                verdict(config.determinism_passed),
                verdict(config.oxc_parse_passed),
                verdict(config.typecheck.as_ref().map(TypecheckReport::passed)),
                config.error_count,
                config.warning_count
            );
            if config.base_url_fallback_used {
                line.push_str(" fallback");
            }
        }
        if !spec.client {
            line.push_str("  full skipped");
        }
        let _ = writeln!(out, "{line}");
    }
    if codes.is_empty() {
        let _ = writeln!(out, "codes: none");
    } else {
        let _ = writeln!(out, "codes:");
        for (code, report) in human_code_order(codes) {
            let _ = writeln!(
                out,
                "  {code} {} specs={} occurrences={}",
                report.severity, report.spec_count, report.occurrence_count
            );
        }
    }
    if ts_codes.is_empty() {
        let _ = writeln!(out, "ts codes: none");
    } else {
        let _ = writeln!(out, "ts codes:");
        for (code, report) in human_ts_code_order(ts_codes) {
            let _ = writeln!(
                out,
                "  {code} error specs={} occurrences={}",
                report.spec_count, report.occurrence_count
            );
        }
    }
}

fn verdict(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "ok",
        Some(false) => "fail",
        None => "-",
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let root = workspace_root();
    let manifest_path = root.join("bench/corpus.yaml");
    let manifest = match CorpusManifest::load(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };

    let result = match cli.command {
        Command::Fetch { names } => {
            let mut stdout = io::stdout().lock();
            fetch_selected(&manifest, &root, &names, &CurlFetcher, &mut stdout)
        }
        Command::Run {
            names,
            jobs,
            report,
            keep_going,
            typecheck,
        } => {
            let mut stdout = io::stdout().lock();
            let options = RunOptions {
                jobs,
                report_path: &report,
                keep_going,
                typecheck,
            };
            run_sweep(&manifest, &root, &names, &options, &mut stdout)
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_yaml(extra_root: &str, extra_spec: &str) -> String {
        format!(
            "schemaVersion: 1\n{extra_root}specs:\n  - name: sample-api\n    title: Sample API\n    url: https://example.test/openapi.yaml\n    file: openapi.yaml\n{extra_spec}"
        )
    }

    fn config_report(config: ConfigKind, diagnostics: Vec<ParsedDiagnostic>) -> ConfigReport {
        let error_count = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Error)
            .count();
        let warning_count = diagnostics.len() - error_count;
        ConfigReport {
            config,
            exit_code: 1,
            wall_ms: 1,
            emitted_file_count: 0,
            determinism_passed: None,
            oxc_parse_passed: None,
            conformance_failure: None,
            error_count,
            warning_count,
            unparsed_lines: 0,
            base_url_fallback_used: false,
            diagnostics,
            typecheck: None,
        }
    }

    fn diagnostic(severity: Severity, code: &str, message: &str) -> ParsedDiagnostic {
        ParsedDiagnostic {
            severity,
            code: code.to_owned(),
            message: message.to_owned(),
            pointer: Some("/paths/~1pets/get".to_owned()),
        }
    }

    fn ts_diagnostic(code: &str, file: &str, message: &str) -> TypeScriptDiagnostic {
        TypeScriptDiagnostic {
            code: code.to_owned(),
            file: Some(file.to_owned()),
            line: Some(4),
            column: Some(2),
            message: message.to_owned(),
        }
    }

    #[test]
    fn corpus_deserialization_defaults_client_and_rejects_unknown_keys() {
        let manifest =
            CorpusManifest::from_str(&manifest_yaml("", "")).expect("valid corpus manifest");
        assert_eq!(manifest.specs.len(), 1);
        assert!(manifest.specs[0].client);

        let root_error = CorpusManifest::from_str(&manifest_yaml("unknown: true\n", ""))
            .expect_err("unknown root key rejected");
        assert!(
            root_error.to_string().contains("unknown key 'unknown'"),
            "{root_error}"
        );

        let spec_error = CorpusManifest::from_str(&manifest_yaml("", "    unknown: true\n"))
            .expect_err("unknown spec key rejected");
        assert!(
            spec_error.to_string().contains("unknown key 'unknown'"),
            "{spec_error}"
        );
    }

    #[test]
    fn corpus_deserialization_validates_names_files_digests_and_client_type() {
        let invalid_name = manifest_yaml("", "").replace("name: sample-api", "name: Sample_API");
        assert!(
            CorpusManifest::from_str(&invalid_name)
                .expect_err("invalid name")
                .to_string()
                .contains("kebab-case")
        );

        let invalid_file =
            manifest_yaml("", "").replace("file: openapi.yaml", "file: ../openapi.yaml");
        assert!(
            CorpusManifest::from_str(&invalid_file)
                .expect_err("invalid file")
                .to_string()
                .contains("basename")
        );

        let invalid_digest = format!("{}    sha256: abc\n", manifest_yaml("", ""));
        assert!(
            CorpusManifest::from_str(&invalid_digest)
                .expect_err("invalid digest")
                .to_string()
                .contains("64 hexadecimal")
        );

        let invalid_client = format!("{}    client: yes\n", manifest_yaml("", ""));
        assert!(
            CorpusManifest::from_str(&invalid_client)
                .expect_err("invalid client")
                .to_string()
                .contains("must be a boolean")
        );
    }

    #[test]
    fn missing_corpus_manifest_has_a_clear_error() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("missing.yaml");
        let error = CorpusManifest::load(&path).expect_err("missing manifest rejected");
        let message = error.to_string();
        assert!(message.contains("reading corpus manifest"), "{message}");
        assert!(message.contains("create bench/corpus.yaml"), "{message}");
    }

    #[test]
    fn diagnostic_parser_captures_locations_summary_and_unparsed_lines() {
        let stderr = concat!(
            "error[OASTS1202]: schema name collision\n",
            "  --> workspace/openapi.json:1:1 /components/schemas/Pet\n",
            "warning[OASTS1111]: required property is absent\n",
            "  --> workspace/openapi.json:4:2\n",
            "renderer note\n",
        );
        let stdout = "generated 7 files\nunexpected stdout\n";

        let parsed = parse_output(stdout, stderr);

        assert_eq!(parsed.emitted_files, Some(7));
        assert_eq!(parsed.unparsed_lines, 2);
        assert_eq!(parsed.diagnostics.len(), 2);
        assert_eq!(
            parsed.diagnostics[0].pointer.as_deref(),
            Some("/components/schemas/Pet")
        );
        assert_eq!(parsed.diagnostics[1].pointer, None);
    }

    #[test]
    fn diagnostic_parser_counts_malformed_headers_and_orphan_locations() {
        let parsed = parse_output(
            "generated many files\n",
            "error[OASTS12]: short code\n  --> workspace/openapi.json:1:1 /paths\n",
        );
        assert!(parsed.diagnostics.is_empty());
        assert_eq!(parsed.unparsed_lines, 3);
    }

    #[test]
    fn typescript_diagnostic_parser_captures_file_positions_and_global_errors() {
        let stdout = concat!(
            "generated/types/pet.ts(12,7): error TS2322: Type 'Pet' is not assignable.\n",
            "  Types of property 'id' are incompatible.\n",
            "error TS18046: 'value' is of type 'unknown'.\n",
            "generated/types/ignored.ts(1,1): warning TS9999: ignored\n",
        );
        let stderr = "pnpm preflight note\n";

        let diagnostics = parse_typescript_output(stdout, stderr);

        assert_eq!(
            diagnostics,
            vec![
                TypeScriptDiagnostic {
                    code: "TS2322".to_owned(),
                    file: Some("generated/types/pet.ts".to_owned()),
                    line: Some(12),
                    column: Some(7),
                    message: concat!(
                        "Type 'Pet' is not assignable.\n",
                        "Types of property 'id' are incompatible."
                    )
                    .to_owned(),
                },
                TypeScriptDiagnostic {
                    code: "TS18046".to_owned(),
                    file: None,
                    line: None,
                    column: None,
                    message: "'value' is of type 'unknown'.".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn base_url_retry_matches_the_live_oasts1420_contract() {
        let diagnostics = vec![diagnostic(
            Severity::Error,
            "OASTS1420",
            "operation has no effective server at index 0",
        )];
        assert!(should_retry_base_url(1, &diagnostics));
        assert!(!should_retry_base_url(2, &diagnostics));
        assert!(!should_retry_base_url(
            1,
            &[diagnostic(Severity::Error, "OASTS1403", "unsupported XML")]
        ));
    }

    #[test]
    fn aggregation_is_code_sorted_and_human_summary_is_spec_count_sorted() {
        let first = SpecReport {
            name: "alpha".to_owned(),
            title: "Alpha".to_owned(),
            client: true,
            configs: vec![config_report(
                ConfigKind::Types,
                vec![
                    diagnostic(Severity::Warning, "OASTS1300", "one"),
                    diagnostic(Severity::Error, "OASTS1200", "two"),
                    diagnostic(Severity::Warning, "OASTS1200", "three"),
                ],
            )],
            harness_error: None,
        };
        let second = SpecReport {
            name: "beta".to_owned(),
            title: "Beta".to_owned(),
            client: true,
            configs: vec![config_report(
                ConfigKind::Full,
                vec![
                    diagnostic(Severity::Warning, "OASTS1200", "four"),
                    diagnostic(Severity::Warning, "OASTS1200", "five"),
                ],
            )],
            harness_error: None,
        };

        let codes = aggregate_codes(&[first, second]);

        assert_eq!(
            codes.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["OASTS1200", "OASTS1300"]
        );
        let shared = codes.get("OASTS1200").expect("shared code");
        assert_eq!(shared.severity, "both");
        assert_eq!(shared.spec_count, 2);
        assert_eq!(shared.occurrence_count, 4);
        assert_eq!(shared.samples.len(), 3);
        assert_eq!(human_code_order(&codes)[0].0, "OASTS1200");
    }

    #[test]
    fn typescript_aggregation_counts_specs_occurrences_and_limits_samples() {
        let mut alpha_types = config_report(ConfigKind::Types, Vec::new());
        alpha_types.typecheck = Some(TypecheckReport {
            exit_code: 1,
            diagnostics: vec![
                ts_diagnostic("TS2304", "generated/a.ts", "one"),
                ts_diagnostic("TS2304", "generated/b.ts", "two"),
                ts_diagnostic("TS2315", "generated/c.ts", "three"),
            ],
            failure: None,
        });
        let mut beta_full = config_report(ConfigKind::Full, Vec::new());
        beta_full.typecheck = Some(TypecheckReport {
            exit_code: 1,
            diagnostics: vec![
                ts_diagnostic("TS2304", "generated-full/d.ts", "four"),
                ts_diagnostic("TS2304", "generated-full/e.ts", "five"),
            ],
            failure: None,
        });
        let reports = [
            SpecReport {
                name: "alpha".to_owned(),
                title: "Alpha".to_owned(),
                client: true,
                configs: vec![alpha_types],
                harness_error: None,
            },
            SpecReport {
                name: "beta".to_owned(),
                title: "Beta".to_owned(),
                client: true,
                configs: vec![beta_full],
                harness_error: None,
            },
        ];

        let codes = aggregate_ts_codes(&reports);

        assert_eq!(
            codes.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["TS2304", "TS2315"]
        );
        let shared = codes.get("TS2304").expect("shared code");
        assert_eq!(shared.spec_count, 2);
        assert_eq!(shared.occurrence_count, 4);
        assert_eq!(shared.samples.len(), 3);
        assert_eq!(human_ts_code_order(&codes)[0].0, "TS2304");
    }
}
