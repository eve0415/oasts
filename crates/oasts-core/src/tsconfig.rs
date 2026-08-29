//! Reading the consumer's `tsconfig.json`, for diagnostics only.
//!
//! Nothing here reaches emitted bytes. Every compiler flag the output is written against is
//! monotone — code that satisfies it also compiles with it off — so one canonical output serves
//! every consumer and generation stays a pure function of document, config and version. What
//! reading a tsconfig buys is saying *at generate time* that a project cannot compile what it just
//! asked for, instead of leaving the consumer to find out from their own `tsc`.
//!
//! TypeScript 7 ships no programmatic API (it arrives in 7.1), so resolution is reimplemented
//! rather than delegated. The algorithm follows `oxc-resolver`'s `src/tsconfig.rs`, which is itself
//! a port of `tsconfck`: JSONC stripped then parsed as JSON, `extends` as `string | string[]`
//! resolved relative to the file that declares it, `${configDir}` substituted, and `files` /
//! `include` / `exclude` from an inheriting file *replacing* the base's rather than merging.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

use crate::diag::Diagnostic;
use crate::inputs::InputRecorder;

/// How deep an `extends` chain may go before the reader gives up.
///
/// Invented, not derived: TypeScript imposes no limit, and a chain this long is a loop that cycle
/// detection somehow missed or a generated config nobody meant to write. Breaching it is an error
/// naming the file that broke it, never a silent truncation.
pub(crate) const MAX_EXTENDS_DEPTH: usize = 32;

/// How many ancestor directories discovery walks looking for a config that claims the output.
pub(crate) const MAX_ANCESTOR_WALK: usize = 64;

/// The largest tsconfig this reader will load. A config past this is not a config.
pub(crate) const MAX_TSCONFIG_BYTES: u64 = 4 * 1024 * 1024;

/// How many tsconfig files one run may read, across discovery and every `extends` chain.
pub(crate) const MAX_TSCONFIG_FILES: usize = 64;

/// The compiler options this reader understands.
///
/// Deliberately not the whole surface: an option earns a field here only when a diagnostic reads
/// it. Everything else is parsed and dropped, so an unknown option is never an error — a consumer's
/// tsconfig is theirs, and refusing to read it because it carries a key we do not model would make
/// this feature worse than not having it.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CompilerOptions {
    pub(crate) target: Option<String>,
    /// The only option in this struct that reaches emitted bytes: it decides whether the
    /// `esnext.temporal` reference directive is written. Everything else here is diagnostics-only.
    pub(crate) lib: Option<Vec<String>>,
    pub(crate) strict: Option<bool>,
    pub(crate) no_implicit_any: Option<bool>,
    pub(crate) strict_null_checks: Option<bool>,
    pub(crate) strict_function_types: Option<bool>,
    pub(crate) strict_bind_call_apply: Option<bool>,
    pub(crate) strict_property_initialization: Option<bool>,
    pub(crate) no_implicit_this: Option<bool>,
    pub(crate) use_unknown_in_catch_variables: Option<bool>,
    pub(crate) always_strict: Option<bool>,
    pub(crate) allow_js: Option<bool>,
    /// Relative to the directory of the file that declared it, per TypeScript.
    pub(crate) out_dir: Option<String>,
}

/// `extends` is one path or an ordered list of them; later entries win over earlier ones.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum ExtendsField {
    Single(String),
    Multiple(Vec<String>),
}

impl ExtendsField {
    fn targets(&self) -> Vec<String> {
        match self {
            Self::Single(one) => vec![one.clone()],
            Self::Multiple(many) => many.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawTsconfig {
    extends: Option<ExtendsField>,
    compiler_options: Option<CompilerOptions>,
    files: Option<Vec<String>>,
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    references: Option<Vec<Reference>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Reference {
    pub(crate) path: String,
}

/// One tsconfig with its `extends` chain already folded in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedTsconfig {
    /// The file this resolution started from — the one every diagnostic names.
    pub(crate) path: PathBuf,
    pub(crate) compiler_options: CompilerOptions,
    /// `files`/`include`/`exclude` are resolved against the directory of whichever file in the
    /// chain last declared them, which is not always `path`'s directory.
    pub(crate) files: Option<Vec<PathBuf>>,
    pub(crate) include: Option<Vec<PathBuf>>,
    pub(crate) exclude: Option<Vec<PathBuf>>,
    /// Never inherited: `references` is the one top-level key `extends` does not carry down.
    pub(crate) references: Vec<PathBuf>,
}

/// Anything that stops a tsconfig being read. Every variant names the file it happened in, because
/// a consumer with an `extends` chain has no other way to tell which link broke.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TsconfigError {
    Unreadable { path: PathBuf, reason: String },
    Malformed { path: PathBuf, reason: String },
    ExtendsCycle { path: PathBuf, target: PathBuf },
    ExtendsTooDeep { path: PathBuf },
    ExtendsUnresolved { path: PathBuf, target: String },
    TooManyFiles { path: PathBuf },
}

impl TsconfigError {
    pub(crate) fn into_diagnostic(self) -> Diagnostic {
        match self {
            Self::Unreadable { path, reason } => Diagnostic::config(
                "OASTS1002",
                format!("tsconfig '{}' could not be read: {reason}", path.display()),
            ),
            Self::Malformed { path, reason } => Diagnostic::config(
                "OASTS1002",
                format!(
                    "tsconfig '{}' is not valid JSON with comments: {reason}",
                    path.display()
                ),
            ),
            Self::ExtendsCycle { path, target } => Diagnostic::config(
                "OASTS0252",
                format!(
                    "tsconfig '{}' extends '{}', which is already in its own extends chain",
                    path.display(),
                    target.display()
                ),
            ),
            Self::ExtendsTooDeep { path } => Diagnostic::config(
                "OASTS0252",
                format!(
                    "tsconfig '{}' extends a chain deeper than {MAX_EXTENDS_DEPTH} files",
                    path.display()
                ),
            ),
            Self::ExtendsUnresolved { path, target } => Diagnostic::config(
                "OASTS0253",
                format!(
                    "tsconfig '{}' extends '{target}', which does not resolve to a readable file",
                    path.display()
                ),
            ),
            Self::TooManyFiles { path } => Diagnostic::config(
                "OASTS0252",
                format!(
                    "reading tsconfig '{}' would pass the {MAX_TSCONFIG_FILES}-file budget for one run",
                    path.display()
                ),
            ),
        }
    }
}

/// Counts files across one run so a fan-out of `extends` arrays cannot read the disk unbounded,
/// and reports every path the run touched to the watcher's recorder.
///
/// The two live together because they answer for the same events: a file that was read, and a
/// candidate that was probed and rejected. A watcher needs both — creating the `base.json` that an
/// `extends` looked for and did not find changes the next run's answer.
#[derive(Debug)]
pub(crate) struct ReadBudget<'a> {
    spent: usize,
    inputs: &'a mut InputRecorder,
}

impl<'a> ReadBudget<'a> {
    pub(crate) fn new(inputs: &'a mut InputRecorder) -> Self {
        Self { spent: 0, inputs }
    }

    /// Notes a path that was looked for, whether or not it was there.
    fn probe(&mut self, path: &Path) {
        self.inputs.record(path);
    }

    fn take(&mut self, path: &Path) -> Result<(), TsconfigError> {
        self.probe(path);
        if self.spent >= MAX_TSCONFIG_FILES {
            return Err(TsconfigError::TooManyFiles {
                path: path.to_path_buf(),
            });
        }
        self.spent += 1;
        Ok(())
    }
}

/// Normalizes `.` and `..` without touching the filesystem.
///
/// Lexical on purpose: the path may not exist yet — the output directory is written after this runs
/// — and a canonicalizing walk would both fail on it and follow symlinks the config never named.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                // Root cannot be climbed past: `/..` is `/`.
                Some(Component::RootDir | Component::Prefix(_)) => {}
                // Popping one `..` against another would cancel a climb that has not happened yet,
                // turning `../../x` into `x`. Nothing above is known, so the climb accumulates.
                Some(Component::ParentDir) | None => out.push(".."),
                _ => {
                    out.pop();
                }
            },
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Substitutes `${configDir}`, which TypeScript resolves to the directory of the file that *starts*
/// the chain rather than the one that wrote the token. Its whole point is letting a shared base
/// name paths in the inheriting project.
fn substitute_config_dir(value: &str, config_dir: &Path) -> String {
    if !value.contains("${configDir}") {
        return value.to_owned();
    }
    value.replace("${configDir}", &config_dir.to_string_lossy())
}

fn resolve_against(base_dir: &Path, value: &str, config_dir: &Path) -> PathBuf {
    let substituted = substitute_config_dir(value, config_dir);
    let candidate = Path::new(&substituted);
    if candidate.is_absolute() {
        normalize(candidate)
    } else {
        normalize(&base_dir.join(candidate))
    }
}

/// Resolves one `extends` target to a file path, Node-style.
///
/// A relative target names a file directly; TypeScript then tries the same path with `.json`, and
/// finally the path as a directory holding `tsconfig.json`. A bare specifier would be a package
/// lookup, which this reader does not do — it reports the target as unresolved rather than guessing
/// at a `node_modules` layout it cannot verify.
fn resolve_extends_target(
    base_dir: &Path,
    target: &str,
    config_dir: &Path,
    budget: &mut ReadBudget<'_>,
) -> Option<PathBuf> {
    let substituted = substitute_config_dir(target, config_dir);
    let looks_relative = substituted.starts_with('.')
        || substituted.starts_with('/')
        || Path::new(&substituted).is_absolute();
    if !looks_relative {
        return None;
    }
    let direct = resolve_against(base_dir, &substituted, config_dir);
    [
        direct.clone(),
        direct.with_extension("json"),
        direct.join("tsconfig.json"),
    ]
    .into_iter()
    .find(|candidate| {
        budget.probe(candidate);
        candidate.is_file()
    })
}

/// Later options win. Only fields the caller left unset are taken from the base, which is what
/// makes an inheriting file's explicit `false` survive a base that said `true`.
fn merge_options(base: CompilerOptions, over: CompilerOptions) -> CompilerOptions {
    CompilerOptions {
        target: over.target.or(base.target),
        lib: over.lib.or(base.lib),
        strict: over.strict.or(base.strict),
        no_implicit_any: over.no_implicit_any.or(base.no_implicit_any),
        strict_null_checks: over.strict_null_checks.or(base.strict_null_checks),
        strict_function_types: over.strict_function_types.or(base.strict_function_types),
        strict_bind_call_apply: over.strict_bind_call_apply.or(base.strict_bind_call_apply),
        strict_property_initialization: over
            .strict_property_initialization
            .or(base.strict_property_initialization),
        no_implicit_this: over.no_implicit_this.or(base.no_implicit_this),
        use_unknown_in_catch_variables: over
            .use_unknown_in_catch_variables
            .or(base.use_unknown_in_catch_variables),
        always_strict: over.always_strict.or(base.always_strict),
        allow_js: over.allow_js.or(base.allow_js),
        out_dir: over.out_dir.or(base.out_dir),
    }
}

fn read_raw(path: &Path, budget: &mut ReadBudget<'_>) -> Result<RawTsconfig, TsconfigError> {
    budget.take(path)?;
    let metadata = std::fs::metadata(path).map_err(|error| TsconfigError::Unreadable {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })?;
    if metadata.len() > MAX_TSCONFIG_BYTES {
        return Err(TsconfigError::Unreadable {
            path: path.to_path_buf(),
            reason: format!("file is larger than the {MAX_TSCONFIG_BYTES}-byte limit"),
        });
    }
    let mut text = std::fs::read_to_string(path).map_err(|error| TsconfigError::Unreadable {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })?;
    // `strip` returns io::Result only because it shares a writer-based implementation; over a
    // String sink it cannot fail, which `jsonc_stripping_over_a_string_cannot_fail` pins. An
    // unterminated comment or string survives stripping and is reported by the parse below, so
    // there is no second failure mode to model here.
    json_strip_comments::strip(&mut text).unwrap_or_default();
    serde_json::from_str(&text).map_err(|error| TsconfigError::Malformed {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })
}

/// Reads one tsconfig with its whole `extends` chain folded in.
pub(crate) fn read(
    path: &Path,
    budget: &mut ReadBudget<'_>,
) -> Result<ResolvedTsconfig, TsconfigError> {
    let start = normalize(path);
    // `unwrap_or` over `map_or_else`: the fallback arm is a closure llvm-cov instantiates and no
    // real config path reaches, so it scores as an uncovered function under the 100% gate.
    let config_dir = start.parent().unwrap_or(Path::new(".")).to_path_buf();
    let mut seen = BTreeSet::new();
    seen.insert(start.clone());
    let resolved = fold(&start, &config_dir, &mut seen, 0, budget)?;
    Ok(ResolvedTsconfig {
        path: start,
        ..resolved
    })
}

fn fold(
    path: &Path,
    config_dir: &Path,
    seen: &mut BTreeSet<PathBuf>,
    depth: usize,
    budget: &mut ReadBudget<'_>,
) -> Result<ResolvedTsconfig, TsconfigError> {
    if depth > MAX_EXTENDS_DEPTH {
        return Err(TsconfigError::ExtendsTooDeep {
            path: path.to_path_buf(),
        });
    }
    let raw = read_raw(path, budget)?;
    let base_dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();

    // Bases first, in declaration order, so a later entry overrides an earlier one and the file
    // that declared `extends` overrides them all.
    let mut inherited = ResolvedTsconfig {
        path: path.to_path_buf(),
        compiler_options: CompilerOptions::default(),
        files: None,
        include: None,
        exclude: None,
        references: Vec::new(),
    };
    for target in raw.extends.iter().flat_map(ExtendsField::targets) {
        let Some(resolved_target) = resolve_extends_target(&base_dir, &target, config_dir, budget)
        else {
            return Err(TsconfigError::ExtendsUnresolved {
                path: path.to_path_buf(),
                target,
            });
        };
        if !seen.insert(resolved_target.clone()) {
            return Err(TsconfigError::ExtendsCycle {
                path: path.to_path_buf(),
                target: resolved_target,
            });
        }
        let base = fold(&resolved_target, config_dir, seen, depth + 1, budget)?;
        inherited = ResolvedTsconfig {
            path: inherited.path,
            compiler_options: merge_options(inherited.compiler_options, base.compiler_options),
            files: base.files.or(inherited.files),
            include: base.include.or(inherited.include),
            exclude: base.exclude.or(inherited.exclude),
            // `references` never inherits, so a base's are dropped here on purpose.
            references: Vec::new(),
        };
    }

    let own = |values: Option<Vec<String>>| -> Option<Vec<PathBuf>> {
        values.map(|entries| {
            entries
                .iter()
                .map(|entry| resolve_against(&base_dir, entry, config_dir))
                .collect()
        })
    };
    Ok(ResolvedTsconfig {
        path: path.to_path_buf(),
        compiler_options: merge_options(
            inherited.compiler_options,
            raw.compiler_options.unwrap_or_default(),
        ),
        files: own(raw.files).or(inherited.files),
        include: own(raw.include).or(inherited.include),
        exclude: own(raw.exclude).or(inherited.exclude),
        references: raw
            .references
            .unwrap_or_default()
            .iter()
            .map(|reference| resolve_against(&base_dir, &reference.path, config_dir))
            .collect(),
    })
}

/// Whether a consumer compiling with these options already has `Temporal` in scope.
///
/// Measured against the pinned `typescript@7.0.2`, not assumed:
///   - `lib` present  → provided iff some entry is `esnext` or `esnext.temporal`.
///   - `lib` absent   → the default set comes from `target`, and only `esnext` carries Temporal.
///
/// `esnext.temporal` on its own is deliberately treated as providing it even though such a project
/// does not compile: `lib` replaces the default set outright, so a lone entry leaves the base ES
/// declarations missing and the file fails with `TS2318: Cannot find global type 'Boolean'` — with
/// or without our directive, byte for byte. Our choice is a no-op there, so the simple rule stands.
pub(crate) fn provides_temporal(options: &CompilerOptions) -> bool {
    let names = |value: &str| {
        value.eq_ignore_ascii_case("esnext") || value.eq_ignore_ascii_case("esnext.temporal")
    };
    options.lib.as_ref().map_or_else(
        || {
            options
                .target
                .as_deref()
                .is_some_and(|target| target.eq_ignore_ascii_case("esnext"))
        },
        |lib| lib.iter().any(|entry| names(entry)),
    )
}

/// The nearest `tsconfig.json` at or above `from`, or `None` within the ancestor bound.
///
/// Nearest-wins rather than claim-checked: the directive decision only needs the compiler options
/// the output will actually be built under, and the nearest config is the one whose `compilerOptions`
/// a consumer would expect to govern that directory. Ownership (`files`/`include`/`references`)
/// decides which *program* a file belongs to, which is a different question and a diagnostics-only
/// one — it never changes what is emitted.
pub(crate) fn discover(from: &Path, inputs: &mut InputRecorder) -> Option<PathBuf> {
    let mut current = Some(normalize(from));
    for _ in 0..MAX_ANCESTOR_WALK {
        let directory = current?;
        let candidate = directory.join("tsconfig.json");
        // Recorded before the test, not after: a nearer `tsconfig.json` appearing above the output
        // directory changes which config governs the run, so the ancestors that had none are as
        // much an input as the one that answered.
        inputs.record(&candidate);
        if candidate.is_file() {
            return Some(candidate);
        }
        current = directory.parent().map(Path::to_path_buf);
    }
    None
}

/// Whether emitted code may omit the `esnext.temporal` reference directive, plus anything that went
/// wrong finding out.
///
/// This is the one place a consumer's tsconfig reaches emitted bytes, so it fails **safe**: no
/// config found, unreadable, or reading disabled all answer "the consumer does not provide
/// Temporal", which emits the directive. Being wrong that way costs a redundant comment; being
/// wrong the other way costs the consumer `TS2503: Cannot find namespace 'Temporal'`.
pub(crate) fn consumer_provides_temporal(
    output_directory: &Path,
    setting: &crate::config::TsconfigSource,
    inputs: &mut InputRecorder,
) -> (bool, Vec<Diagnostic>) {
    let path = match setting {
        crate::config::TsconfigSource::Off => return (false, Vec::new()),
        crate::config::TsconfigSource::Path(path) => path.clone(),
        crate::config::TsconfigSource::Auto => match discover(output_directory, inputs) {
            Some(found) => found,
            None => return (false, Vec::new()),
        },
    };
    match read(&path, &mut ReadBudget::new(inputs)) {
        Ok(resolved) => (provides_temporal(&resolved.compiler_options), Vec::new()),
        Err(error) => (false, vec![error.into_diagnostic()]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent directory");
        }
        fs::write(&path, body).expect("write tsconfig");
        path
    }

    fn read_ok(path: &Path) -> ResolvedTsconfig {
        read(path, &mut ReadBudget::new(&mut InputRecorder::off())).expect("tsconfig resolves")
    }

    fn read_err(path: &Path) -> TsconfigError {
        read(path, &mut ReadBudget::new(&mut InputRecorder::off()))
            .expect_err("tsconfig is rejected")
    }

    #[test]
    fn comments_and_trailing_commas_parse() {
        let temp = TempDir::new().expect("temp");
        let path = write(
            temp.path(),
            "tsconfig.json",
            r#"{
              // a line comment
              /* and a block one */
              "compilerOptions": { "strict": true, "target": "ES2022", },
              "include": ["src"],
            }"#,
        );
        let resolved = read_ok(&path);
        assert_eq!(resolved.compiler_options.strict, Some(true));
        assert_eq!(resolved.compiler_options.target.as_deref(), Some("ES2022"));
        assert_eq!(resolved.include, Some(vec![temp.path().join("src")]));
    }

    #[test]
    fn an_unmodelled_option_is_kept_rather_than_rejected() {
        let temp = TempDir::new().expect("temp");
        let path = write(
            temp.path(),
            "tsconfig.json",
            r#"{ "compilerOptions": { "strict": true, "someFutureFlag": 3 }, "vendorKey": [] }"#,
        );
        assert_eq!(read_ok(&path).compiler_options.strict, Some(true));
    }

    #[test]
    fn a_two_level_extends_chain_folds_base_first() {
        let temp = TempDir::new().expect("temp");
        write(
            temp.path(),
            "base.json",
            r#"{ "compilerOptions": { "strict": true, "target": "ES2019" } }"#,
        );
        write(
            temp.path(),
            "middle.json",
            r#"{ "extends": "./base.json", "compilerOptions": { "target": "ES2022" } }"#,
        );
        let path = write(
            temp.path(),
            "tsconfig.json",
            r#"{ "extends": "./middle.json", "compilerOptions": { "strict": false } }"#,
        );
        let resolved = read_ok(&path);
        // The nearest file wins on `strict`, the middle one on `target`, and the base supplies
        // neither because both were overridden.
        assert_eq!(resolved.compiler_options.strict, Some(false));
        assert_eq!(resolved.compiler_options.target.as_deref(), Some("ES2022"));
        assert_eq!(resolved.path, path);
    }

    #[test]
    fn an_extends_array_lets_the_last_entry_win() {
        let temp = TempDir::new().expect("temp");
        write(
            temp.path(),
            "a.json",
            r#"{ "compilerOptions": { "target": "ES2019" } }"#,
        );
        write(
            temp.path(),
            "b.json",
            r#"{ "compilerOptions": { "target": "ES2022" } }"#,
        );
        let path = write(
            temp.path(),
            "tsconfig.json",
            r#"{ "extends": ["./a.json", "./b.json"] }"#,
        );
        assert_eq!(
            read_ok(&path).compiler_options.target.as_deref(),
            Some("ES2022")
        );
    }

    #[test]
    fn config_dir_resolves_to_the_directory_of_the_file_that_starts_the_chain() {
        let temp = TempDir::new().expect("temp");
        write(
            temp.path(),
            "packages/base.json",
            r#"{ "include": ["${configDir}/src"], "exclude": ["${configDir}/dist"] }"#,
        );
        let path = write(
            temp.path(),
            "tsconfig.json",
            r#"{ "extends": "./packages/base.json" }"#,
        );
        let resolved = read_ok(&path);
        // Not `packages/src`: the token names the inheriting project, which is the whole reason a
        // shared base is allowed to write it.
        assert_eq!(resolved.include, Some(vec![temp.path().join("src")]));
        assert_eq!(resolved.exclude, Some(vec![temp.path().join("dist")]));
    }

    #[test]
    fn files_include_and_exclude_replace_rather_than_merge() {
        let temp = TempDir::new().expect("temp");
        write(
            temp.path(),
            "base.json",
            r#"{ "files": ["base.ts"], "include": ["base"], "exclude": ["node_modules"] }"#,
        );
        let path = write(
            temp.path(),
            "tsconfig.json",
            r#"{ "extends": "./base.json", "include": ["own"] }"#,
        );
        let resolved = read_ok(&path);
        assert_eq!(resolved.include, Some(vec![temp.path().join("own")]));
        // The two the inheriting file said nothing about still come from the base.
        assert_eq!(resolved.files, Some(vec![temp.path().join("base.ts")]));
        assert_eq!(
            resolved.exclude,
            Some(vec![temp.path().join("node_modules")])
        );
    }

    #[test]
    fn references_do_not_inherit() {
        let temp = TempDir::new().expect("temp");
        write(
            temp.path(),
            "base.json",
            r#"{ "references": [{ "path": "./base-ref" }] }"#,
        );
        let inheriting = write(
            temp.path(),
            "tsconfig.json",
            r#"{ "extends": "./base.json" }"#,
        );
        assert!(read_ok(&inheriting).references.is_empty());

        let own = write(
            temp.path(),
            "own.json",
            r#"{ "references": [{ "path": "./app" }, { "path": "./lib" }] }"#,
        );
        assert_eq!(
            read_ok(&own).references,
            vec![temp.path().join("app"), temp.path().join("lib")]
        );
    }

    #[test]
    fn an_extends_target_resolves_by_suffix_or_directory() {
        let temp = TempDir::new().expect("temp");
        write(
            temp.path(),
            "suffixed.json",
            r#"{ "compilerOptions": { "strict": true } }"#,
        );
        let by_suffix = write(temp.path(), "a.json", r#"{ "extends": "./suffixed" }"#);
        assert_eq!(read_ok(&by_suffix).compiler_options.strict, Some(true));

        write(
            temp.path(),
            "pkg/tsconfig.json",
            r#"{ "compilerOptions": { "allowJs": true } }"#,
        );
        let by_directory = write(temp.path(), "b.json", r#"{ "extends": "./pkg" }"#);
        assert_eq!(read_ok(&by_directory).compiler_options.allow_js, Some(true));
    }

    #[test]
    fn a_cycle_names_the_file_that_closed_it() {
        let temp = TempDir::new().expect("temp");
        write(temp.path(), "a.json", r#"{ "extends": "./b.json" }"#);
        write(temp.path(), "b.json", r#"{ "extends": "./a.json" }"#);
        let path = write(temp.path(), "tsconfig.json", r#"{ "extends": "./a.json" }"#);
        let error = read_err(&path);
        assert!(
            matches!(&error, TsconfigError::ExtendsCycle { target, .. } if target == &temp.path().join("a.json")),
            "{error:?}"
        );
        assert_eq!(error.into_diagnostic().code, "OASTS0252");
    }

    #[test]
    fn a_chain_past_the_depth_bound_is_refused() {
        let temp = TempDir::new().expect("temp");
        // Each link extends the next, so the chain is longer than the bound without ever repeating
        // a file — which is what makes this a depth check rather than a cycle check.
        let links = MAX_EXTENDS_DEPTH + 2;
        for index in 0..links {
            write(
                temp.path(),
                &format!("link{index}.json"),
                &format!(r#"{{ "extends": "./link{}.json" }}"#, index + 1),
            );
        }
        write(temp.path(), &format!("link{links}.json"), "{}");
        let error = read_err(&temp.path().join("link0.json"));
        assert!(
            matches!(error, TsconfigError::ExtendsTooDeep { .. }),
            "{error:?}"
        );
        assert_eq!(error.into_diagnostic().code, "OASTS0252");
    }

    #[test]
    fn an_unresolvable_extends_target_names_what_it_looked_for() {
        let temp = TempDir::new().expect("temp");
        let missing = write(
            temp.path(),
            "tsconfig.json",
            r#"{ "extends": "./absent.json" }"#,
        );
        let error = read_err(&missing);
        assert!(
            matches!(&error, TsconfigError::ExtendsUnresolved { target, .. } if target == "./absent.json"),
            "{error:?}"
        );
        assert_eq!(error.clone().into_diagnostic().code, "OASTS0253");
        assert!(error.into_diagnostic().message.contains("./absent.json"));

        // A bare specifier is a package lookup this reader deliberately does not perform.
        let bare = write(
            temp.path(),
            "bare.json",
            r#"{ "extends": "@tsconfig/node20/tsconfig.json" }"#,
        );
        assert!(matches!(
            read_err(&bare),
            TsconfigError::ExtendsUnresolved { .. }
        ));
    }

    #[test]
    fn an_absent_malformed_or_oversized_file_is_reported_against_its_path() {
        let temp = TempDir::new().expect("temp");
        let absent = temp.path().join("nothing.json");
        let error = read_err(&absent);
        assert!(
            matches!(error, TsconfigError::Unreadable { .. }),
            "{error:?}"
        );
        assert_eq!(error.into_diagnostic().code, "OASTS1002");

        let malformed = write(temp.path(), "bad.json", r#"{ "compilerOptions": }"#);
        let error = read_err(&malformed);
        assert!(
            matches!(error, TsconfigError::Malformed { .. }),
            "{error:?}"
        );
        assert_eq!(error.into_diagnostic().code, "OASTS1002");

        let oversized = write(
            temp.path(),
            "big.json",
            &format!(
                r#"{{ "_pad": "{}" }}"#,
                "p".repeat(MAX_TSCONFIG_BYTES as usize + 1)
            ),
        );
        let error = read_err(&oversized);
        assert!(
            matches!(&error, TsconfigError::Unreadable { reason, .. } if reason.contains("larger than")),
            "{error:?}"
        );
    }

    #[test]
    fn the_per_run_file_budget_is_enforced_across_one_chain() {
        let temp = TempDir::new().expect("temp");
        let path = write(temp.path(), "tsconfig.json", "{}");
        let mut recorder = InputRecorder::off();
        let mut budget = ReadBudget {
            spent: MAX_TSCONFIG_FILES,
            inputs: &mut recorder,
        };
        let error = read(&path, &mut budget).expect_err("budget is spent");
        assert!(
            matches!(error, TsconfigError::TooManyFiles { .. }),
            "{error:?}"
        );
        assert_eq!(error.into_diagnostic().code, "OASTS0252");
    }

    #[test]
    fn paths_normalize_lexically_without_touching_the_filesystem() {
        let temp = TempDir::new().expect("temp");
        // `../` in an include has to resolve even though nothing on disk answers to it, because the
        // output directory does not exist until after generation writes it.
        let path = write(
            temp.path(),
            "nested/tsconfig.json",
            r#"{ "include": ["../generated", "./a/./b", "../../escaped"] }"#,
        );
        let include = read_ok(&path).include.expect("include");
        assert_eq!(include[0], temp.path().join("generated"));
        assert_eq!(include[1], temp.path().join("nested/a/b"));
        assert_eq!(
            include[2],
            temp.path()
                .parent()
                .expect("parent")
                .to_path_buf()
                .join("escaped")
        );
    }

    #[test]
    fn a_relative_start_path_and_a_root_level_file_both_resolve() {
        let temp = TempDir::new().expect("temp");
        write(temp.path(), "tsconfig.json", r#"{ "include": ["src"] }"#);
        // A path with no parent component exercises the "." fallback on both sides.
        let resolved = read_ok(&temp.path().join("./tsconfig.json"));
        assert_eq!(resolved.include, Some(vec![temp.path().join("src")]));
    }

    /// Pins why `read_raw` does not model a stripping failure: over a String sink there is none.
    /// An unterminated construct is left for the JSON parse to report, which names the file.
    #[test]
    fn jsonc_stripping_over_a_string_cannot_fail() {
        for case in ["{ \"a\": 1 } /* unterminated", "{ \"a\": \"unterminated"] {
            let mut text = case.to_owned();
            assert!(json_strip_comments::strip(&mut text).is_ok());
        }
        // And the parse is what turns them into a named diagnostic.
        let temp = TempDir::new().expect("temp");
        let path = write(temp.path(), "tsconfig.json", "{ \"a\": \"unterminated");
        assert!(matches!(read_err(&path), TsconfigError::Malformed { .. }));
    }

    #[test]
    fn a_leading_parent_component_survives_normalization() {
        // A relative path that climbs past its own root keeps the `..`, because there is nothing
        // to pop it against — the emitted output directory may sit anywhere relative to the config.
        let temp = TempDir::new().expect("temp");
        let path = write(
            temp.path(),
            "tsconfig.json",
            r#"{ "include": ["../../up/and/out"] }"#,
        );
        let include = read_ok(&path).include.expect("include");
        assert!(include[0].ends_with("up/and/out"), "{include:?}");
        // A leading `./` is the only place Rust's own `components()` keeps a CurDir, so it is the
        // only way to reach that arm — an interior `./` is already normalized away before we see it.
        assert_eq!(normalize(Path::new("./a/b")), PathBuf::from("a/b"));
        assert_eq!(normalize(Path::new("../a/../b")), PathBuf::from("../b"));
        assert_eq!(normalize(Path::new("../../x")), PathBuf::from("../../x"));
        assert_eq!(normalize(Path::new("a/../../x")), PathBuf::from("../x"));
        // Absolute paths stop at the root rather than growing a `..` above it.
        assert_eq!(normalize(Path::new("/a/../../x")), PathBuf::from("/x"));
    }

    #[test]
    fn a_path_that_stats_but_cannot_be_read_is_unreadable_not_malformed() {
        let temp = TempDir::new().expect("temp");
        // A directory answers `metadata` and refuses `read_to_string`.
        let directory = temp.path().join("tsconfig.json");
        fs::create_dir_all(&directory).expect("directory");
        assert!(matches!(
            read_err(&directory),
            TsconfigError::Unreadable { .. }
        ));
    }

    #[test]
    fn discovery_gives_up_at_the_ancestor_bound() {
        let temp = TempDir::new().expect("temp");
        // Deeper than the bound, with no config anywhere on the way up inside it.
        let mut deep = temp.path().to_path_buf();
        for index in 0..=MAX_ANCESTOR_WALK {
            deep = deep.join(format!("d{index}"));
        }
        fs::create_dir_all(&deep).expect("deep directories");
        write(temp.path(), "tsconfig.json", "{}");
        assert_eq!(discover(&deep, &mut InputRecorder::off()), None);
    }

    #[test]
    fn temporal_coverage_follows_lib_then_target() {
        let options = |lib: Option<&[&str]>, target: Option<&str>| CompilerOptions {
            lib: lib.map(|entries| entries.iter().map(|entry| (*entry).to_owned()).collect()),
            target: target.map(str::to_owned),
            ..CompilerOptions::default()
        };
        // `lib` present: only an entry that names the Temporal declarations counts, case-insensitively.
        assert!(provides_temporal(&options(
            Some(&["ES2023", "ESNext.Temporal"]),
            None
        )));
        assert!(provides_temporal(&options(Some(&["esnext"]), None)));
        assert!(provides_temporal(&options(Some(&["ESNEXT"]), None)));
        assert!(!provides_temporal(&options(Some(&["ES2023", "DOM"]), None)));
        assert!(!provides_temporal(&options(Some(&[]), None)));
        // A present `lib` wins outright, even over a target that would have supplied Temporal.
        assert!(!provides_temporal(&options(
            Some(&["ES2023"]),
            Some("ESNext")
        )));
        // `lib` absent: the default set comes from `target`, and only esnext carries Temporal.
        assert!(provides_temporal(&options(None, Some("ESNext"))));
        assert!(!provides_temporal(&options(None, Some("ES2022"))));
        assert!(!provides_temporal(&options(None, None)));
    }

    #[test]
    fn discovery_takes_the_nearest_config_above_the_output_directory() {
        let temp = TempDir::new().expect("temp");
        write(
            temp.path(),
            "tsconfig.json",
            r#"{ "compilerOptions": { "lib": ["ES2023"] } }"#,
        );
        let nested = write(
            temp.path(),
            "packages/app/tsconfig.json",
            r#"{ "compilerOptions": { "lib": ["ESNext"] } }"#,
        );
        let output = temp.path().join("packages/app/src/generated");
        fs::create_dir_all(&output).expect("output directory");
        assert_eq!(
            discover(&output, &mut InputRecorder::off()).as_deref(),
            Some(nested.as_path())
        );

        // A directory under the root but outside the nested package falls through to the root.
        let other = temp.path().join("elsewhere");
        fs::create_dir_all(&other).expect("other directory");
        assert_eq!(
            discover(&other, &mut InputRecorder::off()).as_deref(),
            Some(temp.path().join("tsconfig.json").as_path())
        );
    }

    #[test]
    fn the_temporal_answer_fails_safe_and_honours_the_off_switch() {
        use crate::config::TsconfigSource;
        let temp = TempDir::new().expect("temp");
        let output = temp.path().join("generated");
        fs::create_dir_all(&output).expect("output directory");

        // Nothing to read: the directive stays, and that is not a diagnostic.
        let (provides, diagnostics) =
            consumer_provides_temporal(&output, &TsconfigSource::Auto, &mut InputRecorder::off());
        assert!(!provides);
        assert!(diagnostics.is_empty());

        write(
            temp.path(),
            "tsconfig.json",
            r#"{ "compilerOptions": { "lib": ["ESNext"] } }"#,
        );
        let (provides, diagnostics) =
            consumer_provides_temporal(&output, &TsconfigSource::Auto, &mut InputRecorder::off());
        assert!(provides);
        assert!(diagnostics.is_empty());

        // `off` reads nothing, so output stops depending on anything outside version/config/input.
        let (provides, diagnostics) =
            consumer_provides_temporal(&output, &TsconfigSource::Off, &mut InputRecorder::off());
        assert!(!provides);
        assert!(diagnostics.is_empty());

        // An explicit path is read directly, discovery skipped.
        let explicit = write(
            temp.path(),
            "tsconfig.build.json",
            r#"{ "compilerOptions": {} }"#,
        );
        let (provides, diagnostics) = consumer_provides_temporal(
            &output,
            &TsconfigSource::Path(explicit),
            &mut InputRecorder::off(),
        );
        assert!(!provides);
        assert!(diagnostics.is_empty());

        // A malformed config answers "not provided" and says why, rather than guessing.
        let broken = write(temp.path(), "broken.json", "{ nope");
        let (provides, diagnostics) = consumer_provides_temporal(
            &output,
            &TsconfigSource::Path(broken),
            &mut InputRecorder::off(),
        );
        assert!(!provides);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "OASTS1002");
    }

    #[test]
    fn an_absolute_include_is_taken_as_written() {
        let temp = TempDir::new().expect("temp");
        let absolute = temp.path().join("elsewhere");
        let path = write(
            temp.path(),
            "tsconfig.json",
            &format!(
                r#"{{ "include": [{}] }}"#,
                serde_json::to_string(&absolute.to_string_lossy()).expect("json")
            ),
        );
        assert_eq!(read_ok(&path).include, Some(vec![absolute]));
    }
}
