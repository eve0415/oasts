use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use oasts_core::diag::Category;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Block, Expr, ExprAssign, ExprCall, ExprLit, ExprMethodCall, ExprStruct, FnArg,
    ImplItemFn, ItemConst, ItemFn, Macro, Member, Pat, Signature, Token,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FactoryRule {
    code_argument: usize,
    category: Category,
}

#[derive(Clone, Debug, Default)]
struct CodeReferences {
    constants: BTreeSet<String>,
    literals: BTreeSet<String>,
    has_code_parameter: bool,
}

#[derive(Clone, Debug)]
struct Call {
    name: String,
    arguments: Vec<CodeReferences>,
}

#[derive(Clone, Debug)]
struct Function {
    name: String,
    code_parameter: Option<usize>,
    codes: CodeReferences,
    calls: Vec<Call>,
}

#[derive(Debug)]
struct RustSource {
    path: PathBuf,
    constants: BTreeMap<String, String>,
    codes: BTreeSet<String>,
    functions: Vec<Function>,
    config_writes: usize,
    input_writes: usize,
    category_mutations: usize,
}

#[derive(Debug)]
struct NodeSource {
    path: PathBuf,
    text: String,
    constants: BTreeMap<String, String>,
    codes: BTreeSet<String>,
}

#[test]
fn every_production_diagnostic_matches_its_stage_category() {
    let rust = rust_sources();
    let node = node_sources();
    let mut observed = observed_rust_categories(&rust);
    observe_node_categories(&node, &mut observed);

    let source_codes = rust
        .iter()
        .flat_map(|source| source.codes.iter().cloned())
        .chain(node.iter().flat_map(|source| source.codes.iter().cloned()))
        .collect::<BTreeSet<_>>();
    for code in &source_codes {
        category_for_band(code);
    }

    let observed_codes = observed.keys().cloned().collect::<BTreeSet<_>>();
    let unobserved = source_codes.difference(&observed_codes).collect::<Vec<_>>();
    let absent = observed_codes.difference(&source_codes).collect::<Vec<_>>();
    assert!(
        unobserved.is_empty() && absent.is_empty(),
        "production codes without an observed diagnostic category: {unobserved:?}; observed codes absent from production source: {absent:?}"
    );

    for (code, category) in observed {
        assert_eq!(category_for_band(&code), category, "{code}");
    }
}

/// A code that both hosts emit must be spelled the same in both.
///
/// `oasts watch` is implemented once per host, so the failure a session ends on is declared in
/// Rust and again in TypeScript. Two written-down spellings of one code can drift; this is what
/// stops them, since neither host can see the other's constant.
#[test]
fn a_code_both_hosts_emit_is_spelled_the_same_in_both() {
    let shared = [("CODE_WATCH_IO", "crates/oasts/src/watch.rs")];
    let node = node_sources();
    let rust = rust_sources();
    for (name, rust_path) in shared {
        let in_rust = rust
            .iter()
            .find(|source| source.path.ends_with(rust_path))
            .and_then(|source| source.constants.get(name).cloned())
            .unwrap_or_else(|| panic!("{name} should be declared in {rust_path}"));
        let in_node = node
            .iter()
            .find_map(|source| {
                source
                    .constants
                    .iter()
                    .find(|(constant, _)| *constant == name)
                    .map(|(_, code)| code.clone())
            })
            .unwrap_or_else(|| panic!("{name} should be declared on the Node side"));
        assert_eq!(in_rust, in_node, "{name} disagrees across the two hosts");
    }
}

#[test]
fn diagnostic_category_has_only_its_two_constructor_writes() {
    let sources = rust_sources();
    for source in &sources {
        assert_eq!(
            source.category_mutations,
            0,
            "category mutation found in {}",
            source.path.display()
        );
    }
    assert_eq!(
        sources
            .iter()
            .map(|source| source.config_writes)
            .sum::<usize>(),
        1
    );
    assert_eq!(
        sources
            .iter()
            .map(|source| source.input_writes)
            .sum::<usize>(),
        1
    );
}

fn observed_rust_categories(sources: &[RustSource]) -> BTreeMap<String, Category> {
    let mut rules = BTreeMap::from([
        (
            "Diagnostic::config".to_owned(),
            FactoryRule {
                code_argument: 0,
                category: Category::Config,
            },
        ),
        (
            "Diagnostic::input".to_owned(),
            FactoryRule {
                code_argument: 0,
                category: Category::Input,
            },
        ),
    ]);
    infer_factory_rules(sources, &mut rules);

    let global_constants = global_constants(sources);
    let mut observed = BTreeMap::new();
    for source in sources {
        for function in &source.functions {
            for call in &function.calls {
                let Some(rule) = rules.get(&call.name) else {
                    continue;
                };
                let Some(argument) = call.arguments.get(rule.code_argument) else {
                    continue;
                };
                let direct = resolve_codes(argument, source, &global_constants);
                for code in &direct {
                    observe_category(&mut observed, code.clone(), rule.category);
                }
                if !direct.is_empty() || !argument.has_code_parameter {
                    continue;
                }

                for code in resolve_codes(&function.codes, source, &global_constants) {
                    observe_category(&mut observed, code, rule.category);
                }
                for producer_call in &function.calls {
                    for producer in source
                        .functions
                        .iter()
                        .filter(|producer| producer.name == producer_call.name)
                    {
                        for code in resolve_codes(&producer.codes, source, &global_constants) {
                            observe_category(&mut observed, code, rule.category);
                        }
                    }
                }
            }
        }
    }
    observed
}

fn infer_factory_rules(sources: &[RustSource], rules: &mut BTreeMap<String, FactoryRule>) {
    loop {
        let mut inferred = Vec::new();
        for function in sources.iter().flat_map(|source| &source.functions) {
            let Some(code_argument) = function.code_parameter else {
                continue;
            };
            let mut category = None;
            for call in &function.calls {
                let Some(rule) = rules.get(&call.name) else {
                    continue;
                };
                if !call
                    .arguments
                    .get(rule.code_argument)
                    .is_some_and(|argument| argument.has_code_parameter)
                {
                    continue;
                }
                if let Some(previous) = category {
                    assert_eq!(
                        previous, rule.category,
                        "{} routes its code through conflicting categories",
                        function.name
                    );
                }
                category = Some(rule.category);
            }
            if let Some(category) = category {
                inferred.push((
                    function.name.clone(),
                    FactoryRule {
                        code_argument,
                        category,
                    },
                ));
            }
        }

        let mut changed = false;
        for (name, rule) in inferred {
            if let Some(previous) = rules.get(&name) {
                assert_eq!(
                    previous, &rule,
                    "{name} has conflicting diagnostic factory definitions"
                );
            } else {
                rules.insert(name, rule);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

fn global_constants(sources: &[RustSource]) -> BTreeMap<String, BTreeSet<String>> {
    let mut global = BTreeMap::<String, BTreeSet<String>>::new();
    for source in sources {
        for (name, code) in &source.constants {
            global.entry(name.clone()).or_default().insert(code.clone());
        }
    }
    global
}

fn resolve_codes(
    references: &CodeReferences,
    source: &RustSource,
    global: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut codes = references.literals.clone();
    for name in &references.constants {
        if let Some(code) = source.constants.get(name) {
            codes.insert(code.clone());
            continue;
        }
        if let Some(candidates) = global.get(name) {
            assert_eq!(
                candidates.len(),
                1,
                "{name} is ambiguous outside its defining source"
            );
            codes.extend(candidates.iter().cloned());
        }
    }
    codes
}

fn observe_node_categories(sources: &[NodeSource], observed: &mut BTreeMap<String, Category>) {
    let diagnostics = sources
        .iter()
        .find(|source| source.path.ends_with("packages/oasts/src/diagnostics.ts"))
        .expect("Node diagnostics source should be in the production inventory");
    let start = diagnostics
        .text
        .find("export function configFailure(")
        .expect("configFailure should remain observable");
    let body = &diagnostics.text[start..];
    let end = body
        .find("\n}")
        .expect("configFailure should have a function body");
    let failure = body[..end]
        .lines()
        .find(|line| line.contains("return new CliFailure("))
        .expect("configFailure should construct a CliFailure");
    let exit_code = failure
        .split_once("new CliFailure(")
        .and_then(|(_, arguments)| arguments.split_once(','))
        .map(|(exit_code, _)| exit_code.trim())
        .expect("CliFailure should take an exit code");
    let category = match exit_code {
        "1" => Category::Input,
        "2" => Category::Config,
        _ => panic!("Node diagnostic has non-categorical exit code {exit_code}"),
    };

    let compact = sources
        .iter()
        .flat_map(|source| source.text.chars())
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    for source in sources {
        for (name, code) in &source.constants {
            assert!(
                compact.contains(&format!("configFailure({name},")),
                "Node diagnostic {code} is not routed through configFailure"
            );
            observe_category(observed, code.clone(), category);
        }
    }
}

fn observe_category(observed: &mut BTreeMap<String, Category>, code: String, category: Category) {
    if let Some(previous) = observed.insert(code.clone(), category) {
        assert_eq!(
            previous, category,
            "{code} is emitted with conflicting categories"
        );
    }
}

fn category_for_band(code: &str) -> Category {
    let bytes = code.as_bytes();
    assert_eq!(bytes.len(), 9, "{code}");
    assert_eq!(&bytes[..5], b"OASTS", "{code}");
    assert!(bytes[5..].iter().all(u8::is_ascii_digit), "{code}");
    let stage = if bytes[5] == b'9' {
        assert_ne!(
            bytes[6], b'9',
            "test sentinel emitted in production: {code}"
        );
        bytes[6]
    } else {
        bytes[5]
    };
    match stage {
        b'0' | b'1' => Category::Config,
        b'2'..=b'6' => Category::Input,
        _ => panic!("unassigned diagnostic stage in {code}"),
    }
}

fn rust_sources() -> Vec<RustSource> {
    let crates = workspace_root().join("crates");
    let mut paths = Vec::new();
    for entry in fs::read_dir(crates).expect("workspace crates should be readable") {
        let source = entry
            .expect("crate entry should be readable")
            .path()
            .join("src");
        if source.is_dir() {
            source_paths(&source, OsStr::new("rs"), &mut paths);
        }
    }
    paths.sort();
    paths.into_iter().map(parse_rust_source).collect()
}

fn parse_rust_source(path: PathBuf) -> RustSource {
    let text = fs::read_to_string(&path).expect("Rust source should be UTF-8");
    let syntax = syn::parse_file(&text).expect("production Rust should parse");
    let mut inventory = RustInventory::default();
    inventory.visit_file(&syntax);
    RustSource {
        path,
        constants: inventory.constants,
        codes: inventory.codes,
        functions: inventory.functions,
        config_writes: inventory.config_writes,
        input_writes: inventory.input_writes,
        category_mutations: inventory.category_mutations,
    }
}

fn node_sources() -> Vec<NodeSource> {
    let src = workspace_root().join("packages/oasts/src");
    let mut paths = Vec::new();
    source_paths(&src, OsStr::new("ts"), &mut paths);
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path).expect("Node source should be UTF-8");
            NodeSource {
                path,
                constants: node_code_constants(&text),
                codes: quoted_codes(&text),
                text,
            }
        })
        .collect()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("oasts-core is inside the workspace crates directory")
        .to_owned()
}

fn source_paths(directory: &Path, extension: &OsStr, paths: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("source directory should be readable") {
        let path = entry.expect("source entry should be readable").path();
        if path.is_dir() {
            source_paths(&path, extension, paths);
        } else if path.extension() == Some(extension) {
            paths.push(path);
        }
    }
}

#[derive(Default)]
struct RustInventory {
    constants: BTreeMap<String, String>,
    codes: BTreeSet<String>,
    functions: Vec<Function>,
    config_writes: usize,
    input_writes: usize,
    category_mutations: usize,
}

impl<'ast> Visit<'ast> for RustInventory {
    fn visit_attribute(&mut self, node: &'ast Attribute) {
        if !node.path().is_ident("doc") {
            visit::visit_attribute(self, node);
        }
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !is_test_only(&node.attrs) {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if is_test_only(&node.attrs) {
            return;
        }
        self.functions.push(function(&node.sig, &node.block));
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        if is_test_only(&node.attrs) {
            return;
        }
        self.functions.push(function(&node.sig, &node.block));
        visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_const(&mut self, node: &'ast ItemConst) {
        if is_test_only(&node.attrs) {
            return;
        }
        if node.ident.to_string().starts_with("CODE_")
            && let Expr::Lit(literal) = node.expr.as_ref()
            && let syn::Lit::Str(value) = &literal.lit
            && let Some(code) = exact_codes(&value.value()).into_iter().next()
        {
            self.constants.insert(node.ident.to_string(), code);
        }
        visit::visit_item_const(self, node);
    }

    fn visit_expr_lit(&mut self, node: &'ast ExprLit) {
        if let syn::Lit::Str(value) = &node.lit {
            self.codes.extend(exact_codes(&value.value()));
        }
        visit::visit_expr_lit(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast ExprStruct) {
        for field in &node.fields {
            if !member_is(&field.member, "category") {
                continue;
            }
            if expression_path_ends(&field.expr, &["Category", "Config"]) {
                self.config_writes += 1;
            } else if expression_path_ends(&field.expr, &["Category", "Input"]) {
                self.input_writes += 1;
            }
        }
        visit::visit_expr_struct(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast ExprAssign) {
        if matches!(node.left.as_ref(), Expr::Field(field) if member_is(&field.member, "category"))
        {
            self.category_mutations += 1;
        }
        visit::visit_expr_assign(self, node);
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        visit_macro_expressions(self, node);
    }
}

fn function(signature: &Signature, block: &Block) -> Function {
    let mut code_parameter = None;
    let mut call_index = 0;
    for input in &signature.inputs {
        let FnArg::Typed(parameter) = input else {
            continue;
        };
        if matches!(parameter.pat.as_ref(), Pat::Ident(identifier) if identifier.ident == "code") {
            code_parameter = Some(call_index);
        }
        call_index += 1;
    }

    let mut collector = FunctionCollector::default();
    collector.visit_block(block);
    Function {
        name: signature.ident.to_string(),
        code_parameter,
        codes: collector.codes,
        calls: collector.calls,
    }
}

#[derive(Default)]
struct FunctionCollector {
    codes: CodeReferences,
    calls: Vec<Call>,
}

impl<'ast> Visit<'ast> for FunctionCollector {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(function) = node.func.as_ref() {
            self.calls.push(Call {
                name: call_name(&function.path),
                arguments: node.args.iter().map(code_references).collect(),
            });
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        self.calls.push(Call {
            name: node.method.to_string(),
            arguments: node.args.iter().map(code_references).collect(),
        });
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_lit(&mut self, node: &'ast ExprLit) {
        if let syn::Lit::Str(value) = &node.lit {
            self.codes.literals.extend(exact_codes(&value.value()));
        }
        visit::visit_expr_lit(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        collect_path_reference(&node.path, &mut self.codes);
        visit::visit_expr_path(self, node);
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        visit_macro_expressions(self, node);
    }
}

fn visit_macro_expressions<V>(visitor: &mut V, node: &Macro)
where
    V: for<'syntax> Visit<'syntax>,
{
    let parser = Punctuated::<Expr, Token![,]>::parse_terminated;
    if let Ok(expressions) = parser.parse2(node.tokens.clone()) {
        for expression in &expressions {
            visitor.visit_expr(expression);
        }
    }
}

fn code_references(expression: &Expr) -> CodeReferences {
    let mut references = CodeReferences::default();
    let mut collector = ReferenceCollector {
        references: &mut references,
    };
    collector.visit_expr(expression);
    references
}

struct ReferenceCollector<'a> {
    references: &'a mut CodeReferences,
}

impl<'ast> Visit<'ast> for ReferenceCollector<'_> {
    fn visit_expr_lit(&mut self, node: &'ast ExprLit) {
        if let syn::Lit::Str(value) = &node.lit {
            self.references.literals.extend(exact_codes(&value.value()));
        }
        visit::visit_expr_lit(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        collect_path_reference(&node.path, self.references);
        visit::visit_expr_path(self, node);
    }
}

fn collect_path_reference(path: &syn::Path, references: &mut CodeReferences) {
    let Some(identifier) = path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
    else {
        return;
    };
    if identifier == "code" {
        references.has_code_parameter = true;
    } else if identifier.starts_with("CODE_") {
        references.constants.insert(identifier);
    }
}

fn call_name(path: &syn::Path) -> String {
    let mut segments = path.segments.iter().rev();
    let Some(last) = segments.next() else {
        return String::new();
    };
    if matches!(last.ident.to_string().as_str(), "config" | "input")
        && segments
            .next()
            .is_some_and(|segment| segment.ident == "Diagnostic")
    {
        format!("Diagnostic::{}", last.ident)
    } else {
        last.ident.to_string()
    }
}

fn is_test_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && matches!(
                &attribute.meta,
                syn::Meta::List(list)
                    if list.tokens.to_string().split(|character: char| !character.is_ascii_alphanumeric() && character != '_').any(|token| token == "test")
            )
    })
}

fn expression_path_ends(expression: &Expr, expected: &[&str]) -> bool {
    let Expr::Path(path) = expression else {
        return false;
    };
    path.path
        .segments
        .iter()
        .rev()
        .map(|segment| segment.ident.to_string())
        .zip(expected.iter().rev().copied())
        .all(|(actual, expected)| actual == expected)
        && path.path.segments.len() >= expected.len()
}

fn member_is(member: &Member, expected: &str) -> bool {
    matches!(member, Member::Named(identifier) if identifier == expected)
}

fn node_code_constants(source: &str) -> BTreeMap<String, String> {
    let mut constants = BTreeMap::new();
    for line in source.lines() {
        let Some(code) = quoted_codes(line).into_iter().next() else {
            continue;
        };
        let Some(const_offset) = line.find("const ") else {
            continue;
        };
        let name = line[const_offset + "const ".len()..]
            .trim_start()
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect::<String>();
        if name.starts_with("CODE_") {
            constants.insert(name, code);
        }
    }
    constants
}

fn quoted_codes(source: &str) -> BTreeSet<String> {
    let bytes = source.as_bytes();
    let mut codes = BTreeSet::new();
    for (offset, window) in bytes.windows(9).enumerate() {
        if &window[..5] != b"OASTS" || !window[5..].iter().all(u8::is_ascii_digit) {
            continue;
        }
        let before = offset.checked_sub(1).and_then(|index| bytes.get(index));
        let after = bytes.get(offset + 9);
        if matches!((before, after), (Some(b'\'' | b'"'), Some(b'\'' | b'"'))) {
            codes.insert(String::from_utf8(window.to_vec()).expect("ASCII diagnostic code"));
        }
    }
    codes
}

fn exact_codes(source: &str) -> BTreeSet<String> {
    source
        .as_bytes()
        .windows(9)
        .filter(|window| &window[..5] == b"OASTS" && window[5..].iter().all(u8::is_ascii_digit))
        .map(|window| String::from_utf8(window.to_vec()).expect("ASCII diagnostic code"))
        .collect()
}
