use std::collections::{HashMap, HashSet};

use crate::config::ResolvedConfig;
use crate::diag::DiagnosticSink;
use crate::ir::SourceRef;
use crate::semantic::Analyzed;

use super::{
    CODE_FILE_NAME, CODE_PATH_COLLISION, file_base_name, shape_variants, source_diagnostic,
};

#[derive(Clone, Debug)]
pub(crate) struct SchemaTarget {
    pub(crate) index: usize,
    pub(crate) name: String,
    pub(crate) file_base: String,
    pub(crate) request_differs: bool,
    pub(crate) response_differs: bool,
}

/// Shared deterministic allocation product for all emitters.
pub(crate) struct EmissionModel<'input, 'sink> {
    pub(crate) analyzed: &'input Analyzed,
    pub(crate) config: &'input ResolvedConfig,
    digest: String,
    schema_targets: HashMap<String, HashMap<String, SchemaTarget>>,
    pub(crate) component_files: Vec<Option<String>>,
    pub(crate) operation_files: Vec<Option<String>>,
    seen: HashMap<String, (String, SourceRef)>,
    pub(crate) sink: &'sink mut DiagnosticSink,
}

impl<'input, 'sink> EmissionModel<'input, 'sink> {
    pub(crate) fn new(
        analyzed: &'input Analyzed,
        config: &'input ResolvedConfig,
        digest: String,
        sink: &'sink mut DiagnosticSink,
    ) -> Self {
        let mut model = Self {
            analyzed,
            config,
            digest,
            schema_targets: HashMap::new(),
            component_files: vec![None; analyzed.ir.schemas.len()],
            operation_files: vec![None; analyzed.ir.operations.len()],
            seen: HashMap::new(),
            sink,
        };
        model.allocate_paths();
        model
    }

    fn allocate_paths(&mut self) {
        for allocated in &self.analyzed.schema_names {
            let schema = &self.analyzed.ir.schemas[allocated.schema_index];
            let Some(file_base) = self.allocate_file_base(&allocated.wire_name, &schema.source)
            else {
                continue;
            };
            let relative = format!("types/components/{file_base}.ts");
            self.register_path(&relative, &schema.source);
            self.component_files[allocated.schema_index] = Some(file_base.clone());
            let (request_differs, response_differs) = shape_variants(&schema.schema);
            self.schema_targets
                .entry(schema.source.source_id.clone())
                .or_default()
                .insert(
                    schema.source.json_pointer.clone(),
                    SchemaTarget {
                        index: allocated.schema_index,
                        name: allocated.name.clone(),
                        file_base,
                        request_differs,
                        response_differs,
                    },
                );
        }
        for allocated in &self.analyzed.operation_names {
            let operation = &self.analyzed.ir.operations[allocated.operation_index];
            let source_name = operation.operation_id.as_deref().unwrap_or(&allocated.name);
            let Some(file_base) = self.allocate_file_base(source_name, &operation.source) else {
                continue;
            };
            let relative = format!("types/operations/{file_base}.ts");
            self.register_path(&relative, &operation.source);
            self.operation_files[allocated.operation_index] = Some(file_base);
        }
    }

    fn allocate_file_base(&mut self, name: &str, source: &SourceRef) -> Option<String> {
        match file_base_name(name, self.config.naming.file_case) {
            Ok(file_base) => Some(file_base),
            Err(error) => {
                self.sink.push(source_diagnostic(
                    CODE_FILE_NAME,
                    format!("invalid generated file name for '{name}': {error}"),
                    source,
                ));
                None
            }
        }
    }

    /// Registers an artifact path in the shared case-folded collision namespace.
    pub(crate) fn register_path(&mut self, path: &str, source: &SourceRef) {
        let folded = path.to_ascii_lowercase();
        if let Some((previous, previous_source)) = self.seen.get(&folded) {
            self.sink.push(source_diagnostic(
                CODE_PATH_COLLISION,
                format!(
                    "generated path collision after case folding: '{previous}' at {} and '{path}' at {}",
                    previous_source.display(),
                    source.display()
                ),
                source,
            ));
        } else {
            self.seen.insert(folded, (path.to_owned(), source.clone()));
        }
    }

    pub(crate) fn schema_target(
        &self,
        source_id: &str,
        json_pointer: &str,
    ) -> Option<&SchemaTarget> {
        self.schema_targets.get(source_id)?.get(json_pointer)
    }

    /// Renames component target names that collide with identifiers a terminal emitter injects into
    /// every one of its files (e.g. the validators kernel imports and helpers), so an exported type
    /// never shadows an imported one (TS2440). All name usages — the component's own export, its
    /// self/cross references, sibling imports, and the rendered structural type — read the target
    /// name, so mutating it here keeps every site consistent. Only exact (case-sensitive) matches
    /// are renamed, since that is what actually conflicts in a TypeScript module scope; colliding
    /// names get the lowest free numeric suffix, deterministically across runs. Call this only from
    /// the last emitter to run: it mutates the shared allocation, and any emitter reading target
    /// names afterward would see the renamed set.
    pub(crate) fn reserve_names(&mut self, reserved: &[&str]) {
        let analyzed = self.analyzed;
        let mut taken: HashSet<String> = reserved.iter().map(|name| (*name).to_owned()).collect();
        for targets in self.schema_targets.values() {
            for target in targets.values() {
                taken.insert(target.name.clone());
            }
        }
        for allocated in &analyzed.schema_names {
            let schema = &analyzed.ir.schemas[allocated.schema_index];
            let Some(target) = self
                .schema_targets
                .get_mut(&schema.source.source_id)
                .and_then(|by_pointer| by_pointer.get_mut(&schema.source.json_pointer))
            else {
                continue;
            };
            if !reserved.contains(&target.name.as_str()) {
                continue;
            }
            let base = target.name.clone();
            let mut suffix = 2u32;
            let mut candidate = format!("{base}{suffix}");
            while taken.contains(&candidate) {
                suffix += 1;
                candidate = format!("{base}{suffix}");
            }
            taken.insert(candidate.clone());
            target.name = candidate;
        }
    }

    pub(crate) fn header(&self) -> String {
        let mut output = format!(
            "// Generated by Oasts {}. Do not edit.\n// Config schema version: 1\n// Source digest: {}\n",
            crate::version(),
            self.digest
        );
        for line in &self.config.emit.banner {
            output.push_str("// ");
            output.push_str(line);
            output.push('\n');
        }
        output.push('\n');
        output
    }
}
