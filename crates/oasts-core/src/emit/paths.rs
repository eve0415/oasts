//! Where emitted files land, and how they import each other.
//!
//! Every artifact's directory is configurable, so no emitter may spell its own — or another
//! artifact's — location literally. Emitters build their paths under [`ArtifactDirs`] and reach
//! every other artifact through [`relative_import`], which derives the specifier from the two
//! output-relative paths rather than from a hardcoded `../` count.

use crate::config::ResolvedConfig;

/// The codecs' subdirectory inside the client's tree. Not configured on its own: they run only at
/// the client's pipeline positions and are emitted with the client, so they follow wherever it
/// goes. Both the codec emitter and the tanstack artifact that imports them name it from here.
pub(crate) const TRANSFORM_SUBDIR: &str = "transform";

/// Where each artifact's files land, relative to the output root, in normalized `/`-separated form.
///
/// Borrowed from the resolved config rather than copied out of it: this is read once per emitted
/// path and once per import, and a compile should not pay a string copy per artifact to learn a
/// layout the config already holds.
pub(crate) struct ArtifactDirs<'config> {
    pub(crate) types: &'config str,
    pub(crate) client: &'config str,
    pub(crate) zod: &'config str,
    pub(crate) validators: &'config str,
    pub(crate) tanstack: &'config str,
    pub(crate) msw: &'config str,
    pub(crate) runtime: &'config str,
}

impl<'config> ArtifactDirs<'config> {
    pub(crate) fn new(config: &'config ResolvedConfig) -> Self {
        Self {
            types: &config.artifacts.types.directory,
            client: &config.artifacts.client.directory,
            zod: &config.artifacts.zod.directory,
            validators: &config.artifacts.validators.directory,
            tanstack: &config.artifacts.tanstack.directory,
            msw: &config.artifacts.msw.directory,
            runtime: &config.emit.runtime_directory,
        }
    }
}

/// The specifier `from_file` must use to import the module `to` names.
///
/// `to` is the target module's path in parts — typically an artifact directory, a subdirectory and
/// a file stem — which the caller passes as a stack array so building the target costs nothing;
/// any part may itself carry `/`. Both sides are output-root-relative and `/`-separated, and the
/// stem carries no extension: `extension` supplies it (`.js`, or empty under
/// `emit.importExtension: none`). The walk compares whole segments — a `types2` directory is not
/// inside `types` — and always returns a relative specifier, `./`-prefixed when the target is a
/// sibling, so nothing is ever mistaken for a package.
pub(crate) fn relative_import(from_file: &str, to: &[&str], extension: &str) -> String {
    // The importing file's own name is not part of the directory it imports from. A file at the
    // output root has no directory at all, and so climbs out of nothing.
    let from_directory = from_file.rfind('/').map_or("", |slash| &from_file[..slash]);
    let depth = from_directory
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count();
    let target = || to.iter().flat_map(|part| part.split('/'));

    let shared = from_directory
        .split('/')
        .zip(target())
        .take_while(|(left, right)| left == right)
        .count();

    let climb = depth - shared;
    let mut specifier = String::with_capacity(
        climb * 3 + to.iter().map(|part| part.len() + 1).sum::<usize>() + extension.len() + 2,
    );
    if climb == 0 {
        specifier.push_str("./");
    }
    for _ in 0..climb {
        specifier.push_str("../");
    }
    for (index, segment) in target().skip(shared).enumerate() {
        if index > 0 {
            specifier.push('/');
        }
        specifier.push_str(segment);
    }
    specifier.push_str(extension);
    specifier
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_import_climbs_out_of_the_importer_and_back_down_to_its_target() {
        assert_eq!(
            relative_import(
                "client/operations/getpet.ts",
                &["types", "operations/getpet"],
                ".js"
            ),
            "../../types/operations/getpet.js"
        );
        assert_eq!(
            relative_import("client/auth.ts", &["runtime", "transport"], ".js"),
            "../runtime/transport.js"
        );
        assert_eq!(
            relative_import(
                "client/transform/components/pet.ts",
                &["types", "components", "pet"],
                ".js"
            ),
            "../../../types/components/pet.js"
        );
    }

    #[test]
    fn a_shared_prefix_is_climbed_only_as_far_as_it_diverges() {
        assert_eq!(
            relative_import("zod/components/pet.ts", &["zod", "runtime"], ".js"),
            "../runtime.js"
        );
        assert_eq!(
            relative_import("a/b/c/pet.ts", &["a/b/d", "e", "pet"], ".js"),
            "../d/e/pet.js"
        );
    }

    #[test]
    fn a_sibling_target_is_dot_slash_prefixed_so_it_never_reads_as_a_package() {
        assert_eq!(
            relative_import("msw/paths.ts", &["msw", "runtime"], ".js"),
            "./runtime.js"
        );
        assert_eq!(
            relative_import("msw/paths.ts", &["msw", "handlers", "list"], ""),
            "./handlers/list"
        );
    }

    #[test]
    fn a_directory_that_merely_starts_with_another_is_not_inside_it() {
        assert_eq!(
            relative_import("types2/pet.ts", &["types", "pet"], ".js"),
            "../types/pet.js"
        );
    }

    #[test]
    fn a_file_at_the_output_root_climbs_out_of_nothing() {
        assert_eq!(
            relative_import("index.ts", &["types", "components", "pet"], ".js"),
            "./types/components/pet.js"
        );
    }
}
