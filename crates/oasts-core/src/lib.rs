pub mod client_model;
mod composition;
pub mod config;
pub mod diag;
pub mod emit;
mod headers;
pub mod ir;
pub mod loader;
mod media;
pub mod num;
pub mod parse;
pub mod pipeline;
pub mod semantic;
mod syntax;
pub mod transform;
pub mod writer;

/// Crate version string embedded in generated file headers.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_cargo() {
        assert_eq!(version(), "0.0.0");
    }
}
