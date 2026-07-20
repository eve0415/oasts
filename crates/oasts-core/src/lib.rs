pub mod client_model;
pub mod config;
pub mod diag;
pub mod emit;
pub mod ir;
pub mod loader;
pub mod num;
pub mod parse;
pub mod pipeline;
pub mod semantic;
mod syntax;
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
