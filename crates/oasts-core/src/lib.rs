pub mod client_model;
mod composition;
pub mod config;
pub mod diag;
pub mod driver;
pub mod emit;
mod headers;
pub mod ir;
pub mod loader;
mod media;
pub mod msw_peer;
pub mod num;
mod param_serialization;
pub mod parse;
mod peer;
pub mod pipeline;
mod response_media;
pub mod semantic;
mod syntax;
pub mod transform;
pub mod writer;
pub mod zod_peer;

/// Crate version string embedded in generated file headers.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_cargo() {
        assert_eq!(version(), "0.0.1");
    }
}
