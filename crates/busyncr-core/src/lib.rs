//! BusyNCR core: content-defined chunking, manifests, chunk store, crypto,
//! retention grid. Pure cross-platform logic — no networking, no OS services.

#![deny(missing_docs)]

pub mod bench;
pub mod chunking;
pub mod index;
pub mod manifest;

/// Crate version, re-exported for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_is_green() {
        assert_eq!(super::VERSION, env!("CARGO_PKG_VERSION"));
    }
}
