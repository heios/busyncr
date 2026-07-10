//! BusyNCR daemon library: the backup server's storage engine.
//!
//! The binary (`main.rs`) grows its CLI slice by slice; the reusable pieces
//! live here so integration tests and later slices (gRPC service, prune, GC)
//! can drive them directly.

#![deny(missing_docs)]

pub mod identity;
pub mod service;
pub mod store;
