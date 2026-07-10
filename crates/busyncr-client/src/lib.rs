//! BusyNCR client library: the pieces of the backup client that integration
//! tests (and later slices) drive directly. The binary (`main.rs`) is a thin
//! CLI shell over these modules.

pub mod enroll;
