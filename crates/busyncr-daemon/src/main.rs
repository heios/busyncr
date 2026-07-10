//! BusyNCR daemon: runs on the backup server. Stores versioned snapshots in a
//! content-addressed chunk store, enforces the retention grid, garbage-collects.
//! CLI surface grows slice by slice: serve | prune | gc | enroll-token

fn main() {
    println!("busyncr-daemon {} (skeleton)", busyncr_core::VERSION);
}
