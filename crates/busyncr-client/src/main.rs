//! BusyNCR client: runs on the host being backed up (Windows service in
//! production; Linux for dev/test). CLI surface grows slice by slice:
//! backup | restore | list | bench-chunking | export-key | import-key | enroll

fn main() {
    println!("busyncr-client {} (skeleton)", busyncr_core::VERSION);
}
