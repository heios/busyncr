//! Minimal Windows Event Log writer (PRD §3.6: "event-log logging").
//!
//! This whole module only exists on Windows (declared behind `#[cfg(windows)]`
//! in `service.rs`). `windows-service` (the AGENTS.md palette crate for
//! Windows service integration) wraps SCM install/start/stop/dispatch but
//! does not itself wrap the Event Log APIs, so this calls the three
//! functions actually needed — `RegisterEventSourceW`, `ReportEventW`,
//! `DeregisterEventSource` (all `advapi32.dll`) — directly via `windows-sys`,
//! which `windows-service` already pulls in transitively at the exact same
//! version (see the `Cargo.toml` comment next to the `windows-sys`
//! dependency). `std::os::windows::ffi::OsStrExt::encode_wide` (std) is
//! sufficient for the UTF-16 conversion these APIs need, so no wide-string
//! crate is required either.
//!
//! Every entry is written under the source name [`super::SERVICE_NAME`] —
//! `service install` registers that name as an event source the first time
//! Windows needs it (`RegisterEventSourceW` implicitly creates a generic-
//! message registration if none exists), so no separate registry setup step
//! is required for this minimal usage.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
    EVENTLOG_INFORMATION_TYPE,
};

use super::SERVICE_NAME;

/// Encodes `s` as a NUL-terminated UTF-16 buffer, as every wide Win32 string
/// API here expects.
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Writes an informational entry to the Application event log.
///
/// Best-effort: logging is diagnostic, not part of the service's control
/// flow, and there is nowhere better to report a logging failure itself —
/// see [`log_event`].
pub fn log_info(message: &str) {
    log_event(EVENTLOG_INFORMATION_TYPE, message);
}

/// Writes an error entry to the Application event log (see [`log_info`]).
pub fn log_error(message: &str) {
    log_event(EVENTLOG_ERROR_TYPE, message);
}

/// Registers (or reuses) the `SERVICE_NAME` event source, writes one entry,
/// and deregisters. Silently does nothing if registration fails (e.g. no
/// Application log access) — never panics, never surfaces an error the
/// service loop would have to handle.
fn log_event(event_type: u16, message: &str) {
    let source = to_wide(SERVICE_NAME);
    // SAFETY: `source` is a valid, NUL-terminated UTF-16 buffer that outlives
    // this call. A null first argument means "local computer", per the
    // Win32 API contract. The returned handle is checked for null below
    // before any further use.
    let handle = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
    if handle.is_null() {
        return;
    }

    let text = to_wide(message);
    let strings: [*const u16; 1] = [text.as_ptr()];
    // SAFETY: `handle` is the just-registered, non-null source handle;
    // `strings` holds one pointer to a NUL-terminated UTF-16 string that
    // outlives this call; no SID or raw binary data is passed.
    unsafe {
        ReportEventW(
            handle,
            event_type,
            0,
            0,
            std::ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            std::ptr::null(),
        );
        DeregisterEventSource(handle);
    }
}
