//! Listing the backup history stored on the daemon (`list`, FR6/PRD §6 CLI).
//!
//! Snapshot IDs are ULIDs whose 48-bit timestamp field is the client-side
//! creation time (set at backup), so history can be listed — and displayed
//! with human-readable times — without decrypting anything. Listing
//! therefore works even before `import-key` on a migrated machine; only
//! reading a snapshot's *contents* needs the data key.

// tonic::Status is 176 bytes and rides inside ListError; same call as the
// other client modules — boxing at every `?` conversion would cost more than
// the large variant does.
#![allow(clippy::result_large_err)]

use std::path::Path;

use busyncr_proto::v1::ListSnapshotsRequest;
use ulid::Ulid;

use crate::enroll::{self, EnrollError};

/// One retained snapshot, as reported by the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotEntry {
    /// The snapshot's ULID (the handle `restore` takes).
    pub id: Ulid,
    /// Milliseconds since the Unix epoch, from the ULID's timestamp field
    /// (client clock at backup time).
    pub timestamp_ms: u64,
}

/// Errors from listing snapshots.
#[derive(Debug, thiserror::Error)]
pub enum ListError {
    /// Loading local identity or connecting to the daemon failed.
    #[error(transparent)]
    Enroll(#[from] EnrollError),

    /// The daemon refused the RPC.
    #[error("daemon refused the list RPC: {0}")]
    Rpc(#[from] tonic::Status),

    /// The daemon returned a snapshot ID that is not a 16-byte ULID.
    #[error("daemon returned a malformed snapshot ID ({len} bytes, expected 16)")]
    BadSnapshotId {
        /// Length of the offending ID.
        len: usize,
    },
}

/// Fetches the daemon's snapshot list over the enrolled mTLS identity in
/// `state_dir`, oldest first.
///
/// # Errors
///
/// [`ListError::Enroll`] when the machine is not enrolled or the daemon is
/// unreachable, [`ListError::Rpc`] when the daemon refuses (e.g. revoked
/// certificate), [`ListError::BadSnapshotId`] on a protocol violation.
pub async fn list_snapshots(
    daemon_url: &str,
    state_dir: &Path,
) -> Result<Vec<SnapshotEntry>, ListError> {
    let mut client = enroll::connect_authenticated(daemon_url, state_dir).await?;
    let response = client
        .list_snapshots(ListSnapshotsRequest {})
        .await?
        .into_inner();

    let mut entries = Vec::with_capacity(response.snapshot_ids.len());
    for raw in &response.snapshot_ids {
        let bytes: [u8; 16] = raw
            .as_slice()
            .try_into()
            .map_err(|_| ListError::BadSnapshotId { len: raw.len() })?;
        let id = Ulid::from_bytes(bytes);
        entries.push(SnapshotEntry {
            id,
            timestamp_ms: id.timestamp_ms(),
        });
    }
    // The daemon already sorts ascending; sort defensively so callers can
    // rely on chronological order regardless.
    entries.sort_by_key(|e| (e.timestamp_ms, e.id));
    Ok(entries)
}

/// Formats a Unix-epoch millisecond timestamp as `YYYY-MM-DD HH:MM:SS UTC`
/// for `list` output — hand-rolled (Howard Hinnant's civil-from-days
/// algorithm) because no calendar crate is in the dependency palette.
#[must_use]
pub fn format_utc_ms(timestamp_ms: u64) -> String {
    let secs = timestamp_ms / 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

/// Converts days since 1970-01-01 to a (year, month, day) civil date.
/// Reference: <https://howardhinnant.github.io/date_algorithms.html>.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    (year + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_timestamps() {
        assert_eq!(format_utc_ms(0), "1970-01-01 00:00:00 UTC");
        // 2023-11-14T22:13:20Z
        assert_eq!(format_utc_ms(1_700_000_000_000), "2023-11-14 22:13:20 UTC");
        // Leap-day handling: 2024-02-29T12:00:00Z = 1709208000.
        assert_eq!(format_utc_ms(1_709_208_000_000), "2024-02-29 12:00:00 UTC");
        // Sub-second precision truncates.
        assert_eq!(format_utc_ms(999), "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn ulid_timestamp_matches_from_parts() {
        let id = Ulid::from_parts(1_700_000_000_000, 7);
        assert_eq!(id.timestamp_ms(), 1_700_000_000_000);
        assert_eq!(format_utc_ms(id.timestamp_ms()), "2023-11-14 22:13:20 UTC");
    }
}
