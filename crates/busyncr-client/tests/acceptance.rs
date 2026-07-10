//! S13/C4 acceptance sweep: FR1-FR10 (PRD §4, §5) and phase-2 FR-K1/FR-C1-C7
//! (FR-K1.md, FR-C1.md) traceability.
//!
//! This is not a re-implementation of any FR's behavior — every FR already
//! has its own dedicated test(s) elsewhere in the workspace, named
//! `fr<N>_*` (v1) or `frk1<letter?>_*` / `frc<N><letter?>_*` (phase 2) per
//! AGENTS.md. What this test adds is the thing no single per-FR test can:
//! proof, enforced by `cargo test --workspace` itself, that the *whole*
//! FR matrix (v1 + phase 2) is present and compiled into the suite at
//! once, with no gaps and no silent deletions. If a future change renames
//! or removes the last `fr5_*` or `frc4_*` test without adding a
//! replacement, this test — not a human re-reading SLICES.md — is what
//! fails.
//!
//! It works by walking every `.rs` file under `crates/` (this workspace's
//! only source root) and parsing out `fn fr<...>_...` test-function names
//! with plain string scanning (no `regex` dependency — not in the AGENTS.md
//! palette), classifying each into [`FrId::V1`] (`fr1`..`fr10`),
//! [`FrId::K`] (`frk1`, optionally letter-suffixed: `frk1a`, `frk1b`, ...),
//! or [`FrId::C`] (`frc1`..`frc7`, optionally letter-suffixed: `frc5a`,
//! `frc5b`, ...), then asserting every FR in the matrix has at least one
//! match, per the slices' "each FR covered by >= 1 test named fr<...>_*"
//! requirement. A letter suffix (e.g. FR-C5's `a`/`b`/`c`/`d` sub-criteria)
//! counts toward the same FR — the spec does not require one test per
//! sub-letter, only that the letter itself is a legal way to name multiple
//! tests against one FR without colliding identifiers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Which functional requirement a `fn fr<...>_...` test claims.
///
/// `V1` covers PRD §4's FR1-FR10; `K` and `C` cover the phase-2 FR-K1.md /
/// FR-C1.md numbering (`frk<N>` / `frc<N>`, optionally letter-suffixed for
/// sub-criteria, e.g. `frc5a_...` for FR-C5's criterion (a)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FrId {
    /// PRD §4 FR`<N>`, `N` in 1..=10.
    V1(u32),
    /// FR-K1.md FR-K`<N>` (currently only `FR-K1` exists).
    K(u32),
    /// FR-C1.md FR-C`<N>`, `N` in 1..=7.
    C(u32),
}

impl std::fmt::Display for FrId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrId::V1(n) => write!(f, "FR{n}"),
            FrId::K(n) => write!(f, "FR-K{n}"),
            FrId::C(n) => write!(f, "FR-C{n}"),
        }
    }
}

/// One `fn fr<...>_...` match: which FR it claims, its full name, and where
/// it was found (for readable failure output).
#[derive(Debug, Clone)]
struct FrTest {
    fr: FrId,
    name: String,
    location: String,
}

/// Absolute path to this very file (the scanner), resolved once so the walk
/// can exclude it. The scanner's own regression-test fixture below
/// (`acceptance_scanner_matches_only_true_fr_test_names`) deliberately
/// contains the literal text `fn fr1_enrolls_successfully() {}` and
/// `fn fr10_reads_each_file_once() {}` as sample data for the string
/// scanner to chew on — if this file were included in the FR1-FR10 sweep
/// below, those two literals would always register as "found", making the
/// sweep incapable of ever detecting a missing FR1 or FR10 test. Excluding
/// this file's own path (not just skipping string literals generically)
/// is the simplest exclusion that cannot itself be fooled by future
/// fixture changes.
fn this_file_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/acceptance.rs")
}

/// Recursively collects every `fn fr<N>_...` test-function name under
/// `dir`, skipping `target/` build output and this scanner's own source
/// file (see [`this_file_path`]).
fn collect_fr_tests(dir: &Path, out: &mut Vec<FrTest>) {
    let self_path = this_file_path();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        // The workspace layout is fixed at repo root; a read failure here
        // means the sweep itself is broken, which the test should report as
        // a failure rather than silently pass with an empty (trivially
        // "complete") set.
        Err(err) => panic!("acceptance sweep could not read {}: {err}", dir.display()),
    };
    for entry in entries {
        let entry = entry.unwrap_or_else(|err| {
            panic!(
                "acceptance sweep: bad directory entry under {}: {err}",
                dir.display()
            )
        });
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("target") {
                continue;
            }
            collect_fr_tests(&path, out);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if path == self_path {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("acceptance sweep: reading {}: {err}", path.display()));
        for (name, fr) in extract_fr_fn_names(&content) {
            out.push(FrTest {
                fr,
                name,
                location: path.display().to_string(),
            });
        }
    }
}

/// Parses a `<digits>[<lowercase-letters>]_` prefix (the part of an
/// identifier after the `fr`/`frk`/`frc` marker) and returns the parsed
/// number iff a `_` immediately follows the optional letter suffix — the
/// letter suffix exists so multiple tests can target one FR's sub-criteria
/// (e.g. FR-C5's `(a)`-`(d)`) without colliding identifiers, e.g.
/// `"5a_stored_bytes..."` -> `Some(5)`, `"1_raw_codec..."` -> `Some(1)`,
/// `"_helper"` (no digits) -> `None`.
fn parse_numbered_prefix(s: &str) -> Option<u32> {
    let digit_len = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if digit_len == 0 {
        return None;
    }
    let after_digits = &s[digit_len..];
    let letter_len = after_digits
        .find(|c: char| !c.is_ascii_lowercase())
        .unwrap_or(after_digits.len());
    if after_digits.as_bytes().get(letter_len) == Some(&b'_') {
        s[..digit_len].parse::<u32>().ok()
    } else {
        None
    }
}

/// Scans `content` for `fn fr<...>_<rest>` identifiers and returns each as
/// `(full_identifier, FrId)`. Deliberately hand-rolled (no `regex` in the
/// palette): finds every `fn fr` substring, reads the identifier that
/// follows, and classifies it:
///
/// - `fr<digits>_...` (no letter suffix) -> [`FrId::V1`] (PRD §4 FR1-FR10,
///   e.g. `fr1_foo` -> FR1, `fr10_foo` -> FR10);
/// - `frk<digits>[<letters>]_...` -> [`FrId::K`] (FR-K1.md, e.g.
///   `frk1_foo` / `frk1a_foo` -> FR-K1);
/// - `frc<digits>[<letters>]_...` -> [`FrId::C`] (FR-C1.md, e.g.
///   `frc5b_foo` -> FR-C5);
///
/// anything else (`from_str`, `fresh`, `fr_helper`, `frobnicate`, a bare
/// `fn fr(...)`, ...) never matches.
fn extract_fr_fn_names(content: &str) -> Vec<(String, FrId)> {
    let mut results = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = content[search_from..].find("fn fr") {
        let ident_start = search_from + rel + 3; // skip "fn "
        let rest = &content[ident_start..];
        let ident_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let ident = &rest[..ident_len];
        if let Some(after_fr) = ident.strip_prefix("fr") {
            let matched = if let Some(after_k) = after_fr.strip_prefix('k') {
                parse_numbered_prefix(after_k).map(FrId::K)
            } else if let Some(after_c) = after_fr.strip_prefix('c') {
                parse_numbered_prefix(after_c).map(FrId::C)
            } else {
                // v1 FRs never take a letter suffix (kept exactly as
                // originally scanned, so no pre-existing fr<N>_* name can
                // silently reclassify).
                let digit_len = after_fr
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(after_fr.len());
                let has_underscore_after_digits = after_fr.as_bytes().get(digit_len) == Some(&b'_');
                if digit_len > 0 && has_underscore_after_digits {
                    after_fr[..digit_len].parse::<u32>().ok().map(FrId::V1)
                } else {
                    None
                }
            };
            if let Some(fr) = matched {
                results.push((ident.to_string(), fr));
            }
        }
        search_from = ident_start + ident_len.max(1);
    }
    results
}

/// The `crates/` directory at the workspace root, resolved relative to this
/// crate's manifest (`.../crates/busyncr-client` -> `.../crates`).
fn workspace_crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("busyncr-client's manifest dir has a parent (crates/)")
        .to_path_buf()
}

/// PRD §4 FR1-FR10, one line each, for readable failure messages — kept
/// short and paraphrased (PRD.md itself is normative and is never modified
/// by this test).
const FR_DESCRIPTIONS: [(FrId, &str); 10] = [
    (FrId::V1(1), "Enroll a client against a fresh daemon"),
    (
        FrId::V1(2),
        "Back up a folder tree -> snapshot appears in daemon version list",
    ),
    (
        FrId::V1(3),
        "Second backup after edits ships only new/changed chunks",
    ),
    (
        FrId::V1(4),
        "Restore any retained snapshot byte-exact, including metadata",
    ),
    (
        FrId::V1(5),
        "Retention grid prunes correctly; GC reclaims; survivors restore",
    ),
    (
        FrId::V1(6),
        "Keyfile export/import on a new machine restores old history",
    ),
    (FrId::V1(7), "Daemon never possesses plaintext"),
    (
        FrId::V1(8),
        "Client Windows service / daemon long-lived process survive restart",
    ),
    (
        FrId::V1(9),
        "Corrupt/truncated chunk detected on restore, not silently",
    ),
    (
        FrId::V1(10),
        "bench-chunking single-pass, reference-matching, exact projections",
    ),
];

/// FR-K1.md and FR-C1.md acceptance criteria (§3 / §5 respectively), one
/// line each, paraphrased the same way as [`FR_DESCRIPTIONS`] — those specs
/// are normative and are never modified by this test.
const FR_PHASE2_DESCRIPTIONS: [(FrId, &str); 8] = [
    (
        FrId::K(1),
        "Keyed chunk identity closes the known-plaintext confirmation channel \
         (determinism/key-separation, confirmation attack, full v1 regression, \
         keyfile v2)",
    ),
    (
        FrId::C(1),
        "Codec round-trip byte-exact; unknown codec byte is an integrity error",
    ),
    (
        FrId::C(2),
        "Pre-compressed corpus backs up >=99% raw, stored <=1.01x input",
    ),
    (
        FrId::C(3),
        "Compressible corpus stores >=2x smaller under default policy than raw-only",
    ),
    (
        FrId::C(4),
        "Mixed-codec history restores byte-exact; prune/GC and dedup unaffected \
         by a policy change",
    ),
    (
        FrId::C(5),
        "bench-chunking --compression: single-pass, matches real backup bytes, \
         baseline projection within +/-5%, speed projections internally consistent",
    ),
    (
        FrId::C(6),
        "Escalation phase gate: never during initial backup, fires for \
         qualifying chunks during incremental",
    ),
    (
        FrId::C(7),
        "Zero-knowledge preserved: stored blobs reveal neither codec choice \
         nor compressibility beyond the documented ciphertext-length leak",
    ),
];

/// Runs the scanner once and groups results by [`FrId`]. Shared by both
/// traceability assertions below so the (potentially slow) directory walk
/// happens at most once per test binary invocation... actually once per
/// call, kept simple and re-run per test (the walk is cheap relative to
/// `cargo test`'s own overhead) rather than sharing a `OnceLock` across
/// tests, to keep each test's failure self-contained and order-independent.
fn scan() -> BTreeMap<FrId, Vec<FrTest>> {
    let mut found = Vec::new();
    collect_fr_tests(&workspace_crates_dir(), &mut found);
    let mut by_fr: BTreeMap<FrId, Vec<FrTest>> = BTreeMap::new();
    for t in found {
        by_fr.entry(t.fr).or_default().push(t);
    }
    by_fr
}

/// The core traceability assertion (S13): every FR in PRD §4 has at least
/// one `fr<N>_*` test compiled somewhere in the workspace.
#[test]
fn acceptance_fr1_through_fr10_each_have_a_named_test() {
    let by_fr = scan();
    let total: usize = by_fr.values().map(Vec::len).sum();

    let mut missing = Vec::new();
    for (fr, description) in FR_DESCRIPTIONS {
        match by_fr.get(&fr) {
            Some(tests) if !tests.is_empty() => {
                // Visible with `cargo test -- --nocapture`; also read here
                // so the diagnostic `location` field is not dead code.
                let where_found: Vec<String> = tests
                    .iter()
                    .map(|t| format!("{} ({})", t.name, t.location))
                    .collect();
                println!("{fr}: {} test(s): {}", tests.len(), where_found.join(", "));
            }
            _ => missing.push(format!("{fr} ({description})")),
        }
    }

    assert!(
        missing.is_empty(),
        "FR1-FR10 traceability sweep found no fr<N>_* test for: {}\n\
         (scanned {total} fr<...>_* tests total across the workspace)",
        missing.join(", "),
    );

    // Sanity check on the sweep itself: if the string-scanning logic ever
    // regresses to matching nothing, `missing` above would be wrongly
    // non-empty and this arm is unreachable in practice — but guard the
    // inverse failure mode too (a scanner that matches everything and hides
    // real gaps) by requiring a plausible minimum count.
    assert!(
        total >= 10,
        "FR1-FR10 traceability sweep only found {total} fr<...>_* tests total, \
         fewer than one per v1+phase2 FR — the scan is almost certainly broken",
    );
}

/// C4's extension of the S13 sweep: every phase-2 FR (FR-K1.md, FR-C1.md
/// FR-C1-C7) has at least one `frk1<letter?>_*` / `frc<N><letter?>_*` test
/// compiled somewhere in the workspace, exactly as FR1-FR10 are checked
/// above.
#[test]
fn acceptance_phase2_frk1_and_frc1_through_frc7_each_have_a_named_test() {
    let by_fr = scan();

    let mut missing = Vec::new();
    for (fr, description) in FR_PHASE2_DESCRIPTIONS {
        match by_fr.get(&fr) {
            Some(tests) if !tests.is_empty() => {
                let where_found: Vec<String> = tests
                    .iter()
                    .map(|t| format!("{} ({})", t.name, t.location))
                    .collect();
                println!("{fr}: {} test(s): {}", tests.len(), where_found.join(", "));
            }
            _ => missing.push(format!("{fr} ({description})")),
        }
    }

    assert!(
        missing.is_empty(),
        "phase-2 traceability sweep found no frk<N>_*/frc<N>_* test for: {}",
        missing.join(", "),
    );
}

/// Regression test for the scanner itself: on a small in-memory sample it
/// must match real `fr<N>_...` / `frk<N>[letter]_...` / `frc<N>[letter]_...`
/// test names and must not match look-alikes (`from_str`, `fresh`,
/// `fr_helper`, `frobnicate`) or a bare `fn fr(...)`.
#[test]
fn acceptance_scanner_matches_only_true_fr_test_names() {
    let sample = r#"
        fn from_str(s: &str) -> Self { todo!() }
        fn fresh() -> Thing { todo!() }
        fn fr_helper() -> u32 { 0 }
        fn frobnicate() {}
        fn fr(x: u32) -> u32 { x }
        #[test]
        fn fr1_enrolls_successfully() {}
        #[test]
        fn fr10_reads_each_file_once() {}
        #[test]
        fn frk1_store_holds_keyed_ids() {}
        #[test]
        fn frk1b_confirmation_attack_matches_zero_ids() {}
        #[test]
        fn frc1_raw_codec_roundtrips() {}
        #[test]
        fn frc5a_reads_each_file_once() {}
        #[test]
        fn frc5b_matches_real_backup_bytes() {}
    "#;
    let mut got = extract_fr_fn_names(sample);
    got.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    assert_eq!(
        got,
        vec![
            ("fr1_enrolls_successfully".to_string(), FrId::V1(1)),
            ("fr10_reads_each_file_once".to_string(), FrId::V1(10)),
            ("frk1_store_holds_keyed_ids".to_string(), FrId::K(1)),
            (
                "frk1b_confirmation_attack_matches_zero_ids".to_string(),
                FrId::K(1)
            ),
            ("frc1_raw_codec_roundtrips".to_string(), FrId::C(1)),
            ("frc5a_reads_each_file_once".to_string(), FrId::C(5)),
            ("frc5b_matches_real_backup_bytes".to_string(), FrId::C(5)),
        ]
    );
}
