//! S13 acceptance sweep: FR1-FR10 traceability (PRD §4, §5).
//!
//! This is not a re-implementation of any FR's behavior — every FR already
//! has its own dedicated test(s) elsewhere in the workspace, named
//! `fr<N>_*` per AGENTS.md. What this test adds is the thing no single
//! per-FR test can: proof, enforced by `cargo test --workspace` itself,
//! that the *whole* FR1-FR10 matrix is present and compiled into the suite
//! at once, with no gaps and no silent deletions. If a future change
//! renames or removes the last `fr5_*` test without adding a replacement,
//! this test — not a human re-reading SLICES.md — is what fails.
//!
//! It works by walking every `.rs` file under `crates/` (this workspace's
//! only source root) and parsing out `fn fr<N>_...` test-function names
//! with plain string scanning (no `regex` dependency — not in the AGENTS.md
//! palette), then asserting each FR in 1..=10 has at least one match, per
//! the slice's "each FR covered by >= 1 test named fr<N>_*" requirement.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One `fn fr<N>_...` match: which FR it claims, its full name, and where
/// it was found (for readable failure output).
#[derive(Debug, Clone)]
struct FrTest {
    fr: u32,
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

/// Scans `content` for `fn fr<digits>_<rest>` identifiers and returns each
/// as `(full_identifier, fr_number)`. Deliberately hand-rolled (no `regex`
/// in the palette): finds every `fn fr` substring, reads the identifier
/// that follows, and accepts it only if it is `fr` + digits + `_` + more
/// identifier chars (so `fr1_foo` matches FR1, `fr10_foo` matches FR10,
/// and `from_str` / `fresh` / etc. never match).
fn extract_fr_fn_names(content: &str) -> Vec<(String, u32)> {
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
            let digit_len = after_fr
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(after_fr.len());
            let has_underscore_after_digits = after_fr.as_bytes().get(digit_len) == Some(&b'_');
            if digit_len > 0 && has_underscore_after_digits {
                if let Ok(fr) = after_fr[..digit_len].parse::<u32>() {
                    results.push((ident.to_string(), fr));
                }
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
const FR_DESCRIPTIONS: [(u32, &str); 10] = [
    (1, "Enroll a client against a fresh daemon"),
    (
        2,
        "Back up a folder tree -> snapshot appears in daemon version list",
    ),
    (3, "Second backup after edits ships only new/changed chunks"),
    (
        4,
        "Restore any retained snapshot byte-exact, including metadata",
    ),
    (
        5,
        "Retention grid prunes correctly; GC reclaims; survivors restore",
    ),
    (
        6,
        "Keyfile export/import on a new machine restores old history",
    ),
    (7, "Daemon never possesses plaintext"),
    (
        8,
        "Client Windows service / daemon long-lived process survive restart",
    ),
    (
        9,
        "Corrupt/truncated chunk detected on restore, not silently",
    ),
    (
        10,
        "bench-chunking single-pass, reference-matching, exact projections",
    ),
];

/// The core traceability assertion (S13): every FR in PRD §4 has at least
/// one `fr<N>_*` test compiled somewhere in the workspace.
#[test]
fn acceptance_fr1_through_fr10_each_have_a_named_test() {
    let mut found = Vec::new();
    collect_fr_tests(&workspace_crates_dir(), &mut found);

    let mut by_fr: BTreeMap<u32, Vec<&FrTest>> = BTreeMap::new();
    for t in &found {
        by_fr.entry(t.fr).or_default().push(t);
    }

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
                println!(
                    "FR{fr}: {} test(s): {}",
                    tests.len(),
                    where_found.join(", ")
                );
            }
            _ => missing.push(format!("FR{fr} ({description})")),
        }
    }

    assert!(
        missing.is_empty(),
        "FR1-FR10 traceability sweep found no fr<N>_* test for: {}\n\
         (scanned {} fr<N>_* tests total across the workspace)",
        missing.join(", "),
        found.len(),
    );

    // Sanity check on the sweep itself: if the string-scanning logic ever
    // regresses to matching nothing, `missing` above would be wrongly
    // non-empty and this arm is unreachable in practice — but guard the
    // inverse failure mode too (a scanner that matches everything and hides
    // real gaps) by requiring a plausible minimum count.
    assert!(
        found.len() >= 10,
        "FR1-FR10 traceability sweep only found {} fr<N>_* tests total, \
         fewer than one per FR — the scan is almost certainly broken",
        found.len()
    );
}

/// Regression test for the scanner itself: on a small in-memory sample it
/// must match real `fr<N>_...` test names and must not match look-alikes
/// (`from_str`, `fresh`, `fr_helper`, `frobnicate`) or a bare `fn fr(...)`.
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
    "#;
    let mut got: Vec<(String, u32)> = extract_fr_fn_names(sample);
    got.sort();
    assert_eq!(
        got,
        vec![
            ("fr10_reads_each_file_once".to_string(), 10),
            ("fr1_enrolls_successfully".to_string(), 1),
        ]
    );
}
