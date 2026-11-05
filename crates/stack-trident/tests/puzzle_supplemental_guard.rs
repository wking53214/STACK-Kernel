//! Guard: the puzzle inspector is a supplemental layer, and nothing else in
//! the workspace treats its verdict as authorization.
//!
//! `Released` from the puzzle gate means "no known pattern was found and the
//! pieces are complete". It is not a permit. Authorization is decided by
//! `stack-authority`, `stack-admission` and `stack-receipt` from signed
//! capabilities and decisions, and suspicious content cannot override that.
//!
//! This is a grep-style test, like `stack-authority/tests/no_signing_in_src.rs`:
//! it fails when another crate names the puzzle module or the inspector types.
//! It cannot see a dependency through a path it does not scan; it is a tripwire,
//! not a proof.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

/// Names that would mean a crate uses the puzzle module or an inspector.
const FORBIDDEN: &[&str] = &["puzzle", "ruleinspector", "denylistinspector", "inspectinput", "puzzlegate"];

/// The crates that decide authorization. They must not use the puzzle module
/// in any file, comments included, so a later "just check Released" does not
/// begin as a comment.
const AUTHORIZATION_CRATES: &[&str] = &["stack-authority", "stack-admission", "stack-receipt"];

fn workspace_crates() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs" || e == "toml") {
            out.push(path);
        }
    }
}

fn hits_in(crate_dir: &Path) -> Vec<String> {
    let mut all = Vec::new();
    files(crate_dir, &mut all);
    let mut hits = Vec::new();
    for f in all {
        let text = std::fs::read_to_string(&f).unwrap().to_lowercase();
        for token in FORBIDDEN {
            if text.contains(token) {
                hits.push(format!("{} mentions {token:?}", f.display()));
            }
        }
    }
    hits
}

#[test]
fn the_authorization_crates_do_not_mention_the_puzzle_module_or_the_inspector() {
    for name in AUTHORIZATION_CRATES {
        let dir = workspace_crates().join(name);
        assert!(dir.join("Cargo.toml").is_file(), "{name} is expected in the workspace");
        let hits = hits_in(&dir);
        assert!(hits.is_empty(), "the puzzle inspector is supplemental, not authorization: {hits:?}");
    }
}

#[test]
fn no_other_crate_in_the_workspace_uses_the_puzzle_module() {
    let mut checked = 0;
    for entry in std::fs::read_dir(workspace_crates()).unwrap() {
        let dir = entry.unwrap().path();
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        if name == "stack-trident" || !dir.join("Cargo.toml").is_file() {
            continue;
        }
        checked += 1;
        let hits = hits_in(&dir);
        assert!(hits.is_empty(), "{name}: the puzzle module is not wired into any other crate: {hits:?}");
    }
    assert!(checked >= 3, "expected to scan the other workspace crates, scanned {checked}");
}

#[test]
fn the_authorization_crates_manifests_do_not_make_the_puzzle_module_a_dependency() {
    // stack-admission may depend on stack-trident for envelope verification.
    // What it must not do is use the puzzle module, which the source scan above
    // enforces. stack-authority and stack-receipt must not depend on
    // stack-trident at all.
    for name in ["stack-authority", "stack-receipt"] {
        let manifest = std::fs::read_to_string(workspace_crates().join(name).join("Cargo.toml")).unwrap();
        assert!(!manifest.contains("stack-trident"), "{name} must not depend on stack-trident");
    }
}

#[test]
fn the_scan_notices_a_mention() {
    // Mutation check: a crate that names the puzzle gate is reported.
    let dir = std::env::temp_dir().join(format!("trident-guard-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src").join("lib.rs"), "use stack_trident::puzzle::PuzzleGate;\n").unwrap();
    let hits = hits_in(&dir);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(hits.iter().any(|h| h.contains("puzzle")), "{hits:?}");
    assert!(hits.iter().any(|h| h.contains("puzzlegate")), "{hits:?}");
}
