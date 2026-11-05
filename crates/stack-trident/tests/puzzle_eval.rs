//! The evaluation harness reproduces the recorded numbers exactly, so a
//! change to the rules or to a corpus file cannot move a number silently.
//!
//! The sealed held-out file is never run here: running it against changed
//! rules would spend it. This test only checks its hash against the
//! committed manifest. See `eval/PROCESS.md`.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use serde_json::Value;
use stack_trident::puzzle::eval::{
    base64_decode, evidence_inspector, parse_rows, report_rows, sha256_hex, wilson95, Row,
};

fn eval_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("eval")
}

fn corpus_rows() -> Vec<Row> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(eval_dir().join("corpus"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    files.sort();
    let mut rows = Vec::new();
    for f in files {
        let stem = f.file_stem().unwrap().to_string_lossy().into_owned();
        rows.extend(parse_rows(&stem, &std::fs::read_to_string(&f).unwrap()).unwrap());
    }
    rows
}

type Counts = (u64, u64, u64, u64);

fn tally(report: &Value, set: &str) -> Counts {
    let t = &report["sets"][set];
    let n = |k: &str| t[k].as_u64().unwrap();
    (n("tp"), n("fn"), n("fp"), n("tn"))
}

/// Per corpus file: (true positives, false negatives, false positives, true negatives).
/// These are the rules as they stood before any change (dev 18/18, held-out
/// 12/14, red-team 18/18, paraphrases 0/8, encodings 0/6, benign 6/49), plus
/// the files added with the harness.
const EXPECTED: &[(&str, Counts)] = &[
    ("benign", (0, 0, 6, 43)),
    ("dev", (18, 0, 0, 0)),
    ("encodings", (0, 6, 0, 0)),
    ("heldout_v1", (12, 2, 0, 0)),
    ("paraphrases", (0, 8, 0, 0)),
    ("race02_evasions", (1, 15, 1, 0)),
    ("red_team", (18, 0, 0, 0)),
    ("split", (3, 1, 0, 0)),
];

#[test]
fn the_harness_reproduces_the_recorded_numbers_exactly() {
    let rows = corpus_rows();
    let report = report_rows(&evidence_inspector().unwrap(), &rows);
    let sets = report["sets"].as_object().unwrap();
    assert_eq!(sets.len(), EXPECTED.len(), "a corpus file was added or removed: update EXPECTED and say why");
    for (set, want) in EXPECTED {
        assert_eq!(tally(&report, set), *want, "{set}");
    }
}

#[test]
fn the_report_is_deterministic() {
    let rows = corpus_rows();
    let i = evidence_inspector().unwrap();
    let a = serde_json::to_string(&report_rows(&i, &rows)).unwrap();
    let b = serde_json::to_string(&report_rows(&i, &rows)).unwrap();
    assert_eq!(a, b);
}

#[test]
fn every_row_is_well_formed_and_every_required_family_is_present() {
    let rows = corpus_rows();
    let mut ids = std::collections::BTreeSet::new();
    for r in &rows {
        assert!(ids.insert((r.set.clone(), r.id.clone())), "duplicate id {}/{}", r.set, r.id);
    }
    let families: std::collections::BTreeSet<&str> = rows.iter().map(|r| r.family.as_str()).collect();
    for f in [
        "plain_injection",
        "split_phrase",
        "invisible_chars",
        "homoglyph",
        "encoding",
        "paraphrase",
        "harmful_build",
        "benign_general",
        "benign_near_miss",
    ] {
        assert!(families.contains(f), "family {f} missing from the corpus");
    }
}

#[test]
fn the_sealed_held_out_file_matches_its_committed_manifest() {
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(eval_dir().join("heldout_manifest.json")).unwrap()).unwrap();
    let files = manifest["files"].as_array().unwrap();
    assert!(!files.is_empty());
    for entry in files {
        let path = eval_dir().join(entry["path"].as_str().unwrap());
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(sha256_hex(&bytes), entry["sha256"].as_str().unwrap(), "{}", path.display());
    }
}

#[test]
fn small_helpers_are_right() {
    assert_eq!(base64_decode("SGk=").unwrap(), b"Hi");
    assert_eq!(base64_decode("SGVsbG8=").unwrap(), b"Hello");
    assert!(base64_decode("SGk").is_none());
    assert!(base64_decode("S!k=").is_none());
    assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert!(wilson95(0, 0).is_none());
    let (lo, hi) = wilson95(5, 10).unwrap();
    assert!((lo - 0.2366).abs() < 1e-3 && (hi - 0.7634).abs() < 1e-3, "{lo} {hi}");
    let (lo, hi) = wilson95(0, 10).unwrap();
    assert!(lo == 0.0 && (hi - 0.2775).abs() < 1e-3);
}
