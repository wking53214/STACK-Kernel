//! Live cross-check: the real Python verifier against the compiled Rust binary.
//!
//! `differential.rs` replays what Python printed once, by hand, and feeds it
//! to the Rust *library* in its Python-compatible mode. This test closes the
//! two gaps that leaves. It runs both programs as separate processes, on the
//! same files, every time, so a change to either one shows up as a difference
//! here. And it runs the shipped command, with its default limits, not a
//! library configuration.
//!
//! For each recorded case it rebuilds the exact export Python checked (the
//! SHA-256 of the rebuilt text is asserted), writes the export, anchor and key
//! file once, then runs:
//!
//! * `$PYTHON $SENTINEL_OS_DIR/tools/verify_receipts.py ...`
//! * the `stack-sentinel-verify` binary Cargo built for this test, same flags.
//!
//! and compares the four things a caller can rely on: the exit code, the
//! verdict word, the failing row, and whether an `also:` line was printed.
//! The detail text is never compared (the two programs word it differently on
//! purpose).
//!
//! Two kinds of failure, kept apart so the cause is obvious:
//!
//! * **Python drift**: the live Python result no longer equals what
//!   `manifest.json` recorded. Either sentinel_os changed, or the checkout
//!   under test is not the one the manifest was made from.
//! * **Disagreement**: Python and Rust differ on a case that is not in
//!   [`KNOWN_DIFFERENCES`]. A listed difference that stops happening also
//!   fails, so the list cannot go stale.
//!
//! The test is `#[ignore]`d because it needs two things Cargo cannot supply:
//! a sentinel_os checkout and a Python with its dependencies. Run it with:
//!
//! ```text
//! SENTINEL_OS_DIR=/path/to/sentinel_os PYTHON=/path/to/venv/bin/python \
//!     cargo test -p stack-sentinel --test crosscheck -- --ignored
//! ```
//!
//! Every key written here is a TEST FIXTURE from the manifest, never a real
//! secret. The key file is created owner-only and the scratch directory is
//! removed afterwards.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use stack_sentinel::canonical::sha256_hex;
use stack_sentinel::pyjson::{dumps, Object, Separators, Value};

/// What a caller can rely on from one run of either verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Outcome {
    exit: i64,
    /// The first word printed, or `None` when nothing was printed (usage
    /// errors, refusals, a Python traceback).
    verdict: Option<String>,
    /// The `row=` token of the first line, without the prefix.
    row: Option<String>,
    /// Whether a second `  also: ` line was printed.
    also: bool,
}

impl Outcome {
    fn from_output(exit: i64, stdout: &str) -> Self {
        let lines: Vec<&str> = stdout.lines().collect();
        let first = lines.first().copied().unwrap_or("");
        let mut words = first.split(' ');
        let verdict = words.next().filter(|w| !w.is_empty()).map(str::to_owned);
        let row = words.next().and_then(|w| w.strip_prefix("row=")).map(str::to_owned);
        let also = lines.iter().any(|l| l.starts_with("  also: "));
        Self { exit, verdict, row, also }
    }
}

/// One recorded case, rebuilt.
struct Case {
    name: String,
    export_text: String,
    anchor: Option<String>,
    key_file: String,
    fingerprints: Vec<String>,
    recorded_python: Outcome,
}

/// A difference between the two verifiers that is understood and accepted.
/// The test requires the case to differ in exactly this way.
struct KnownDifference {
    /// The case name, or a prefix of it ending in `*`.
    case: &'static str,
    python: Outcome,
    rust: Outcome,
    why: &'static str,
}

fn obj(v: &Value) -> &Object {
    v.as_object().unwrap()
}

fn int(v: &Value) -> i64 {
    match v {
        Value::Int(i) => i.to_i64().unwrap(),
        other => panic!("expected an integer, found {other:?}"),
    }
}

/// Rebuild every case in `manifest.json` exactly as `differential.rs` does.
fn load_cases() -> Vec<Case> {
    let manifest = common::load("differential/manifest.json");
    let shipped = common::columns("differential/base_post_receipts.json");
    let mut bases: BTreeMap<String, Vec<Object>> = BTreeMap::new();
    for (name, path) in obj(&manifest["bases"]) {
        let rel = format!("differential/{}", path.as_str().unwrap());
        bases.insert(name.clone(), common::base_rows(&rel));
    }
    let Value::Array(cases) = &manifest["cases"] else {
        panic!("manifest has no cases")
    };
    let mut out = Vec::new();
    for c in cases {
        let c = obj(c);
        let name = c["name"].as_str().unwrap().to_owned();
        let base = &bases[c["base"].as_str().unwrap()];
        let Value::Array(entries) = &c["rows"] else {
            panic!("{name}: rows is not a list")
        };
        let mut rows = Vec::new();
        for e in entries {
            let e = obj(e);
            let mut row = base[usize::try_from(int(&e["base"])).unwrap()].clone();
            if let Some(Value::Object(sets)) = e.get("set") {
                for (k, v) in sets {
                    row.insert(k.clone(), v.clone());
                }
            }
            if let Some(Value::Array(dels)) = e.get("del") {
                for d in dels {
                    row.remove(d.as_str().unwrap());
                }
            }
            rows.push(row);
        }
        let export_text = dumps(&common::export_value(&shipped, &rows), Separators::Python);
        assert_eq!(
            sha256_hex(export_text.as_bytes()),
            c["export_sha256"].as_str().unwrap(),
            "{name}: rebuilt export differs from the one Python checked, so this test would not be \
             comparing the programs on the input the manifest describes"
        );
        let Value::Array(fps) = &c["fingerprints"] else {
            panic!("{name}: fingerprints is not a list")
        };
        let py = obj(&c["python"]);
        out.push(Case {
            name,
            export_text,
            anchor: c["anchor"].as_str().map(str::to_owned),
            key_file: c["key_file"].as_str().unwrap().to_owned(),
            fingerprints: fps.iter().map(|f| f.as_str().unwrap().to_owned()).collect(),
            recorded_python: Outcome {
                exit: int(&py["exit"]),
                verdict: py["verdict"].as_str().map(str::to_owned),
                row: py["row"].as_str().map(str::to_owned),
                also: py["also"] == Value::Bool(true),
            },
        });
    }
    out
}

/// A scratch directory that removes itself, including when an assertion fails.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("stack-crosscheck-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_private(path: &Path, text: &str) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(text.as_bytes()).unwrap();
}

fn run(program: &str, leading: &[&str], args: &[&str]) -> Outcome {
    let mut cmd = Command::new(program);
    cmd.args(leading).args(args);
    // The same environment for both programs, with the ledger's own key
    // variables removed so neither can pick a key up from the host.
    for (k, _) in std::env::vars() {
        if k.starts_with("ICEBERG_LEDGER_ATTESTATION") {
            cmd.env_remove(k);
        }
    }
    cmd.env("PYTHONDONTWRITEBYTECODE", "1");
    let out = cmd.output().unwrap_or_else(|e| panic!("could not start {program}: {e}"));
    let code = i64::from(out.status.code().unwrap_or(-1));
    Outcome::from_output(code, &String::from_utf8_lossy(&out.stdout))
}

/// Differences that are understood. Each entry came from a live run and was
/// checked against the manual and the source before it was written here.
///
/// The manual (`manual/sections/sentinel.md`, the table of limits) lists three
/// deliberate departures from the Python tool: retired-key signatures,
/// retired-key anchors and zero-entry anchors. Only the third can be reached
/// through the command line: the CLI takes keys from `--key-file` alone and
/// treats them all as current, so a key can never be "retired" there.
fn known_differences() -> Vec<KnownDifference> {
    let python_accepts = Outcome { exit: 0, verdict: Some("VERIFIED".to_owned()), row: None, also: false };
    let rust_refuses = Outcome { exit: 1, verdict: Some("TRUNCATED".to_owned()), row: Some("-".to_owned()), also: false };
    vec![KnownDifference {
        // Two cases carry this name, one per base export.
        case: "anchor_zero_entries",
        python: python_accepts,
        rust: rust_refuses,
        why: "min_anchor_entries defaults to 1: an anchor that seals no rows makes no claim about a \
              non-empty chain, so Rust reports TRUNCATED where Python reports VERIFIED \
              (a deliberate departure, see the manual)",
    }]
}

fn matches_case(pattern: &str, name: &str) -> bool {
    pattern.strip_suffix('*').map_or(pattern == name, |prefix| name.starts_with(prefix))
}

#[test]
#[ignore = "needs SENTINEL_OS_DIR (a sentinel_os checkout) and PYTHON (an interpreter with its dependencies); run with --ignored"]
fn live_python_and_rust_binaries_agree_on_every_case() {
    let os_dir = std::env::var("SENTINEL_OS_DIR")
        .expect("set SENTINEL_OS_DIR to a sentinel_os checkout (see the header of this file)");
    let python = std::env::var("PYTHON").unwrap_or_else(|_| "python3".to_owned());
    let tool = Path::new(&os_dir).join("tools").join("verify_receipts.py");
    assert!(tool.is_file(), "{} does not exist; is SENTINEL_OS_DIR a sentinel_os checkout?", tool.display());
    let tool = tool.to_str().unwrap().to_owned();
    let rust = env!("CARGO_BIN_EXE_stack-sentinel-verify");

    let cases = load_cases();
    assert!(cases.len() >= 200, "expected at least 200 cases, found {}", cases.len());

    let scratch = Scratch::new();
    let export = scratch.path("export.json");
    let anchor = scratch.path("ledger.anchor");
    let keys = scratch.path("keys.txt");
    let (export_s, anchor_s, keys_s) = (
        export.to_str().unwrap().to_owned(),
        anchor.to_str().unwrap().to_owned(),
        keys.to_str().unwrap().to_owned(),
    );

    let known = known_differences();
    let mut drift = Vec::new();
    let mut disagreements = Vec::new();
    let mut seen_known: Vec<bool> = vec![false; known.len()];
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();

    for c in &cases {
        fs::write(&export, &c.export_text).unwrap();
        let _ = fs::remove_file(&anchor);
        if let Some(a) = &c.anchor {
            fs::write(&anchor, a).unwrap();
        }
        write_private(&keys, &c.key_file);
        let fps = c.fingerprints.join(",");
        let args = [
            "--export",
            export_s.as_str(),
            "--anchor",
            anchor_s.as_str(),
            "--trusted-fingerprints",
            fps.as_str(),
            "--key-file",
            keys_s.as_str(),
        ];

        let py = run(&python, &[tool.as_str()], &args);
        let rs = run(rust, &[], &args);
        *tally
            .entry(py.verdict.clone().unwrap_or_else(|| format!("exit {}", py.exit)))
            .or_default() += 1;

        if py != c.recorded_python {
            drift.push(format!("{}: recorded {:?}, live {:?}", c.name, c.recorded_python, py));
        }
        let listed = known.iter().position(|k| matches_case(k.case, &c.name));
        match listed {
            Some(i) => {
                seen_known[i] = true;
                if py != known[i].python || rs != known[i].rust {
                    disagreements.push(format!(
                        "{}: listed as `{}` but now python={:?} rust={:?}, expected python={:?} rust={:?}",
                        c.name, known[i].why, py, rs, known[i].python, known[i].rust
                    ));
                }
            }
            None if py != rs => disagreements.push(format!("{}: python={:?} rust={:?}", c.name, py, rs)),
            None => {}
        }
    }
    for (i, k) in known.iter().enumerate() {
        if !seen_known[i] {
            disagreements.push(format!("known difference `{}` ({}) matched no case; remove or fix it", k.case, k.why));
        }
    }

    assert!(
        drift.is_empty(),
        "Python drift: {} case(s) no longer print what the manifest recorded:\n{}",
        drift.len(),
        drift.join("\n")
    );
    assert!(
        disagreements.is_empty(),
        "{} unexplained disagreement(s) between the Python tool and the Rust binary:\n{}",
        disagreements.len(),
        disagreements.join("\n")
    );
    // Every verdict word and the refusal must have been exercised, or the
    // agreement above says nothing about it.
    for word in ["VERIFIED", "TAMPERED", "TRANSPLANTED", "SEED_FORGED", "TRUNCATED", "UNATTESTED", "exit 2"] {
        assert!(tally.contains_key(word), "no case produced {word}: {tally:?}");
    }
}
