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
use std::sync::atomic::{AtomicUsize, Ordering};

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
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("stack-crosscheck-{}-{n}", std::process::id()));
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

fn run(program: &str, leading: &[&str], args: &[&str], extra_env: &[(&str, &str)]) -> Outcome {
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
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
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

        let py = run(&python, &[tool.as_str()], &args, &[]);
        let rs = run(rust, &[], &args, &[]);
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


/// One hand-built input aimed at a place where the two programs are known or
/// suspected to differ.
struct Edge {
    name: &'static str,
    export_text: String,
    /// `None` leaves `--key-file` off the command line.
    key_file: Option<String>,
    env: Vec<(&'static str, String)>,
    /// `None` means the two programs must agree. `Some` lists the exact
    /// Python and Rust outcomes of a documented difference.
    expected: Option<(Outcome, Outcome, &'static str)>,
}

/// Byte range of the first `"key": "..."` string value, quotes included.
fn string_value_span(text: &str, key: &str) -> (usize, usize) {
    let pattern = format!("\"{key}\": \"");
    let at = text.find(&pattern).unwrap_or_else(|| panic!("no string value for {key}"));
    let open = at + pattern.len() - 1;
    let close = open + 1 + text[open + 1..].find('"').expect("unterminated string");
    (open, close + 1)
}

fn replace_first_value(text: &str, key: &str, raw_json: &str) -> String {
    let (a, b) = string_value_span(text, key);
    format!("{}{}{}", &text[..a], raw_json, &text[b..])
}

fn duplicate_first_pair(text: &str, key: &str) -> String {
    let (a, b) = string_value_span(text, key);
    let start = a - format!("\"{key}\": ").len();
    format!("{}{}, {}", &text[..start], &text[start..b], &text[start..])
}

fn edge_cases() -> Vec<Edge> {
    let base = load_cases()
        .into_iter()
        .find(|c| {
            c.recorded_python.verdict.as_deref() == Some("VERIFIED")
                && c.anchor.is_some()
                && c.key_file.lines().count() == 1
        })
        .expect("the manifest has no single-key VERIFIED case to build from");
    let text = base.export_text.clone();
    let one_key = base.key_file.clone();
    let edge = |name: &'static str, export_text: String, key_file: Option<String>| Edge {
        name,
        export_text,
        key_file,
        env: Vec::new(),
        expected: None,
    };
    let nested = |depth: usize| format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
    let mut padded_over_cap = one_key.clone();
    for i in 0..30_000 {
        padded_over_cap.push_str(&format!("padding-key-{i:06}-not-a-real-secret\n"));
    }
    let mut sixty_five_keys = one_key.clone();
    for i in 0..64 {
        sixty_five_keys.push_str(&format!("padding-key-{i:02}-not-a-real-secret\n"));
    }
    let mut env_only = edge("env_key_only", text.clone(), None);
    env_only.env.push(("ICEBERG_LEDGER_ATTESTATION_KEY", one_key.trim().to_owned()));
    let mut edges = vec![
        edge("control_verified", text.clone(), Some(one_key.clone())),
        edge(
            "duplicate_top_level_key",
            text.replacen('{', "{\"format\": \"sentinel_os.ledger_export.v1\", ", 1),
            Some(one_key.clone()),
        ),
        edge("duplicate_row_key", duplicate_first_pair(&text, "current_hash"), Some(one_key.clone())),
        edge(
            "lone_surrogate_escape",
            replace_first_value(&text, "current_hash", "\"\\ud800\""),
            Some(one_key.clone()),
        ),
        edge("nesting_300_deep", replace_first_value(&text, "current_hash", &nested(300)), Some(one_key.clone())),
        edge("nesting_5000_deep", replace_first_value(&text, "current_hash", &nested(5000)), Some(one_key.clone())),
        edge(
            "integer_5000_digits",
            replace_first_value(&text, "current_hash", &"1".repeat(5000)),
            Some(one_key.clone()),
        ),
        edge("nan_literal", replace_first_value(&text, "current_hash", "NaN"), Some(one_key.clone())),
        edge("utf8_bom_prefix", format!("\u{feff}{text}"), Some(one_key.clone())),
        edge("key_file_over_1_mib", text.clone(), Some(padded_over_cap)),
        edge("sixty_five_keys", text.clone(), Some(sixty_five_keys)),
        env_only,
    ];
    let outcome = |exit: i64, verdict: Option<&str>, row: Option<&str>| Outcome {
        exit,
        verdict: verdict.map(str::to_owned),
        row: row.map(str::to_owned),
        also: false,
    };
    // Where the two differ, Rust is the stricter program. The manual
    // (sentinel.md, "Stricter than Python") gives each reason.
    for e in &mut edges {
        e.expected = match e.name {
            "duplicate_top_level_key" | "duplicate_row_key" => Some((
                outcome(0, Some("VERIFIED"), None),
                outcome(1, None, None),
                "Python keeps the last of two equal keys; Rust refuses duplicate JSON keys as malformed",
            )),
            "nesting_300_deep" => Some((
                outcome(1, Some("TAMPERED"), Some("1")),
                outcome(1, None, None),
                "Python parses 300 levels and finds the hash wrong; Rust refuses nesting deeper than 256",
            )),
            "key_file_over_1_mib" => Some((
                outcome(0, Some("VERIFIED"), None),
                outcome(2, None, None),
                "Rust refuses a key file over max_key_file_bytes (1 MiB); Python reads any size",
            )),
            "sixty_five_keys" => Some((
                outcome(0, Some("VERIFIED"), None),
                outcome(2, None, None),
                "Rust refuses more than max_keys (64) keys; Python takes any number",
            )),
            "env_key_only" => Some((
                outcome(0, Some("VERIFIED"), None),
                outcome(2, None, None),
                "Python also reads ICEBERG_LEDGER_ATTESTATION_KEY; Rust takes keys only from --key-file",
            )),
            _ => None,
        };
    }
    edges
}

/// Twelve hand-built inputs that probe where the two parsers and loaders could
/// differ: duplicate keys, deep nesting, huge integers, lone surrogates, NaN, a
/// byte-order mark, key-file size and count, and keys given only by the
/// environment. Six must agree with each other. On the other six the test pins
/// exactly how they differ, so a change to either program shows up here.
#[test]
#[ignore = "needs SENTINEL_OS_DIR (a sentinel_os checkout) and PYTHON (an interpreter with its dependencies); run with --ignored"]
fn live_edge_cases_differ_only_as_documented() {
    let os_dir = std::env::var("SENTINEL_OS_DIR")
        .expect("set SENTINEL_OS_DIR to a sentinel_os checkout (see the header of this file)");
    let python = std::env::var("PYTHON").unwrap_or_else(|_| "python3".to_owned());
    let tool = Path::new(&os_dir).join("tools").join("verify_receipts.py");
    assert!(tool.is_file(), "{} does not exist; is SENTINEL_OS_DIR a sentinel_os checkout?", tool.display());
    let tool = tool.to_str().unwrap().to_owned();
    let rust = env!("CARGO_BIN_EXE_stack-sentinel-verify");

    let base = load_cases()
        .into_iter()
        .find(|c| {
            c.recorded_python.verdict.as_deref() == Some("VERIFIED")
                && c.anchor.is_some()
                && c.key_file.lines().count() == 1
        })
        .expect("the manifest has no single-key VERIFIED case to build from");
    let scratch = Scratch::new();
    let export = scratch.path("export.json");
    let anchor = scratch.path("ledger.anchor");
    let keys = scratch.path("keys.txt");
    fs::write(&anchor, base.anchor.as_deref().unwrap()).unwrap();
    let fps = base.fingerprints.join(",");

    let mut problems = Vec::new();
    for e in edge_cases() {
        fs::write(&export, &e.export_text).unwrap();
        let mut args: Vec<String> = vec![
            "--export".into(),
            export.to_str().unwrap().into(),
            "--anchor".into(),
            anchor.to_str().unwrap().into(),
            "--trusted-fingerprints".into(),
            fps.clone(),
        ];
        if let Some(k) = &e.key_file {
            write_private(&keys, k);
            args.push("--key-file".into());
            args.push(keys.to_str().unwrap().into());
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let env: Vec<(&str, &str)> = e.env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let py = run(&python, &[tool.as_str()], &args, &env);
        let rs = run(rust, &[], &args, &env);
        if e.name == "control_verified" && (py.verdict.as_deref() != Some("VERIFIED") || rs.verdict.as_deref() != Some("VERIFIED")) {
            problems.push(format!("control_verified is not VERIFIED in both: python={py:?} rust={rs:?}"));
        }
        match &e.expected {
            None if py != rs => problems.push(format!("{}: python={:?} rust={:?}", e.name, py, rs)),
            None => {}
            Some((ep, er, why)) if py != *ep || rs != *er => problems.push(format!(
                "{}: listed as `{why}` but now python={py:?} rust={rs:?}, expected python={ep:?} rust={er:?}",
                e.name
            )),
            Some(_) => {}
        }
    }
    assert!(problems.is_empty(), "{} unexplained edge-case difference(s):\n{}", problems.len(), problems.join("\n"));
}
