//! Reproducible evaluation of the Trident `RuleInspector`.
//!
//! ```text
//! cargo run -p stack-trident --example rules_eval -- <corpus dir> [--held-out <file>] [--commit <hash>]
//! ```
//!
//! Reads every `*.jsonl` file in the corpus directory (sorted by name) and
//! prints one JSON document to stdout: the evidence configuration, the corpus
//! hashes, and per-family, per-file, split-phrase and per-Unicode-class
//! results with Wilson 95 percent intervals. The output is deterministic: the
//! same corpus and the same rules give the same bytes. `--commit` only echoes
//! the given text into the report.
//!
//! `--held-out <file>` also measures a sealed held-out file. Its SHA-256 is
//! compared with `heldout_manifest.json` next to the corpus directory; a
//! mismatch is reported and the exit code is 2. See `eval/PROCESS.md`.
//!
//! The inspector is a supplemental layer, not a defense. This tool measures
//! how many labelled examples it flags and says nothing about unseen text.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{json, Value};
use stack_trident::puzzle::eval::{
    config_json, evidence_inspector, parse_rows, report_rows, sha256_hex, Row,
};

struct Args {
    corpus: PathBuf,
    held_out: Option<PathBuf>,
    commit: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let mut corpus = None;
    let mut held_out = None;
    let mut commit = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--held-out" => held_out = Some(PathBuf::from(it.next().ok_or("--held-out needs a file")?)),
            "--commit" => commit = Some(it.next().ok_or("--commit needs a value")?),
            other if other.starts_with("--") => return Err(format!("unknown flag {other}")),
            other => {
                if corpus.replace(PathBuf::from(other)).is_some() {
                    return Err("only one corpus directory".to_owned());
                }
            }
        }
    }
    Ok(Args { corpus: corpus.ok_or("usage: rules_eval <corpus dir> [--held-out <file>] [--commit <hash>]")?, held_out, commit })
}

fn stem(path: &Path) -> String {
    path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

fn load_file(path: &Path) -> Result<(Vec<Row>, String, usize), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let text = String::from_utf8(bytes.clone()).map_err(|e| format!("{}: {e}", path.display()))?;
    let rows = parse_rows(&stem(path), &text).map_err(|e| e.to_string())?;
    let n = rows.len();
    Ok((rows, sha256_hex(&bytes), n))
}

fn run() -> Result<ExitCode, String> {
    let args = parse_args()?;
    let inspector = evidence_inspector().map_err(|e| e.to_string())?;

    let mut files: Vec<PathBuf> = std::fs::read_dir(&args.corpus)
        .map_err(|e| format!("{}: {e}", args.corpus.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("no *.jsonl files in {}", args.corpus.display()));
    }
    let mut rows = Vec::new();
    let mut file_info = serde_json::Map::new();
    let mut manifest_text = String::new();
    for f in &files {
        let (r, sha, n) = load_file(f)?;
        manifest_text.push_str(&format!("{} {}\n", stem(f), sha));
        file_info.insert(stem(f), json!({ "sha256": sha, "rows": n }));
        rows.extend(r);
    }
    let mut out = json!({
        "tool": "rules_eval",
        "schema": 1,
        "commit": args.commit,
        "config": config_json(),
        "corpus": { "files": Value::Object(file_info), "sha256": sha256_hex(manifest_text.as_bytes()) },
        "results": report_rows(&inspector, &rows),
    });
    let mut code = ExitCode::SUCCESS;
    if let Some(path) = &args.held_out {
        let (hrows, sha, n) = load_file(path)?;
        let manifest_path = args.corpus.parent().unwrap_or(Path::new(".")).join("heldout_manifest.json");
        let name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let expected = std::fs::read_to_string(&manifest_path)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|m| {
                m.get("files")?.as_array()?.iter().find_map(|e| {
                    (e.get("file")?.as_str()? == name).then(|| e.get("sha256")?.as_str().map(str::to_owned)).flatten()
                })
            });
        let matched = expected.as_ref().map(|e| *e == sha);
        if matched != Some(true) {
            code = ExitCode::from(2);
        }
        out["held_out"] = json!({
            "file": name,
            "sha256": sha,
            "rows": n,
            "manifest_sha256": expected,
            "manifest_match": matched,
            "results": report_rows(&inspector, &hrows),
        });
    }
    let text = serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?;
    println!("{text}");
    Ok(code)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("rules_eval: {e}");
            ExitCode::FAILURE
        }
    }
}
