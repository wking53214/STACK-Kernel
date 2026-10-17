//! `stack-sentinel-verify`: the Rust counterpart of
//! `sentinel_os/tools/verify_receipts.py`, with the same flags, the same
//! output lines and the same exit codes (0 only on VERIFIED, 1 on a finding
//! or an unreadable export, 2 when no trusted key material is held or the
//! arguments are wrong).
//!
//! ```text
//! stack-sentinel-verify --export ledger.json --anchor ledger.anchor \
//!     --trusted-fingerprints 0123456789abcdef --key-file keys.txt
//! ```
//!
//! Unlike the Python tool it does not read `ICEBERG_LEDGER_ATTESTATION_KEY*`
//! from the environment: keys come only from `--key-file`.
//!
//! Arguments are read as OS strings, so an argument that is not valid
//! Unicode never panics. File paths may be any bytes the OS allows; a flag
//! name or a `--trusted-fingerprints` value that is not UTF-8 is bad
//! arguments (exit 2), and the message gives its length, never its bytes.

use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use stack_sentinel::{parse_key_file, KeySet, Verifier, VerifierConfig, VerifyError};

const USAGE: &str = "usage: stack-sentinel-verify --export EXPORT --anchor ANCHOR \
--trusted-fingerprints TRUSTED_FINGERPRINTS [--key-file KEY_FILE]";

struct Args {
    export: PathBuf,
    anchor: PathBuf,
    fingerprints: String,
    key_file: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut export: Option<OsString> = None;
    let mut anchor: Option<OsString> = None;
    let mut fingerprints: Option<OsString> = None;
    let mut key_file: Option<OsString> = None;
    let mut it = std::env::args_os().skip(1);
    while let Some(flag) = it.next() {
        let slot = match flag.to_str() {
            Some("--export") => &mut export,
            Some("--anchor") => &mut anchor,
            Some("--trusted-fingerprints") => &mut fingerprints,
            Some("--key-file") => &mut key_file,
            Some("-h" | "--help") => return Err(String::new()),
            _ => return Err(format!("unrecognized argument: {} bytes", flag.len())),
        };
        *slot = Some(it.next().ok_or_else(|| "a flag is missing its value".to_owned())?);
    }
    match (export, anchor, fingerprints) {
        (Some(export), Some(anchor), Some(fingerprints)) => {
            let fingerprints = fingerprints.into_string().map_err(|raw| {
                format!("--trusted-fingerprints is not valid UTF-8: {} bytes", raw.len())
            })?;
            Ok(Args {
                export: PathBuf::from(export),
                anchor: PathBuf::from(anchor),
                fingerprints,
                key_file: key_file.map(PathBuf::from),
            })
        }
        _ => Err("--export, --anchor and --trusted-fingerprints are required".to_owned()),
    }
}

/// Read at most `max + 1` bytes, so an oversized file is detected without
/// reading all of it.
fn read_capped(path: &Path, max: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    File::open(path)?.take(max as u64 + 1).read_to_end(&mut buf)?;
    Ok(buf)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("{msg}");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let config = VerifierConfig::default();

    let held = match &args.key_file {
        None => Vec::new(),
        Some(path) => {
            let parsed = read_capped(path, config.max_key_file_bytes)
                .map_err(|e| format!("key file cannot be read: {}", e.kind()))
                .and_then(|b| {
                    parse_key_file(&b, config.max_key_file_bytes, config.max_keys).map_err(|e| e.to_string())
                });
            match parsed {
                Ok(k) => k,
                Err(msg) => {
                    eprintln!("{msg}");
                    return ExitCode::from(2);
                }
            }
        }
    };
    let fps: Vec<&str> = args.fingerprints.split(',').collect();
    let keys = KeySet::from_trusted_fingerprints(held, &fps);
    let verifier = match Verifier::new(config, keys) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "no trusted key material: none of the held keys matches --trusted-fingerprints \
                 (supply --key-file); {e}"
            );
            return ExitCode::from(2);
        }
    };

    let export = match read_capped(&args.export, config.max_export_bytes) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("export cannot be read: {}", e.kind());
            return ExitCode::from(1);
        }
    };
    // An anchor that cannot be read is a finding (TRUNCATED), never a pass.
    let anchor = read_capped(&args.anchor, config.max_anchor_bytes).ok();

    match verifier.verify_export(&export, anchor.as_deref()) {
        Ok(report) => {
            println!("{}", report.render());
            if report.finding.is_none() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(VerifyError::NoTrustedKeyMaterial) => ExitCode::from(2),
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
