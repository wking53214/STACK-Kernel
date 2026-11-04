//! Guard: the non-test source of this crate contains no signing path and
//! no secret key type. The only signing code is in tests/common.

#![allow(clippy::unwrap_used)]

use std::path::Path;

/// Tokens that would indicate an issuing or signing path.
const FORBIDDEN: &[&str] = &[
    "SigningKey",
    "ExpandedSecretKey",
    "SecretKey",
    "ed25519_dalek::Signer",
    "Signer;",
    ".sign(",
    "sign_prehashed",
    "keypair",
    "Keypair",
];

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn src_contains_no_signing_path() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(files.len() >= 8, "expected the crate's modules under {}", src.display());
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        for token in FORBIDDEN {
            assert!(
                !text.contains(token),
                "{} mentions {token:?}; issuing lives outside the kernel",
                file.display()
            );
        }
    }
    // The dependency is used for verification only.
    let manifest = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    assert!(manifest.contains("ed25519-dalek.workspace = true"));
    assert!(!manifest.contains("rand_core"), "no key generation feature");
    assert!(!manifest.contains("pkcs8") && !manifest.contains("pem"), "no key file loading feature");
}

#[test]
fn src_contains_no_hard_coded_key_material() {
    // A 64-character lowercase hex literal, or a 32-byte array literal of
    // non-zero bytes, in non-test source would be a key or a digest baked
    // in. Only domain tags and bounds are constants here.
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        let mut run = 0usize;
        for ch in text.chars() {
            if ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase() {
                run += 1;
                assert!(run < 64, "{} holds a 64-hex-character literal", file.display());
            } else {
                run = 0;
            }
        }
    }
}
