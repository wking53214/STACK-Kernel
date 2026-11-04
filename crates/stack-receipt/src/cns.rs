//! The CNS canonical rendering and subject digest (`cns.gate.subject_digest`)
//! over this crate's own value type, for recomputing a decision root and,
//! when the auditor supplies the content, a subject digest.
//!
//! The rendering is CNS's length-prefixed text encoding, not JSON:
//!
//! | value | rendering |
//! |---|---|
//! | null | `n:` |
//! | boolean | `b:1` or `b:0` |
//! | integer | `i:<decimal>:` |
//! | text | `s:<code points>:<text>` |
//! | list | `l:<n>:` then each item |
//! | map | `d:<n>:` then, for each key in code point order, the key as text and its value |
//!
//! The digest is SHA-256 of the UTF-8 bytes of the rendering.
//!
//! Domain: this type carries no float and integers within `i64`. A CNS
//! decision root is a map of text, lists of text and maps of text, so
//! the whole root domain is covered; a subject supplied by an auditor
//! that needs floats or wider integers is outside this crate and its
//! digest cannot be recomputed here (the verifier then reports the
//! subject as not recomputed, never as matching). Every vector in the
//! shared CNS answer key that lies inside this domain is reproduced byte
//! for byte (`tests/cns_vectors.rs`).

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use stack_authority::Digest32;

/// A CNS content value inside this crate's domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CnsValue {
    /// Python `None`.
    Null,
    /// Python `bool`, distinct from the integers 0 and 1.
    Bool(bool),
    /// Python `int` within `i64`.
    Int(i64),
    /// Python `str`.
    Str(String),
    /// Python `list`.
    List(Vec<CnsValue>),
    /// Python `dict` with text keys; iterates in code point order, which
    /// is `sorted()` order for `str` keys.
    Map(BTreeMap<String, CnsValue>),
}

impl CnsValue {
    /// A text value.
    pub fn text(s: &str) -> Self {
        Self::Str(s.to_owned())
    }

    /// A list of text values.
    pub fn texts<'a>(items: impl IntoIterator<Item = &'a str>) -> Self {
        Self::List(items.into_iter().map(Self::text).collect())
    }
}

/// Where a rendering goes: into a string, or into the hash.
trait Sink {
    fn put(&mut self, s: &str);
}

impl Sink for String {
    fn put(&mut self, s: &str) {
        self.push_str(s);
    }
}

impl Sink for Sha256 {
    fn put(&mut self, s: &str) {
        self.update(s.as_bytes());
    }
}

fn render<S: Sink>(v: &CnsValue, out: &mut S) {
    match v {
        CnsValue::Null => out.put("n:"),
        CnsValue::Bool(true) => out.put("b:1"),
        CnsValue::Bool(false) => out.put("b:0"),
        CnsValue::Int(i) => {
            out.put("i:");
            out.put(&i.to_string());
            out.put(":");
        }
        CnsValue::Str(s) => render_str(s, out),
        CnsValue::Map(map) => {
            out.put("d:");
            out.put(&map.len().to_string());
            out.put(":");
            for (k, item) in map {
                render_str(k, out);
                render(item, out);
            }
        }
        CnsValue::List(items) => {
            out.put("l:");
            out.put(&items.len().to_string());
            out.put(":");
            for item in items {
                render(item, out);
            }
        }
    }
}

fn render_str<S: Sink>(s: &str, out: &mut S) {
    // Python's len() counts code points, not bytes.
    out.put("s:");
    out.put(&s.chars().count().to_string());
    out.put(":");
    out.put(s);
}

/// The CNS canonical rendering of `content` (`cns.gate._canonical`).
pub fn canonical_rendering(content: &CnsValue) -> String {
    let mut out = String::new();
    render(content, &mut out);
    out
}

/// `cns.gate.subject_digest(content)`: full SHA-256, never truncated. The
/// rendering is streamed into the hash and never built as one string.
pub fn subject_digest(content: &CnsValue) -> Digest32 {
    let mut h = Sha256::new();
    render(content, &mut h);
    Digest32::from_bytes(h.finalize().into())
}
