//! The CNS subject digest, reproduced from `cns.gate.subject_digest`.
//!
//! A `governance_decision` row written after STACK Layer 5 carries
//! `subject_digest`: the CNS canonical digest of the content the decision
//! judged, its stored `input_data`. The witness recomputes it from the
//! content and a mismatch is `TRANSPLANTED`.
//!
//! The CNS rendering (`cns/gate.py::_canonical`) is not JSON. It is a
//! length-prefixed encoding, so no two distinct inputs can render alike:
//!
//! | value | rendering |
//! |---|---|
//! | `None` | `n:` |
//! | `bool` | `b:1` or `b:0` (checked before int, since bool is an int in Python) |
//! | `int` | `i:<decimal>:` |
//! | `float` | `f:<repr>:`, with `-0.0` normalised to `0.0`; NaN and the infinities are refused |
//! | `str` | `s:<length in code points>:<text>` |
//! | mapping | `d:<n>:` then, for each key in sorted order, the key and its value |
//! | sequence | `l:<n>:` then each item |
//!
//! The digest is the SHA-256 of the UTF-8 bytes of that rendering, as 64
//! lowercase hex characters.

use crate::canonical::Sha256Sink;
use crate::pyjson::{float_repr, Sink, Value};

/// The content cannot be bound to a verdict. Python raises `TypeError` here
/// and the witness reports the row as `TRANSPLANTED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CnsError {
    /// NaN or an infinity somewhere in the content.
    #[error("cannot bind a verdict to NaN or an infinity")]
    NonFiniteFloat,
}

fn render<S: Sink + ?Sized>(v: &Value, out: &mut S) -> Result<(), CnsError> {
    match v {
        Value::Null => out.put("n:"),
        Value::Bool(true) => out.put("b:1"),
        Value::Bool(false) => out.put("b:0"),
        Value::Int(i) => {
            out.put("i:");
            out.put(&i.to_string());
            out.put(":");
        }
        Value::Float(f) => {
            if !f.is_finite() {
                return Err(CnsError::NonFiniteFloat);
            }
            let f = if *f == 0.0 { 0.0 } else { *f };
            out.put("f:");
            out.put(&float_repr(f));
            out.put(":");
        }
        Value::Str(s) => render_str(s, out),
        Value::Object(map) => {
            // BTreeMap iterates in code point order, which is Python's
            // `sorted()` order for str keys. JSON keys are already strings,
            // so `str(k)` is the identity and cannot collide.
            out.put("d:");
            out.put(&map.len().to_string());
            out.put(":");
            for (k, item) in map {
                render_str(k, out);
                render(item, out)?;
            }
        }
        Value::Array(items) => {
            out.put("l:");
            out.put(&items.len().to_string());
            out.put(":");
            for item in items {
                render(item, out)?;
            }
        }
    }
    Ok(())
}

fn render_str<S: Sink + ?Sized>(s: &str, out: &mut S) {
    // Python's len() counts code points, not bytes.
    out.put("s:");
    out.put(&s.chars().count().to_string());
    out.put(":");
    out.put(s);
}

/// The CNS canonical rendering of `content` (`cns.gate._canonical`).
pub fn canonical_rendering(content: &Value) -> Result<String, CnsError> {
    let mut out = String::new();
    render(content, &mut out)?;
    Ok(out)
}

/// `cns.gate.subject_digest(content)`: full SHA-256 hex, never truncated.
/// The rendering is streamed into the hash, never built as one string.
pub fn subject_digest(content: &Value) -> Result<String, CnsError> {
    let mut sink = Sha256Sink::default();
    render(content, &mut sink)?;
    Ok(sink.hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pyjson::{parse, ParseLimits};

    #[test]
    fn rendering_is_length_prefixed_and_sorted() {
        let v = parse(
            r#"{"b": [1, 2.5, null, true], "a": "hé"}"#.as_bytes(),
            ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(
            canonical_rendering(&v).unwrap(),
            "d:2:s:1:as:2:h\u{e9}s:1:bl:4:i:1:f:2.5:n:b:1"
        );
    }

    #[test]
    fn negative_zero_digests_like_zero_and_nan_is_refused() {
        let neg = Value::Float(-0.0);
        let pos = Value::Float(0.0);
        assert_eq!(subject_digest(&neg), subject_digest(&pos));
        assert_eq!(subject_digest(&Value::Float(f64::NAN)), Err(CnsError::NonFiniteFloat));
    }
}
