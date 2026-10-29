//! The CNS subject digest, reproduced from `cns.gate.subject_digest`.
//!
//! This is the digest an envelope's `subject_digest` field carries. It is the
//! same function every CNS producer already uses (Enforcer, GSA, CCC, CCCb,
//! DIT and the Sentinel witness), so a Python producer and this crate agree on
//! what "the digest of this content" means.
//!
//! The CNS rendering (`cns/gate.py::_canonical`) is not JSON. It is a
//! length-prefixed, type-tagged encoding, so no two distinct inputs render
//! alike:
//!
//! | value | rendering |
//! |---|---|
//! | `null` | `n:` |
//! | boolean | `b:1` or `b:0` |
//! | integer | `i:<decimal>:` |
//! | string | `s:<length in code points>:<text>` |
//! | object | `d:<n>:` then, for each key in code point order, the key as a string and its value |
//! | array | `l:<n>:` then each item |
//!
//! The digest is the SHA-256 of the UTF-8 bytes of that rendering, as 64
//! lowercase hex characters.
//!
//! Two deliberate narrowings from the Python function, both consistent with
//! the Trident's strict grammar. Floats are refused (the Python function
//! renders them as `f:<repr>:`), because the Trident admits integers only.
//! Integers outside plus or minus 2^53 - 1 are refused for the same reason.
//! Everything the Trident can carry renders byte-for-byte as Python renders
//! it; the shared vectors in `tests/cns_digest.rs` check that.
//!
//! This digest binds the payload to the verdict. It is separate from the
//! canonical JSON in [`crate::canonical`], which the MAC still covers: the MAC
//! authenticates the exact wire bytes, and the digest names the content in the
//! one format the rest of the stack uses.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonical::{to_hex, CanonicalError, Limits, MAX_SAFE_INTEGER};

/// `cns.gate.subject_digest(content)` for a payload the Trident can carry:
/// full SHA-256 hex, never truncated. The rendering is streamed into the
/// hash and never built as one string.
///
/// `limits.max_depth` bounds recursion. The Trident has already encoded the
/// payload under the same limits before it calls this, so the check is a
/// second line of defence for direct callers.
pub fn subject_digest(content: &Value, limits: &Limits) -> Result<String, CanonicalError> {
    let raw = subject_digest_raw(content, limits)?;
    Ok(to_hex(&raw))
}

/// As [`subject_digest`], but the 32 digest bytes.
pub fn subject_digest_raw(content: &Value, limits: &Limits) -> Result<[u8; 32], CanonicalError> {
    let mut hasher = Sha256::new();
    render(content, 1, limits.max_depth, &mut hasher)?;
    Ok(hasher.finalize().into())
}

fn put(h: &mut Sha256, s: &str) {
    h.update(s.as_bytes());
}

fn render(v: &Value, depth: usize, max_depth: usize, h: &mut Sha256) -> Result<(), CanonicalError> {
    match v {
        Value::Null => put(h, "n:"),
        Value::Bool(true) => put(h, "b:1"),
        Value::Bool(false) => put(h, "b:0"),
        Value::Number(n) => {
            let text = if let Some(i) = n.as_i64() {
                if i.unsigned_abs() > MAX_SAFE_INTEGER {
                    return Err(CanonicalError::IntegerOutOfRange);
                }
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                if u > MAX_SAFE_INTEGER {
                    return Err(CanonicalError::IntegerOutOfRange);
                }
                u.to_string()
            } else if n.as_f64().is_some_and(f64::is_finite) {
                return Err(CanonicalError::NonInteger);
            } else {
                return Err(CanonicalError::NonFinite);
            };
            put(h, "i:");
            put(h, &text);
            put(h, ":");
        }
        Value::String(s) => render_str(s, h),
        Value::Object(map) => {
            if depth > max_depth {
                return Err(CanonicalError::TooDeep);
            }
            put(h, "d:");
            put(h, &map.len().to_string());
            put(h, ":");
            // `str` ordering is byte order of the UTF-8, which is code point
            // order, which is Python's `sorted()` order for str keys. It is
            // not the UTF-16 order the canonical JSON uses above U+FFFF.
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_unstable_by(|a, b| a.0.cmp(b.0));
            for (k, item) in members {
                render_str(k, h);
                render(item, depth.saturating_add(1), max_depth, h)?;
            }
        }
        Value::Array(items) => {
            if depth > max_depth {
                return Err(CanonicalError::TooDeep);
            }
            put(h, "l:");
            put(h, &items.len().to_string());
            put(h, ":");
            for item in items {
                render(item, depth.saturating_add(1), max_depth, h)?;
            }
        }
    }
    Ok(())
}

fn render_str(s: &str, h: &mut Sha256) {
    // Python's len() counts code points, not bytes.
    put(h, "s:");
    put(h, &s.chars().count().to_string());
    put(h, ":");
    put(h, s);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn limits() -> Limits {
        Limits {
            max_bytes: 1 << 20,
            max_depth: 32,
            max_nodes: 10_000,
        }
    }

    #[test]
    fn empty_object_matches_the_cns_vector() {
        assert_eq!(
            subject_digest(&json!({}), &limits()).unwrap(),
            "c348e1722fbda6fbdd0ce8ec7831067eeff989c54b833673b8ebf6890883f012"
        );
    }

    #[test]
    fn floats_and_out_of_range_integers_are_refused() {
        assert_eq!(
            subject_digest(&json!(1.5), &limits()),
            Err(CanonicalError::NonInteger)
        );
        assert_eq!(
            subject_digest(&json!(9_007_199_254_740_992_i64), &limits()),
            Err(CanonicalError::IntegerOutOfRange)
        );
        assert_eq!(
            subject_digest(&json!(-9_007_199_254_740_992_i64), &limits()),
            Err(CanonicalError::IntegerOutOfRange)
        );
    }

    #[test]
    fn depth_is_bounded() {
        let mut v = json!(1);
        for _ in 0..40 {
            v = json!([v]);
        }
        assert_eq!(subject_digest(&v, &limits()), Err(CanonicalError::TooDeep));
    }
}
