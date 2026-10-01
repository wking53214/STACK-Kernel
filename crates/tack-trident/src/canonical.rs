//! Strict JSON parsing and canonical JSON encoding, both bounded.
//!
//! # The canonical encoding, precisely
//!
//! A value is encoded as follows. The result is UTF-8 bytes.
//!
//! * `null`, `true`, `false`: those literals.
//! * Numbers: integers only, in the range `-(2^53 - 1) ..= 2^53 - 1` (the
//!   I-JSON "safe integer" range, RFC 7493). Written in base 10 with no
//!   sign for non-negative values, a single `-` for negative ones, no
//!   leading zeros, no fraction, no exponent. `-0` is written as `0`.
//!   Floats, NaN and the infinities are refused, not rounded.
//! * Strings: a `"`, then each character of the string, then a `"`.
//!   `"` becomes `\"`, `\` becomes `\\`, U+0008 `\b`, U+000C `\f`,
//!   U+000A `\n`, U+000D `\r`, U+0009 `\t`, any other character below
//!   U+0020 becomes `\u00xx` with lowercase hex. Every other character,
//!   including `/`, U+007F and all non-ASCII, is written as raw UTF-8.
//! * Arrays: `[`, the elements separated by `,`, `]`. No whitespace.
//! * Objects: `{`, the members sorted by key, each written as the key
//!   string, `:`, the value, separated by `,`, then `}`. No whitespace.
//!   Keys are sorted by comparing their UTF-16 code units, which is the
//!   RFC 8785 rule. Duplicate keys are refused at parse time.
//!
//! For the integer-only subset this is byte-for-byte RFC 8785 (JSON
//! Canonicalization Scheme). For keys made only of characters in the Basic
//! Multilingual Plane it is also byte-for-byte what Python produces with
//! `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`,
//! because Python sorts by code point and UTF-16 order only differs from
//! code-point order above U+FFFF. That agreement is tested with a
//! known-answer vector. It is **not** what CNS `subject_digest` computes;
//! see the crate-level open questions.
//!
//! # Bounds
//!
//! The parser refuses input longer than `max_bytes` before reading it,
//! stops at `max_depth` levels of nesting before recursing further, and
//! stops after `max_nodes` values. Recursion depth is therefore at most
//! `max_depth`, which config validation caps at 128. The encoder applies
//! the same three limits to in-process values, so an envelope built in
//! Rust gets exactly the same caps as one that arrived as bytes. The
//! encoder never writes past the byte cap: a string's exact escaped length
//! is checked before it is written, and an object with more members than
//! the remaining node or byte budget allows is refused before its keys are
//! collected and sorted, so refusal cost is bounded by the caps rather than
//! by the size of a caller-built value.

use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

/// Largest integer magnitude the encoding accepts: 2^53 - 1.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Why a value could not be parsed or canonically encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    /// Input or encoding longer than the byte budget.
    #[error("input exceeds the byte budget")]
    TooLarge,
    /// Nesting deeper than the depth cap.
    #[error("nesting exceeds the depth cap")]
    TooDeep,
    /// More values than the node cap.
    #[error("value count exceeds the node cap")]
    TooManyNodes,
    /// Not well-formed JSON under the strict grammar.
    #[error("input is not well-formed JSON")]
    Malformed,
    /// A number with a fraction or exponent.
    #[error("number is not an integer")]
    NonInteger,
    /// `NaN`, `Infinity` or `-Infinity`.
    #[error("number is not finite")]
    NonFinite,
    /// An integer outside the safe range.
    #[error("integer is outside plus or minus 2^53 - 1")]
    IntegerOutOfRange,
    /// The same key twice in one object.
    #[error("object has a duplicate key")]
    DuplicateKey,
}

/// The three caps shared by the parser and the encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum input length, and maximum canonical output length, in bytes.
    pub max_bytes: usize,
    /// Maximum nesting. The outermost array or object is level 1.
    pub max_depth: usize,
    /// Maximum number of JSON values (every scalar, array and object
    /// counts as one; object keys do not).
    pub max_nodes: usize,
}

/// SHA-256 of `bytes` as 64 lowercase hex characters. Never truncated.
pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}

/// Lowercase hex of `bytes`.
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

/// Decodes exactly `2 * N` lowercase hex characters. Uppercase is refused so
/// that every byte string has exactly one accepted spelling.
pub fn decode_hex_lower<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = s.as_bytes();
    if bytes.len() != N.checked_mul(2)? {
        return None;
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let hi = hex_nibble(*pair.first()?)?;
        let lo = hex_nibble(*pair.get(1)?)?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Strict parser
// ---------------------------------------------------------------------------

/// Parses `input` as one JSON value under the strict grammar and the caps.
///
/// Refused: input over `max_bytes` (checked before anything is read),
/// invalid UTF-8, a byte-order mark, whitespace other than space, tab, LF
/// and CR, trailing content, raw control characters in strings, lone
/// surrogate escapes, numbers with a fraction or exponent, `NaN` and the
/// infinities, leading zeros, integers outside the safe range, and
/// duplicate object keys.
pub fn parse_strict(input: &[u8], limits: &Limits) -> Result<Value, CanonicalError> {
    if input.len() > limits.max_bytes {
        return Err(CanonicalError::TooLarge);
    }
    let text = std::str::from_utf8(input).map_err(|_| CanonicalError::Malformed)?;
    let mut p = Parser {
        text,
        bytes: text.as_bytes(),
        pos: 0,
        depth: 0,
        nodes: 0,
        limits,
    };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(CanonicalError::Malformed);
    }
    Ok(v)
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
    nodes: usize,
    limits: &'a Limits,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn eat(&mut self, want: u8) -> bool {
        if self.peek() == Some(want) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, want: u8) -> Result<(), CanonicalError> {
        if self.eat(want) {
            Ok(())
        } else {
            Err(CanonicalError::Malformed)
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn starts_with(&self, lit: &[u8]) -> bool {
        self.bytes
            .get(self.pos..)
            .is_some_and(|rest| rest.starts_with(lit))
    }

    fn literal(&mut self, lit: &[u8], v: Value) -> Result<Value, CanonicalError> {
        if self.starts_with(lit) {
            self.pos += lit.len();
            Ok(v)
        } else {
            Err(CanonicalError::Malformed)
        }
    }

    fn value(&mut self) -> Result<Value, CanonicalError> {
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            return Err(CanonicalError::TooManyNodes);
        }
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b'N') if self.starts_with(b"NaN") => Err(CanonicalError::NonFinite),
            Some(b'I') if self.starts_with(b"Infinity") => Err(CanonicalError::NonFinite),
            Some(b'-') if self.starts_with(b"-Infinity") => Err(CanonicalError::NonFinite),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(CanonicalError::Malformed),
        }
    }

    fn enter(&mut self) -> Result<(), CanonicalError> {
        self.depth += 1;
        if self.depth > self.limits.max_depth {
            Err(CanonicalError::TooDeep)
        } else {
            Ok(())
        }
    }

    fn object(&mut self) -> Result<Value, CanonicalError> {
        self.expect(b'{')?;
        self.enter()?;
        let mut map = Map::new();
        self.skip_ws();
        if !self.eat(b'}') {
            loop {
                self.skip_ws();
                if self.peek() != Some(b'"') {
                    return Err(CanonicalError::Malformed);
                }
                let key = self.string()?;
                self.skip_ws();
                self.expect(b':')?;
                self.skip_ws();
                let val = self.value()?;
                if map.contains_key(&key) {
                    return Err(CanonicalError::DuplicateKey);
                }
                map.insert(key, val);
                self.skip_ws();
                if self.eat(b',') {
                    continue;
                }
                self.expect(b'}')?;
                break;
            }
        }
        self.depth -= 1;
        Ok(Value::Object(map))
    }

    fn array(&mut self) -> Result<Value, CanonicalError> {
        self.expect(b'[')?;
        self.enter()?;
        let mut items = Vec::new();
        self.skip_ws();
        if !self.eat(b']') {
            loop {
                self.skip_ws();
                items.push(self.value()?);
                self.skip_ws();
                if self.eat(b',') {
                    continue;
                }
                self.expect(b']')?;
                break;
            }
        }
        self.depth -= 1;
        Ok(Value::Array(items))
    }

    fn number(&mut self) -> Result<Value, CanonicalError> {
        let negative = self.eat(b'-');
        let digits_start = self.pos;
        match self.bump() {
            Some(b'0') => {
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(CanonicalError::Malformed); // leading zero
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(CanonicalError::Malformed),
        }
        let digits_end = self.pos;
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            // Validate the rest of the number grammar so that a malformed
            // token is reported as malformed, and a well-formed float as a
            // float.
            if self.eat(b'.') {
                self.digits1()?;
            }
            if self.eat(b'e') || self.eat(b'E') {
                if !self.eat(b'+') {
                    self.eat(b'-');
                }
                self.digits1()?;
            }
            return Err(CanonicalError::NonInteger);
        }
        let digits = self
            .bytes
            .get(digits_start..digits_end)
            .ok_or(CanonicalError::Malformed)?;
        let magnitude = parse_safe_magnitude(digits)?;
        let n = if negative {
            // magnitude <= 2^53 - 1, so the cast and the negation are exact.
            Number::from(0i64 - magnitude as i64)
        } else {
            Number::from(magnitude)
        };
        Ok(Value::Number(n))
    }

    fn digits1(&mut self) -> Result<(), CanonicalError> {
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(CanonicalError::Malformed);
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        Ok(())
    }

    fn hex4(&mut self) -> Result<u32, CanonicalError> {
        let mut v = 0u32;
        for _ in 0..4 {
            let b = self.bump().ok_or(CanonicalError::Malformed)?;
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(CanonicalError::Malformed),
            };
            v = (v << 4) | u32::from(d);
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String, CanonicalError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let run_start = self.pos;
            while matches!(self.peek(), Some(b) if b != b'"' && b != b'\\' && b >= 0x20) {
                self.pos += 1;
            }
            // The run stops only at ASCII bytes, so both ends are on char
            // boundaries of the already-validated UTF-8 text.
            let run = self
                .text
                .get(run_start..self.pos)
                .ok_or(CanonicalError::Malformed)?;
            out.push_str(run);
            match self.bump() {
                Some(b'"') => return Ok(out),
                Some(b'\\') => out.push(self.escape()?),
                _ => return Err(CanonicalError::Malformed), // control char or end
            }
        }
    }

    fn escape(&mut self) -> Result<char, CanonicalError> {
        let c = match self.bump() {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                let first = self.hex4()?;
                let code = match first {
                    0xD800..=0xDBFF => {
                        if !(self.eat(b'\\') && self.eat(b'u')) {
                            return Err(CanonicalError::Malformed); // lone high surrogate
                        }
                        let second = self.hex4()?;
                        if !(0xDC00..=0xDFFF).contains(&second) {
                            return Err(CanonicalError::Malformed);
                        }
                        0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                    }
                    0xDC00..=0xDFFF => return Err(CanonicalError::Malformed), // lone low
                    other => other,
                };
                char::from_u32(code).ok_or(CanonicalError::Malformed)?
            }
            _ => return Err(CanonicalError::Malformed),
        };
        Ok(c)
    }
}

/// Parses ASCII digits (already grammar-checked) into a magnitude no larger
/// than [`MAX_SAFE_INTEGER`]. Work is bounded: it stops at 17 digits.
fn parse_safe_magnitude(digits: &[u8]) -> Result<u64, CanonicalError> {
    // 2^53 - 1 has 16 digits; anything longer is out of range.
    if digits.len() > 16 {
        return Err(CanonicalError::IntegerOutOfRange);
    }
    let mut v: u64 = 0;
    for d in digits {
        v = v * 10 + u64::from(d - b'0'); // at most 16 digits: no overflow
    }
    if v > MAX_SAFE_INTEGER {
        return Err(CanonicalError::IntegerOutOfRange);
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// Canonical encoder
// ---------------------------------------------------------------------------

/// Canonically encodes `value`, appending to `out`.
///
/// `start_depth` is the nesting level `value` sits at (0 for a top-level
/// value, 1 for a member of the envelope object). The byte budget applies
/// to the whole of `out`, so callers can encode several parts under one
/// budget.
pub fn encode_value(
    value: &Value,
    limits: &Limits,
    start_depth: usize,
    out: &mut Vec<u8>,
) -> Result<(), CanonicalError> {
    encode_value_counted(value, limits, start_depth, 0, out)
}

/// [`encode_value`] with `start_nodes` values already counted against
/// `max_nodes`. The Trident uses this to count the envelope object and its
/// nine scalar fields, exactly as the wire parser does.
pub(crate) fn encode_value_counted(
    value: &Value,
    limits: &Limits,
    start_depth: usize,
    start_nodes: usize,
    out: &mut Vec<u8>,
) -> Result<(), CanonicalError> {
    let mut enc = Encoder {
        limits,
        nodes: start_nodes,
        out,
    };
    enc.value(value, start_depth)
}

/// Canonical encoding of a top-level value, as a fresh buffer.
pub fn to_canonical_bytes(value: &Value, limits: &Limits) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    encode_value(value, limits, 0, &mut out)?;
    Ok(out)
}

/// Exact length in bytes of the canonical form of `s`, quotes included:
/// what [`write_str`] would append. One pass over `s`, no allocation.
pub fn escaped_len(s: &str) -> usize {
    let mut n: usize = 2;
    for ch in s.chars() {
        let add = match ch {
            '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
            c if u32::from(c) < 0x20 => 6,
            c => c.len_utf8(),
        };
        n = n.saturating_add(add);
    }
    n
}

/// Writes a canonical JSON string. The caller checks the budget, using
/// [`escaped_len`] for the exact size.
pub fn write_str(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    let mut buf = [0u8; 4];
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if u32::from(c) < 0x20 => {
                out.extend_from_slice(b"\\u00");
                out.extend_from_slice(to_hex(&[c as u8]).as_bytes());
            }
            c => out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes()),
        }
    }
    out.push(b'"');
}

/// Writes a canonical integer after checking its range.
pub fn write_u64(n: u64, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    if n > MAX_SAFE_INTEGER {
        return Err(CanonicalError::IntegerOutOfRange);
    }
    out.extend_from_slice(n.to_string().as_bytes());
    Ok(())
}

struct Encoder<'a> {
    limits: &'a Limits,
    nodes: usize,
    out: &'a mut Vec<u8>,
}

impl Encoder<'_> {
    fn budget(&self, extra: usize) -> Result<(), CanonicalError> {
        if self.out.len().saturating_add(extra) > self.limits.max_bytes {
            Err(CanonicalError::TooLarge)
        } else {
            Ok(())
        }
    }

    fn string(&mut self, s: &str) -> Result<(), CanonicalError> {
        // The escaped form is at least len + 2 bytes: refuse in O(1) when
        // even that does not fit. Otherwise `s` is within the budget, so the
        // exact escaped length is a bounded scan, and nothing is written
        // unless it fits. No transient overshoot of the byte cap.
        self.budget(s.len().saturating_add(2))?;
        self.budget(escaped_len(s))?;
        write_str(s, self.out);
        Ok(())
    }

    fn value(&mut self, v: &Value, depth: usize) -> Result<(), CanonicalError> {
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            return Err(CanonicalError::TooManyNodes);
        }
        match v {
            Value::Null => {
                self.budget(4)?;
                self.out.extend_from_slice(b"null");
            }
            Value::Bool(true) => {
                self.budget(4)?;
                self.out.extend_from_slice(b"true");
            }
            Value::Bool(false) => {
                self.budget(5)?;
                self.out.extend_from_slice(b"false");
            }
            Value::Number(n) => {
                self.budget(17)?;
                self.number(n)?;
            }
            Value::String(s) => self.string(s)?,
            Value::Array(items) => {
                let depth = self.enter(depth)?;
                self.budget(2)?;
                self.out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        self.budget(1)?;
                        self.out.push(b',');
                    }
                    self.value(item, depth)?;
                }
                self.budget(1)?;
                self.out.push(b']');
            }
            Value::Object(map) => {
                let depth = self.enter(depth)?;
                // Refuse before collecting and sorting the keys when the
                // object cannot fit: each member is at least one more value,
                // and at least `"":0` plus a separator (5 bytes), so the
                // work done here is bounded by the caps, not by the size of
                // a caller-built map.
                let remaining_nodes = self.limits.max_nodes.saturating_sub(self.nodes);
                if map.len() > remaining_nodes {
                    return Err(CanonicalError::TooManyNodes);
                }
                self.budget(map.len().saturating_mul(5).saturating_add(1))?;
                self.out.push(b'{');
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
                for (i, key) in keys.into_iter().enumerate() {
                    if i > 0 {
                        self.budget(1)?;
                        self.out.push(b',');
                    }
                    self.string(key)?;
                    self.budget(1)?;
                    self.out.push(b':');
                    let member = map.get(key).ok_or(CanonicalError::Malformed)?;
                    self.value(member, depth)?;
                }
                self.budget(1)?;
                self.out.push(b'}');
            }
        }
        Ok(())
    }

    fn enter(&self, depth: usize) -> Result<usize, CanonicalError> {
        let next = depth.saturating_add(1);
        if next > self.limits.max_depth {
            Err(CanonicalError::TooDeep)
        } else {
            Ok(next)
        }
    }

    fn number(&mut self, n: &Number) -> Result<(), CanonicalError> {
        if let Some(i) = n.as_i64() {
            if i.unsigned_abs() > MAX_SAFE_INTEGER {
                return Err(CanonicalError::IntegerOutOfRange);
            }
            self.out.extend_from_slice(i.to_string().as_bytes());
            Ok(())
        } else if n.as_u64().is_some() {
            // Only reachable for values above i64::MAX.
            Err(CanonicalError::IntegerOutOfRange)
        } else {
            match n.as_f64() {
                Some(f) if !f.is_finite() => Err(CanonicalError::NonFinite),
                _ => Err(CanonicalError::NonInteger),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const LIM: Limits = Limits {
        max_bytes: 4096,
        max_depth: 8,
        max_nodes: 256,
    };

    fn parse(s: &str) -> Result<Value, CanonicalError> {
        parse_strict(s.as_bytes(), &LIM)
    }

    fn canon(v: &Value) -> String {
        String::from_utf8(to_canonical_bytes(v, &LIM).unwrap()).unwrap()
    }

    #[test]
    fn sorted_keys_no_whitespace() {
        let v = parse(r#" { "b" : 1 , "a" : [ true , null , "x" ] } "#).unwrap();
        assert_eq!(canon(&v), r#"{"a":[true,null,"x"],"b":1}"#);
    }

    #[test]
    fn keys_sort_by_utf16_code_units() {
        // U+FF61 is above the surrogate range in UTF-16 order; U+1F600 is
        // encoded with a high surrogate (0xD83D), so it sorts first in
        // UTF-16 order but last in code-point order.
        let v = json!({"\u{FF61}": 1, "\u{1F600}": 2, "a": 3});
        assert_eq!(canon(&v), "{\"a\":3,\"\u{1F600}\":2,\"\u{FF61}\":1}");
    }

    #[test]
    fn string_escapes_are_minimal_and_lowercase() {
        let v = Value::String("q\"b\\/\u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f}é".into());
        assert_eq!(canon(&v), "\"q\\\"b\\\\/\\b\\f\\n\\r\\t\\u0001\\u001f\u{7f}é\"");
    }

    #[test]
    fn escaped_and_raw_forms_canonicalize_identically() {
        let a = parse(r#"{"k":"\u00e9\/A"}"#).unwrap();
        let b = parse("{\"k\":\"é/\\u0041\"}").unwrap();
        assert_eq!(canon(&a), canon(&b));
        assert_eq!(canon(&a), "{\"k\":\"é/A\"}");
    }

    #[test]
    fn integers_only() {
        assert_eq!(parse("1.0"), Err(CanonicalError::NonInteger));
        assert_eq!(parse("1e3"), Err(CanonicalError::NonInteger));
        assert_eq!(parse("-2E-1"), Err(CanonicalError::NonInteger));
        assert_eq!(parse("1."), Err(CanonicalError::Malformed));
        assert_eq!(parse("NaN"), Err(CanonicalError::NonFinite));
        assert_eq!(parse("Infinity"), Err(CanonicalError::NonFinite));
        assert_eq!(parse("[-Infinity]"), Err(CanonicalError::NonFinite));
        assert_eq!(parse("01"), Err(CanonicalError::Malformed));
        assert_eq!(parse("+1"), Err(CanonicalError::Malformed));
        assert_eq!(canon(&parse("-0").unwrap()), "0");
        assert_eq!(canon(&parse("9007199254740991").unwrap()), "9007199254740991");
        assert_eq!(canon(&parse("-9007199254740991").unwrap()), "-9007199254740991");
        assert_eq!(parse("9007199254740992"), Err(CanonicalError::IntegerOutOfRange));
        assert_eq!(parse("123456789012345678901234567890"), Err(CanonicalError::IntegerOutOfRange));
        let float = Value::Number(Number::from_f64(0.5).unwrap());
        assert_eq!(to_canonical_bytes(&float, &LIM), Err(CanonicalError::NonInteger));
        assert_eq!(
            to_canonical_bytes(&json!(u64::MAX), &LIM),
            Err(CanonicalError::IntegerOutOfRange)
        );
    }

    #[test]
    fn duplicate_keys_refused() {
        assert_eq!(parse(r#"{"a":1,"a":1}"#), Err(CanonicalError::DuplicateKey));
        assert_eq!(parse(r#"{"a":1,"\u0061":2}"#), Err(CanonicalError::DuplicateKey));
    }

    #[test]
    fn strict_grammar() {
        for bad in [
            "",
            "   ",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "{a:1}",
            "'a'",
            "\"\u{1}\"",
            "\"\\x\"",
            "\"\\ud800\"",
            "\"\\udc00\"",
            "\"\\ud800\\u0041\"",
            "tru",
            "nul",
            "1 2",
            "\u{feff}1",
            "\u{a0}1",
        ] {
            assert_eq!(parse(bad), Err(CanonicalError::Malformed), "{bad:?}");
        }
        assert_eq!(parse_strict(&[0x22, 0xff, 0x22], &LIM), Err(CanonicalError::Malformed));
        assert_eq!(
            parse("\"\\ud83d\\ude00\"").unwrap(),
            Value::String("\u{1F600}".into())
        );
    }

    #[test]
    fn caps_apply_in_both_directions() {
        let deep = "[".repeat(9) + &"]".repeat(9);
        assert_eq!(parse(&deep), Err(CanonicalError::TooDeep));
        let ok = "[".repeat(8) + &"]".repeat(8);
        assert!(parse(&ok).is_ok());
        let wide = format!("[{}]", vec!["0"; 300].join(","));
        assert_eq!(parse(&wide), Err(CanonicalError::TooManyNodes));
        let big = "x".repeat(5000);
        assert_eq!(parse(&big), Err(CanonicalError::TooLarge));

        let mut v = json!(0);
        for _ in 0..9 {
            v = json!([v]);
        }
        assert_eq!(to_canonical_bytes(&v, &LIM), Err(CanonicalError::TooDeep));
        let long = Value::String("y".repeat(5000));
        assert_eq!(to_canonical_bytes(&long, &LIM), Err(CanonicalError::TooLarge));
    }

    #[test]
    fn escaped_len_matches_write_str() {
        for s in ["", "abc", "q\"b\\/\u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f}é\u{1F600}", &"\u{1}".repeat(50)] {
            let mut out = Vec::new();
            write_str(s, &mut out);
            assert_eq!(escaped_len(s), out.len(), "{s:?}");
        }
    }

    #[test]
    fn wide_objects_are_refused_before_sorting() {
        let mut m = Map::new();
        for i in 0..300 {
            m.insert(format!("{i}"), Value::Null);
        }
        let v = Value::Object(m);
        assert_eq!(to_canonical_bytes(&v, &LIM), Err(CanonicalError::TooManyNodes));
        let tight = Limits { max_bytes: 100, ..LIM };
        let mut m = Map::new();
        for i in 0..30 {
            m.insert(format!("{i}"), Value::Null);
        }
        assert_eq!(to_canonical_bytes(&Value::Object(m), &tight), Err(CanonicalError::TooLarge));
    }

    #[test]
    fn hex_is_strict_lowercase() {
        assert_eq!(decode_hex_lower::<2>("0aff"), Some([0x0a, 0xff]));
        assert_eq!(decode_hex_lower::<2>("0AFF"), None);
        assert_eq!(decode_hex_lower::<2>("0af"), None);
        assert_eq!(decode_hex_lower::<2>("0afg"), None);
        assert_eq!(to_hex(&[0x00, 0xab]), "00ab");
        assert_eq!(sha256_hex(b"").len(), 64);
    }
}
