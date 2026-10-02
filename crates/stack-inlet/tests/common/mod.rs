//! A slow, independent reference for the inlet's automaton.
//!
//! Structure comes from `std::str::from_utf8` (which reports where each
//! ill-formed subpart starts and how long it is), classification comes from
//! `char` methods and plain code-point ranges. Nothing here shares code or
//! tables with the automaton.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use stack_inlet::Reason;

/// What the reference expects for one input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    pub violations: Vec<(usize, Reason)>,
}

impl Expected {
    pub fn first(&self) -> Option<(usize, Reason)> {
        self.violations.first().copied()
    }
    pub fn count(&self) -> usize {
        self.violations.len()
    }
    pub fn reasons(&self) -> Vec<Reason> {
        let mut r: Vec<Reason> = self.violations.iter().map(|v| v.1).collect();
        r.sort();
        r.dedup();
        r
    }
}

/// Unicode 16.0 `Default_Ignorable_Code_Point`, copied from
/// DerivedCoreProperties.txt (all 17 ranges, 4174 code points).
pub const DEFAULT_IGNORABLE: [(u32, u32); 17] = [
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
];

/// Unicode `Bidi_Control`: the 12 code points, split into the overrides and
/// isolates (terminal) and the implicit marks (repairable).
pub const BIDI_OVERRIDES: [(u32, u32); 2] = [(0x202A, 0x202E), (0x2066, 0x2069)];
pub const BIDI_MARKS: [u32; 3] = [0x061C, 0x200E, 0x200F];

fn in_ranges(u: u32, r: &[(u32, u32)]) -> bool {
    r.iter().any(|&(lo, hi)| (lo..=hi).contains(&u))
}

/// Classify a valid scalar value.
pub fn classify_char(c: char) -> Option<Reason> {
    let u = c as u32;
    if c.is_control() && !matches!(c, '\t' | '\n' | '\r') {
        return Some(if u < 0x20 {
            Reason::C0Control
        } else {
            Reason::DelOrC1Control
        });
    }
    if u == 0x2028 || u == 0x2029 {
        return Some(Reason::DelOrC1Control);
    }
    if in_ranges(u, &BIDI_OVERRIDES) {
        return Some(Reason::BidiControl);
    }
    if BIDI_MARKS.contains(&u) {
        return Some(Reason::BidiMark);
    }
    if in_ranges(u, &DEFAULT_IGNORABLE) || (0xFFF9..=0xFFFB).contains(&u) {
        return Some(Reason::ZeroWidth);
    }
    if (0xFDD0..=0xFDEF).contains(&u) || (u & 0xFFFE) == 0xFFFE {
        return Some(Reason::Noncharacter);
    }
    None
}

/// Classify an ill-formed subpart starting at `rest[0]`, given the
/// `error_len` that `from_utf8` reported for it.
fn classify_malformed(rest: &[u8], error_len: Option<usize>) -> Reason {
    let Some(n) = error_len else {
        return Reason::Truncated;
    };
    let b0 = rest[0];
    match b0 {
        0x80..=0xBF => return Reason::UnexpectedContinuation,
        // A C0 or C1 lead is overlong only if a continuation byte follows;
        // alone it is an invalid byte (Latin-1 A-grave or A-acute).
        0xC0 | 0xC1 => {
            return if rest.get(1).is_some_and(|b| (0x80..=0xBF).contains(b)) {
                Reason::Overlong
            } else {
                Reason::InvalidByte
            }
        }
        0xF5..=0xF7 => return Reason::AboveMax,
        0xF8..=0xFF => return Reason::InvalidByte,
        _ => {}
    }
    if n >= 2 {
        return Reason::Truncated;
    }
    let b1 = rest[1];
    if !(0x80..=0xBF).contains(&b1) {
        return Reason::Truncated;
    }
    // The second byte is a continuation the lead does not allow. Decode the
    // smallest code point the two bytes could start and name the problem.
    let hi = u32::from(b1 & 0x3F);
    match b0 {
        0xE0..=0xEF => {
            let cp = (u32::from(b0 & 0x0F) << 12) | (hi << 6);
            if cp < 0x800 {
                Reason::Overlong
            } else if (0xD800..=0xDFFF).contains(&cp) {
                Reason::Surrogate
            } else {
                panic!("unexpected 3-byte rejection {b0:#x} {b1:#x}")
            }
        }
        0xF0..=0xF4 => {
            let cp = (u32::from(b0 & 0x07) << 18) | (hi << 12);
            if cp < 0x10000 {
                Reason::Overlong
            } else if cp > 0x10FFFF {
                Reason::AboveMax
            } else {
                panic!("unexpected 4-byte rejection {b0:#x} {b1:#x}")
            }
        }
        _ => panic!("unexpected rejection {b0:#x} {b1:#x}"),
    }
}

fn classify_valid(s: &str, base: usize, out: &mut Vec<(usize, Reason)>) {
    for (i, c) in s.char_indices() {
        if let Some(r) = classify_char(c) {
            out.push((base + i, r));
        }
    }
}

/// The reference judgement of `bytes`, ignoring the length cap.
pub fn reference(bytes: &[u8]) -> Expected {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos <= bytes.len() {
        match std::str::from_utf8(&bytes[pos..]) {
            Ok(s) => {
                classify_valid(s, pos, &mut out);
                break;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                let s = std::str::from_utf8(&bytes[pos..pos + valid]).unwrap();
                classify_valid(s, pos, &mut out);
                let at = pos + valid;
                out.push((at, classify_malformed(&bytes[at..], e.error_len())));
                match e.error_len() {
                    Some(n) => pos = at + n,
                    None => break,
                }
            }
        }
    }
    Expected { violations: out }
}

/// Every banned scalar value, grouped by reason.
pub fn banned_chars() -> Vec<(char, Reason)> {
    (0u32..=0x10FFFF)
        .filter_map(char::from_u32)
        .filter_map(|c| classify_char(c).map(|r| (c, r)))
        .collect()
}
