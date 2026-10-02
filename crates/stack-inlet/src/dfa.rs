//! The winnowing fan: a table-driven deterministic finite automaton over bytes.
//!
//! # How it works, in plain words
//!
//! A deterministic finite automaton (DFA) is a machine with a fixed, small
//! number of states. It reads one byte at a time and, from the current state
//! and that byte alone, looks up the next state in a table. There is no
//! backtracking (it never re-reads an earlier byte), no recursion and no
//! memory that grows with the input: the whole machine is a handful of
//! integers. That is what makes it safe to point at hostile input. The work
//! per byte is one table lookup plus a few arithmetic operations, whatever
//! the bytes are.
//!
//! The states track "where am I inside a UTF-8 character". UTF-8 writes each
//! character as 1 to 4 bytes: a lead byte that says how long the character is,
//! then continuation bytes (80..BF). Most states just count continuation
//! bytes. A few extra states follow the specific byte prefixes of the banned
//! characters (for example `E2 80` is the prefix shared by U+200B..U+200F,
//! U+2028, U+2029 and U+202A..U+202E), so the last byte of a banned character
//! lands on a table entry that says "violation". The banned sets are fixed
//! Unicode 16.0 properties (see [`Reason`]); they are written out by hand in
//! [`step`] and checked against an independent per-code-point reference over
//! all 1,114,112 code points by the `hand_cases` tests.
//!
//! # The table
//!
//! `TABLE[state][class]` is a `const`, computed at compile time from the
//! readable specification in [`step`]. The 256 byte values are first grouped
//! into classes of bytes that behave identically in every state (for
//! example, all ASCII letters are one class). The grouping is also computed
//! at compile time, by comparing each byte's column of behaviour against the
//! classes found so far, so it cannot drift out of step with the
//! specification; a unit test re-checks every (state, byte) pair.
//!
//! The specification needs 53 classes and 36 states:
//!
//! | Class | Bytes | Role |
//! |---|---|---|
//! | 0 | 00..08 0B 0C 0E..1F | C0 controls (banned) |
//! | 1 | 09 0A 0D 20..7E | ordinary ASCII |
//! | 2 | 7F | DEL (banned) |
//! | 3..34 | 80..BF, split 32 ways | continuation bytes, split wherever a banned character or an overlong, surrogate or above-maximum range has a boundary |
//! | 35 | C0 C1 | overlong two-byte leads, or lone invalid bytes |
//! | 36 | C2 | lead of U+0080..U+00BF (C1 controls, soft hyphen) |
//! | 37 | C3..CC CE..D7 D9..DF | other two-byte leads |
//! | 38 | CD | lead of U+0340..U+037F (combining grapheme joiner) |
//! | 39 | D8 | lead of U+0600..U+063F (Arabic letter mark) |
//! | 40 | E0 | three-byte lead with an overlong range |
//! | 41 | E1 | lead of U+1000..U+1FFF (Hangul, Khmer, Mongolian invisibles) |
//! | 42 | E2 | lead of U+2000..U+2FFF (zero-width, bidi, line separators) |
//! | 43 | E3 | lead of U+3000..U+3FFF (Hangul filler) |
//! | 44 | E4..EC EE | plain three-byte leads |
//! | 45 | ED | three-byte lead with the surrogate range |
//! | 46 | EF | lead of U+F000..U+FFFF (BOM, selectors, noncharacters) |
//! | 47 | F0 | four-byte lead with an overlong range |
//! | 48 | F1 F2 | plain four-byte leads |
//! | 49 | F3 | lead of U+C0000..U+FFFFF (tags, selectors 17 to 256) |
//! | 50 | F4 | four-byte lead with an above-maximum range |
//! | 51 | F5..F7 | leads that would encode above U+10FFFF |
//! | 52 | F8..FF | never valid in UTF-8 |
//!
//! Padded to 64 rows by 64 columns of `u16`, the table is 8 KiB, of which
//! the 36 real rows (about 4.5 KiB) are ever touched; that fits in the
//! first-level data cache of current CPUs.
//!
//! Each table entry is a `u16` holding four things:
//!
//! * the next state (6 bits),
//! * a "pending" reason (4 bits): a violation that belongs to the character
//!   that started at the remembered sequence start, either because this byte
//!   completed a banned character or because it showed the sequence was
//!   malformed,
//! * a "current" reason (4 bits): a violation at this very byte, such as a
//!   control character or a stray continuation byte,
//! * a flag that says "this byte starts a new multi-byte sequence".
//!
//! # Malformed input and resynchronisation
//!
//! When a multi-byte sequence breaks, the automaton reports it at the offset
//! where the sequence started, and treats the byte that broke it as if it had
//! arrived in the start state. That is not backtracking: the table entry for
//! (mid-sequence state, byte) is built as "the start state's entry for this
//! byte, plus a pending violation". The effect is that malformed input is
//! counted once per maximal ill-formed subpart, which is the convention the
//! Rust standard library (`str::from_utf8`) and the WHATWG decoder use, and
//! which the property tests check against.
//!
//! The one lookahead is C0 and C1. Neither byte appears in valid UTF-8, so
//! each is one violation either way, but the reason depends on the next
//! byte: a continuation byte makes it an overlong form (and the continuation
//! a stray), anything else makes it a lone invalid byte. The C0 state holds
//! that one byte of context; it does not re-read anything.
//!
//! # Constant work per byte
//!
//! The loop records violations with mask arithmetic rather than `if`
//! statements, so a byte that is a violation costs the same instructions as
//! one that is not. Rust gives no guarantee that the compiler keeps this
//! branch-free, so the timing test measures it instead of assuming it.

use crate::verdict::{Reason, ReasonSet};

// Entry layout.
const NEXT_MASK: u16 = 0x3F;
const PEND_SHIFT: u16 = 6;
const CUR_SHIFT: u16 = 10;
const REASON_BITS: u16 = 0x0F;
const START_BIT: u16 = 1 << 14;

/// Rows in the padded table. Indexing with `state & 63` is provably in bounds.
const ROWS: usize = 64;
/// Columns in the padded table. Indexing with `class & 63` is provably in bounds.
const COLS: usize = 64;

// States. Names say what has been read of the current sequence.
/// Between characters.
const S_START: u8 = 0;
/// Read `C2`; the next byte decides C1 control (80..9F), soft hyphen (AD) or
/// neither.
const S_C2: u8 = 1;
/// One continuation byte still needed, nothing special can follow.
const S_TAIL1: u8 = 2;
/// Two continuation bytes still needed, nothing special can follow.
const S_TAIL2: u8 = 3;
/// Read `E0`; 80..9F would be overlong.
const S_E0: u8 = 4;
/// Read `ED`; A0..BF would be a surrogate.
const S_ED: u8 = 5;
/// Read `E2`; prefix of the zero-width, bidi and line-separator characters.
const S_E2: u8 = 6;
/// Read `E2 80`: U+2000..U+203F.
const S_E2_80: u8 = 7;
/// Read `E2 81`: U+2040..U+207F.
const S_E2_81: u8 = 8;
/// Read `EF`; prefix of the BOM, the variation selectors, the Hangul
/// halfwidth filler, U+FFF0..U+FFFB and the BMP noncharacters.
const S_EF: u8 = 9;
/// Read `EF B7`: U+FDC0..U+FDFF.
const S_EF_B7: u8 = 10;
/// Read `EF BB`: U+FEC0..U+FEFF.
const S_EF_BB: u8 = 11;
/// Read `EF BF`: U+FFC0..U+FFFF.
const S_EF_BF: u8 = 12;
/// Read `F0`; 80..8F would be overlong.
const S_F0: u8 = 13;
/// Read `F1` or `F2`.
const S_F12: u8 = 14;
/// Read `F4`; 90..BF would be above U+10FFFF.
const S_F4: u8 = 15;
/// Four-byte sequence whose code point so far ends in hex F (U+xF000 range):
/// could become U+xFFFE or U+xFFFF.
const S_NC2: u8 = 16;
/// As [`S_NC2`] with third byte `BF`: U+xFFC0..U+xFFFF.
const S_NC3: u8 = 17;
/// Read `C0` or `C1`. Followed by a continuation byte it is an overlong
/// form; followed by anything else it is a lone invalid byte (for example a
/// Latin-1 capital A with grave or acute accent).
const S_C0: u8 = 18;
/// Read `CD`: U+0340..U+037F (combining grapheme joiner U+034F).
const S_CD: u8 = 19;
/// Read `D8`: U+0600..U+063F (Arabic letter mark U+061C).
const S_D8: u8 = 20;
/// Read `E1`: U+1000..U+1FFF.
const S_E1: u8 = 21;
/// Read `E1 85`: U+1140..U+117F (Hangul fillers U+115F, U+1160).
const S_E1_85: u8 = 22;
/// Read `E1 9E`: U+1780..U+17BF (Khmer inherent vowels U+17B4, U+17B5).
const S_E1_9E: u8 = 23;
/// Read `E1 A0`: U+1800..U+183F (Mongolian selectors U+180B..U+180F).
const S_E1_A0: u8 = 24;
/// Read `E3`: U+3000..U+3FFF.
const S_E3: u8 = 25;
/// Read `E3 85`: U+3140..U+317F (Hangul filler U+3164).
const S_E3_85: u8 = 26;
/// Read `EF B8`: U+FE00..U+FE3F (variation selectors U+FE00..U+FE0F).
const S_EF_B8: u8 = 27;
/// Read `EF BE`: U+FF80..U+FFBF (halfwidth Hangul filler U+FFA0).
const S_EF_BE: u8 = 28;
/// Read `F0 9B`: U+1B000..U+1BFFF.
const S_F0_9B: u8 = 29;
/// Read `F0 9B B2`: U+1BC80..U+1BCBF (shorthand format controls).
const S_F0_9B_B2: u8 = 30;
/// Read `F0 9D`: U+1D000..U+1DFFF.
const S_F0_9D: u8 = 31;
/// Read `F0 9D 85`: U+1D140..U+1D17F (musical formatting controls).
const S_F0_9D_85: u8 = 32;
/// Read `F3`: U+C0000..U+FFFFF.
const S_F3: u8 = 33;
/// Two continuation bytes still needed, and the character is invisible
/// whatever they are: read `F3 A0`, U+E0000..U+E0FFF (tag characters and
/// variation selectors 17 to 256).
const S_ZW2: u8 = 34;
/// As [`S_ZW2`] with one continuation byte still needed.
const S_ZW1: u8 = 35;
/// Number of real states.
const STATE_COUNT: u8 = 36;

// Reason codes as stored in the table (0 means none).
const NONE: u8 = 0;
const C0: u8 = Reason::C0Control as u8;
const C1: u8 = Reason::DelOrC1Control as u8;
const BIDI: u8 = Reason::BidiControl as u8;
const MARK: u8 = Reason::BidiMark as u8;
const ZW: u8 = Reason::ZeroWidth as u8;
const NONCHAR: u8 = Reason::Noncharacter as u8;
const OVERLONG: u8 = Reason::Overlong as u8;
const SURROGATE: u8 = Reason::Surrogate as u8;
const ABOVE_MAX: u8 = Reason::AboveMax as u8;
const INVALID: u8 = Reason::InvalidByte as u8;
const UNEXPECTED: u8 = Reason::UnexpectedContinuation as u8;
const TRUNCATED: u8 = Reason::Truncated as u8;

const fn ent(next: u8, pend: u8, cur: u8, starts: bool) -> u16 {
    (next as u16 & NEXT_MASK)
        | ((pend as u16 & REASON_BITS) << PEND_SHIFT)
        | ((cur as u16 & REASON_BITS) << CUR_SHIFT)
        | if starts { START_BIT } else { 0 }
}

/// A character completed; `pend` is its violation, if any.
const fn done(pend: u8) -> u16 {
    ent(S_START, pend, NONE, false)
}

/// Go to `next`, still inside the sequence.
const fn to(next: u8) -> u16 {
    ent(next, NONE, NONE, false)
}

/// The sequence in progress is broken with `pend`; handle `b` afresh.
const fn abort(pend: u8, b: u8) -> u16 {
    start(b) | ((pend as u16 & REASON_BITS) << PEND_SHIFT)
}

const fn is_cont(b: u8) -> bool {
    matches!(b, 0x80..=0xBF)
}

/// Behaviour of byte `b` between characters.
const fn start(b: u8) -> u16 {
    match b {
        0x09 | 0x0A | 0x0D | 0x20..=0x7E => to(S_START),
        0x00..=0x1F => ent(S_START, NONE, C0, false),
        0x7F => ent(S_START, NONE, C1, false),
        0x80..=0xBF => ent(S_START, NONE, UNEXPECTED, false),
        0xC0 | 0xC1 => ent(S_C0, NONE, NONE, true),
        0xC2 => ent(S_C2, NONE, NONE, true),
        0xCD => ent(S_CD, NONE, NONE, true),
        0xD8 => ent(S_D8, NONE, NONE, true),
        0xC3..=0xDF => ent(S_TAIL1, NONE, NONE, true),
        0xE0 => ent(S_E0, NONE, NONE, true),
        0xE1 => ent(S_E1, NONE, NONE, true),
        0xE2 => ent(S_E2, NONE, NONE, true),
        0xE3 => ent(S_E3, NONE, NONE, true),
        0xED => ent(S_ED, NONE, NONE, true),
        0xEF => ent(S_EF, NONE, NONE, true),
        0xE4..=0xEC | 0xEE => ent(S_TAIL2, NONE, NONE, true),
        0xF0 => ent(S_F0, NONE, NONE, true),
        0xF1 | 0xF2 => ent(S_F12, NONE, NONE, true),
        0xF3 => ent(S_F3, NONE, NONE, true),
        0xF4 => ent(S_F4, NONE, NONE, true),
        0xF5..=0xF7 => ent(S_START, NONE, ABOVE_MAX, false),
        0xF8..=0xFF => ent(S_START, NONE, INVALID, false),
    }
}

/// The last byte of a character whose only special value is `hit`.
const fn last(b: u8, hit: bool, reason: u8) -> u16 {
    if hit && is_cont(b) {
        done(reason)
    } else if is_cont(b) {
        done(NONE)
    } else {
        abort(TRUNCATED, b)
    }
}

/// A middle byte: `hit` goes to `special`, any other continuation to
/// `plain`.
const fn mid(b: u8, hit: bool, special: u8, plain: u8) -> u16 {
    if hit && is_cont(b) {
        to(special)
    } else if is_cont(b) {
        to(plain)
    } else {
        abort(TRUNCATED, b)
    }
}

/// The specification: behaviour of byte `b` in `state`.
///
/// This is the readable form. [`TABLE`] is derived from it at compile time.
const fn step(state: u8, b: u8) -> u16 {
    let c = is_cont(b);
    match state {
        S_START => start(b),
        S_C2 => match b {
            0x80..=0x9F => done(C1),
            0xAD => done(ZW),
            _ if c => done(NONE),
            _ => abort(TRUNCATED, b),
        },
        S_TAIL1 => last(b, false, NONE),
        S_TAIL2 => mid(b, false, S_TAIL1, S_TAIL1),
        S_E0 => match b {
            0x80..=0x9F => abort(OVERLONG, b),
            0xA0..=0xBF => to(S_TAIL1),
            _ => abort(TRUNCATED, b),
        },
        S_ED => match b {
            0x80..=0x9F => to(S_TAIL1),
            0xA0..=0xBF => abort(SURROGATE, b),
            _ => abort(TRUNCATED, b),
        },
        S_E2 => match b {
            0x80 => to(S_E2_80),
            0x81 => to(S_E2_81),
            _ if c => to(S_TAIL1),
            _ => abort(TRUNCATED, b),
        },
        S_E2_80 => match b {
            0x8B..=0x8D => done(ZW),
            0x8E | 0x8F => done(MARK),
            0xA8 | 0xA9 => done(C1),
            0xAA..=0xAE => done(BIDI),
            _ if c => done(NONE),
            _ => abort(TRUNCATED, b),
        },
        S_E2_81 => match b {
            0xA0..=0xA5 | 0xAA..=0xAF => done(ZW),
            0xA6..=0xA9 => done(BIDI),
            _ if c => done(NONE),
            _ => abort(TRUNCATED, b),
        },
        S_EF => match b {
            0xB7 => to(S_EF_B7),
            0xB8 => to(S_EF_B8),
            0xBB => to(S_EF_BB),
            0xBE => to(S_EF_BE),
            0xBF => to(S_EF_BF),
            _ if c => to(S_TAIL1),
            _ => abort(TRUNCATED, b),
        },
        S_EF_B7 => last(b, matches!(b, 0x90..=0xAF), NONCHAR),
        S_EF_B8 => last(b, matches!(b, 0x80..=0x8F), ZW),
        S_EF_BB => last(b, b == 0xBF, ZW),
        S_EF_BE => last(b, b == 0xA0, ZW),
        S_EF_BF => match b {
            0xB0..=0xBB => done(ZW),
            0xBE | 0xBF => done(NONCHAR),
            _ if c => done(NONE),
            _ => abort(TRUNCATED, b),
        },
        S_F0 => match b {
            0x80..=0x8F => abort(OVERLONG, b),
            0x9B => to(S_F0_9B),
            0x9D => to(S_F0_9D),
            0x9F | 0xAF | 0xBF => to(S_NC2),
            0x90..=0xBF => to(S_TAIL2),
            _ => abort(TRUNCATED, b),
        },
        S_F12 => mid(b, matches!(b, 0x8F | 0x9F | 0xAF | 0xBF), S_NC2, S_TAIL2),
        S_F3 => match b {
            0xA0 => to(S_ZW2),
            0x8F | 0x9F | 0xAF | 0xBF => to(S_NC2),
            _ if c => to(S_TAIL2),
            _ => abort(TRUNCATED, b),
        },
        S_F4 => match b {
            0x8F => to(S_NC2),
            0x80..=0x8E => to(S_TAIL2),
            0x90..=0xBF => abort(ABOVE_MAX, b),
            _ => abort(TRUNCATED, b),
        },
        S_NC2 => mid(b, b == 0xBF, S_NC3, S_TAIL1),
        S_NC3 => last(b, matches!(b, 0xBE | 0xBF), NONCHAR),
        S_C0 => {
            if c {
                // An overlong lead (reported at its own offset) followed by
                // a continuation byte, which is then a stray.
                ent(S_START, OVERLONG, UNEXPECTED, false)
            } else {
                abort(INVALID, b)
            }
        }
        S_CD => last(b, b == 0x8F, ZW),
        S_D8 => last(b, b == 0x9C, MARK),
        S_E1 => match b {
            0x85 => to(S_E1_85),
            0x9E => to(S_E1_9E),
            0xA0 => to(S_E1_A0),
            _ if c => to(S_TAIL1),
            _ => abort(TRUNCATED, b),
        },
        S_E1_85 => last(b, matches!(b, 0x9F | 0xA0), ZW),
        S_E1_9E => last(b, matches!(b, 0xB4 | 0xB5), ZW),
        S_E1_A0 => last(b, matches!(b, 0x8B..=0x8F), ZW),
        S_E3 => mid(b, b == 0x85, S_E3_85, S_TAIL1),
        S_E3_85 => last(b, b == 0xA4, ZW),
        S_F0_9B => mid(b, b == 0xB2, S_F0_9B_B2, S_TAIL1),
        S_F0_9B_B2 => last(b, matches!(b, 0xA0..=0xA3), ZW),
        S_F0_9D => mid(b, b == 0x85, S_F0_9D_85, S_TAIL1),
        S_F0_9D_85 => last(b, matches!(b, 0xB3..=0xBA), ZW),
        S_ZW2 => mid(b, false, S_ZW1, S_ZW1),
        S_ZW1 => last(b, true, ZW),
        // Unreachable: no entry names a state at or above STATE_COUNT (a unit
        // test checks). Fail closed anyway.
        _ => ent(S_START, NONE, INVALID, false),
    }
}

/// Filler for padding cells that no input can reach. Fails closed.
const FILLER: u16 = ent(S_START, NONE, INVALID, false);

/// Byte-to-class map plus one representative byte per class.
struct ClassMap {
    class_of: [u8; 256],
    rep: [u8; COLS],
    count: usize,
}

const fn same_column(a: u8, b: u8) -> bool {
    let mut s = 0;
    while s < STATE_COUNT {
        if step(s, a) != step(s, b) {
            return false;
        }
        s += 1;
    }
    true
}

/// Group bytes that behave identically in every state. If more than
/// [`COLS`] classes were ever needed, the index below would go out of bounds
/// during constant evaluation and the crate would fail to compile.
const fn build_classes() -> ClassMap {
    let mut class_of = [0u8; 256];
    let mut rep = [0u8; COLS];
    let mut count = 0usize;
    let mut b = 0usize;
    while b < 256 {
        let mut c = 0usize;
        let mut found = false;
        while c < count {
            if same_column(rep[c], b as u8) {
                class_of[b] = c as u8;
                found = true;
                break;
            }
            c += 1;
        }
        if !found {
            rep[count] = b as u8;
            class_of[b] = count as u8;
            count += 1;
        }
        b += 1;
    }
    ClassMap {
        class_of,
        rep,
        count,
    }
}

const CLASSES: ClassMap = build_classes();

/// Byte to byte-class map.
const CLASS: [u8; 256] = CLASSES.class_of;

/// Number of byte classes the specification needs.
pub(crate) const CLASS_COUNT: usize = CLASSES.count;

// Compile-time guarantees: the classes fit the padded columns and the states
// fit the padded rows, so the masked indexing in `scan` never discards bits.
const _: () = assert!(CLASS_COUNT <= COLS);
const _: () = assert!((STATE_COUNT as usize) <= ROWS);

const fn build_table() -> [[u16; COLS]; ROWS] {
    let mut t = [[FILLER; COLS]; ROWS];
    let mut s = 0usize;
    while s < STATE_COUNT as usize {
        let mut c = 0usize;
        while c < CLASSES.count {
            t[s][c] = step(s as u8, CLASSES.rep[c]);
            c += 1;
        }
        s += 1;
    }
    t
}

/// The transition table, indexed `[state][byte class]`.
const TABLE: [[u16; COLS]; ROWS] = build_table();

const fn build_eof() -> [u16; ROWS] {
    let mut t = [done(TRUNCATED); ROWS];
    t[S_START as usize] = done(NONE);
    t[S_C0 as usize] = done(INVALID);
    t
}

/// What end of input means in each state: a truncated sequence, except
/// between characters (nothing) and after a lone `C0` or `C1` (an invalid
/// byte, since no sequence can ever complete from it).
const EOF: [u16; ROWS] = build_eof();

/// Violation tally, updated without data-dependent branches.
#[derive(Debug, Clone, Copy)]
struct Tally {
    count: usize,
    first_off: usize,
    first_code: usize,
    seen: u16,
}

impl Tally {
    #[inline(always)]
    fn record(&mut self, code: u16, off: usize) {
        let has = usize::from(code != 0);
        let is_first = has & usize::from(self.count == 0);
        let m = 0usize.wrapping_sub(is_first);
        self.first_off = (off & m) | (self.first_off & !m);
        self.first_code = (usize::from(code) & m) | (self.first_code & !m);
        // Bit 0 collects "no violation" and is masked off when read.
        self.seen |= 1u16 << (code & REASON_BITS);
        self.count = self.count.saturating_add(has);
    }
}

/// Result of a completed scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScanResult {
    pub(crate) scanned: usize,
    pub(crate) count: usize,
    pub(crate) first: Option<(usize, Reason)>,
    pub(crate) seen: ReasonSet,
}

/// The automaton's whole run-time state: a few integers, whatever the input.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Dfa {
    state: u8,
    seq_start: usize,
    pos: usize,
    tally: Tally,
}

impl Dfa {
    pub(crate) const fn new() -> Self {
        Self {
            state: S_START,
            seq_start: 0,
            pos: 0,
            tally: Tally {
                count: 0,
                first_off: 0,
                first_code: 0,
                seen: 0,
            },
        }
    }

    /// Bytes consumed so far.
    pub(crate) const fn pos(&self) -> usize {
        self.pos
    }

    /// Consume `chunk`. One pass, every byte, no early exit.
    pub(crate) fn scan(&mut self, chunk: &[u8]) {
        let mut state = self.state;
        let mut seq_start = self.seq_start;
        let mut pos = self.pos;
        let mut tally = self.tally;
        for &b in chunk {
            let e = TABLE[usize::from(state) & (ROWS - 1)]
                [usize::from(CLASS[usize::from(b)]) & (COLS - 1)];
            tally.record((e >> PEND_SHIFT) & REASON_BITS, seq_start);
            tally.record((e >> CUR_SHIFT) & REASON_BITS, pos);
            let m = 0usize.wrapping_sub(usize::from(e & START_BIT != 0));
            seq_start = (pos & m) | (seq_start & !m);
            state = (e & NEXT_MASK) as u8;
            pos = pos.saturating_add(1);
        }
        self.state = state;
        self.seq_start = seq_start;
        self.pos = pos;
        self.tally = tally;
    }

    /// Apply end of input and report.
    pub(crate) fn finish(mut self) -> ScanResult {
        let e = EOF[usize::from(self.state) & (ROWS - 1)];
        self.tally
            .record((e >> PEND_SHIFT) & REASON_BITS, self.seq_start);
        let t = self.tally;
        let first = if t.count > 0 {
            u8::try_from(t.first_code)
                .ok()
                .and_then(Reason::from_code)
                .map(|r| (t.first_off, r))
        } else {
            None
        };
        ScanResult {
            scanned: self.pos,
            count: t.count,
            first,
            seen: ReasonSet::from_bits(t.seen),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next(e: u16) -> u8 {
        (e & NEXT_MASK) as u8
    }

    #[test]
    fn class_partition_is_exact() {
        // Every (state, byte) behaves exactly as the specification says, so
        // compressing bytes into classes lost nothing.
        for s in 0..STATE_COUNT {
            for b in 0..=255u8 {
                let via_table = TABLE[s as usize][CLASS[b as usize] as usize];
                assert_eq!(via_table, step(s, b), "state {s} byte {b:#04x}");
            }
        }
    }

    #[test]
    fn class_count_is_small() {
        assert_eq!(CLASS_COUNT, 53, "class count changed; update the docs");
    }

    #[test]
    fn every_reachable_next_state_is_real() {
        for s in 0..STATE_COUNT {
            for b in 0..=255u8 {
                assert!(next(step(s, b)) < STATE_COUNT);
            }
            assert_eq!(next(EOF[s as usize]), S_START);
        }
    }

    #[test]
    fn start_entries_carry_no_pending_reason() {
        // abort() relies on this to compose "pending + start(b)".
        for b in 0..=255u8 {
            assert_eq!((start(b) >> PEND_SHIFT) & REASON_BITS, 0);
        }
    }

    #[test]
    fn start_entries_never_both_flag_and_report() {
        for b in 0..=255u8 {
            let e = start(b);
            let cur = (e >> CUR_SHIFT) & REASON_BITS;
            assert!(!(cur != 0 && e & START_BIT != 0), "byte {b:#04x}");
        }
    }

    #[test]
    fn reason_codes_fit_the_field() {
        for r in Reason::ALL {
            assert!(u16::from(r as u8) <= REASON_BITS);
        }
    }
}
