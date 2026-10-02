//! Hand-written cases: one or more per banned class and per malformed form,
//! plus exhaustive sweeps that complement the random property tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{banned_chars, classify_char, reference};
use stack_inlet::{
    Feed, GateOutcome, GatePosition, Inlet, InletConfig, Reason, Resolution, Verdict,
    BYTE_CLASS_COUNT, MAX_LEN_CEILING,
};

fn inlet() -> Inlet {
    Inlet::new(InletConfig::default()).unwrap()
}

fn judge(b: &[u8]) -> Verdict {
    inlet().winnow(b)
}

/// Assert the full list of violations, in order, via the reference and the
/// verdict's summary fields.
fn expect(b: &[u8], violations: &[(usize, Reason)]) -> Verdict {
    let v = judge(b);
    let exp = reference(b);
    assert_eq!(
        exp.violations, violations,
        "reference disagrees with the hand case {b:02x?}"
    );
    assert_eq!(v.count(), violations.len(), "count for {b:02x?}");
    assert_eq!(
        v.first_offset().zip(v.reason()),
        violations.first().copied(),
        "first for {b:02x?}"
    );
    v
}

// ---------- passing input ----------

#[test]
fn plain_text_and_allowed_whitespace_pass() {
    for s in [
        "",
        "a",
        "hello, world",
        "tab\there",
        "lf\n",
        "crlf\r\n",
        "caf\u{e9}",
        "\u{4e2d}\u{6587}",
        "\u{1F600}",
        "\u{10FFFD}",
        "\u{FDCF}",
        "\u{FDF0}",
        "\u{FFFD}",
        "\u{200A}",
    ] {
        let v = judge(s.as_bytes());
        assert!(v.is_pass(), "{s:?}: {v:?}");
        assert_eq!(v.resolution(), None);
        assert_eq!(v.position(), GatePosition::Alpha);
        assert_eq!(v.scanned(), s.len());
        assert_eq!(v.sha256_hex().unwrap().len(), 64);
    }
}

#[test]
fn boundaries_next_to_banned_ranges_pass() {
    for c in [
        '\u{A0}',
        '\u{200A}',
        '\u{202F}',
        '\u{205F}',
        '\u{FDCF}',
        '\u{FDF0}',
        '\u{FEFE}',
        '\u{FFFD}',
        '\u{1FFFD}',
        '\u{10FFFD}',
        '\u{D7FF}',
        '\u{E000}',
    ] {
        assert!(
            judge(c.to_string().as_bytes()).is_pass(),
            "U+{:04X}",
            c as u32
        );
    }
}

// ---------- banned classes ----------

#[test]
fn nul_and_c0_controls_are_refused() {
    for b in (0x00u8..=0x1F).filter(|b| !matches!(b, 0x09 | 0x0A | 0x0D)) {
        let v = expect(&[b'a', b], &[(1, Reason::C0Control)]);
        assert_eq!(v.outcome(), GateOutcome::Retry);
        assert_eq!(v.resolution(), Some(Resolution::Reject));
    }
}

#[test]
fn del_and_c1_controls_are_refused() {
    expect(&[0x7F], &[(0, Reason::DelOrC1Control)]);
    for u in 0x80u32..=0x9F {
        let s = char::from_u32(u).unwrap().to_string();
        let v = expect(s.as_bytes(), &[(0, Reason::DelOrC1Control)]);
        assert_eq!(v.outcome(), GateOutcome::Retry);
    }
}

#[test]
fn bidi_overrides_and_isolates_are_terminal() {
    for u in (0x202Au32..=0x202E).chain(0x2066..=0x2069) {
        let s = format!("ab{}", char::from_u32(u).unwrap());
        let v = expect(s.as_bytes(), &[(2, Reason::BidiControl)]);
        assert_eq!(v.outcome(), GateOutcome::TerminalBreach);
        assert_eq!(v.resolution(), Some(Resolution::Quarantine));
    }
}

#[test]
fn zero_width_and_bom_are_refused() {
    for u in [0x200Bu32, 0x200C, 0x200D, 0x2060, 0xFEFF] {
        let s = char::from_u32(u).unwrap().to_string();
        let v = expect(s.as_bytes(), &[(0, Reason::ZeroWidth)]);
        assert_eq!(v.outcome(), GateOutcome::Retry);
    }
}

#[test]
fn noncharacters_are_refused_in_every_plane() {
    for u in 0xFDD0u32..=0xFDEF {
        let s = char::from_u32(u).unwrap().to_string();
        expect(s.as_bytes(), &[(0, Reason::Noncharacter)]);
    }
    for plane in 0u32..=16 {
        for low in [0xFFFE, 0xFFFF] {
            let s = char::from_u32((plane << 16) | low).unwrap().to_string();
            let v = expect(s.as_bytes(), &[(0, Reason::Noncharacter)]);
            assert_eq!(v.outcome(), GateOutcome::Retry);
        }
    }
}

#[test]
fn invisible_characters_are_refused() {
    let list: &[u32] = &[
        0x00AD, 0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180E, 0x180F, 0x2061, 0x2064,
        0x2065, 0x206A, 0x206F, 0x3164, 0xFE00, 0xFE0F, 0xFFA0, 0xFFF0, 0xFFF8, 0xFFF9, 0xFFFB,
        0x1BCA0, 0x1BCA3, 0x1D173, 0x1D17A, 0xE0000, 0xE0001, 0xE0041, 0xE007F, 0xE0100,
        0xE01EF, 0xE0FFF,
    ];
    for &u in list {
        let s = format!("ab{}", char::from_u32(u).unwrap());
        let v = expect(s.as_bytes(), &[(2, Reason::ZeroWidth)]);
        assert_eq!(v.outcome(), GateOutcome::Retry, "U+{u:04X}");
        assert_eq!(v.resolution(), Some(Resolution::Reject), "U+{u:04X}");
    }
}

#[test]
fn bidi_marks_are_refused_as_repairable() {
    for u in [0x061Cu32, 0x200E, 0x200F] {
        let s = format!("ab{}", char::from_u32(u).unwrap());
        let v = expect(s.as_bytes(), &[(2, Reason::BidiMark)]);
        assert_eq!(v.outcome(), GateOutcome::Retry);
        assert_eq!(v.resolution(), Some(Resolution::Reject));
    }
}

#[test]
fn line_and_paragraph_separators_are_refused() {
    for u in [0x2028u32, 0x2029] {
        let s = format!("ab{}", char::from_u32(u).unwrap());
        let v = expect(s.as_bytes(), &[(2, Reason::DelOrC1Control)]);
        assert_eq!(v.outcome(), GateOutcome::Retry);
    }
}

#[test]
fn neighbours_of_the_new_banned_ranges_pass() {
    for u in [
        0x00ACu32, 0x00AE, 0x034E, 0x0350, 0x061B, 0x061D, 0x115E, 0x1161, 0x17B3, 0x17B6,
        0x180A, 0x1810, 0x2027, 0x3163, 0x3165, 0xFDFF, 0xFE10, 0xFF9F, 0xFFA1, 0xFFEF, 0xFFFC,
        0x1BC9F, 0x1BCA4, 0x1D172, 0x1D17B, 0xDFFFD, 0xE1000, 0xEFFFD,
    ] {
        let c = char::from_u32(u).unwrap();
        assert!(
            judge(c.to_string().as_bytes()).is_pass(),
            "U+{u:04X} should pass"
        );
    }
}

// ---------- malformed UTF-8 ----------

#[test]
fn lone_c0_and_c1_are_invalid_bytes_not_overlong() {
    // Latin-1 capital A-grave then a space, and A-acute then a letter.
    let v = expect(&[0xC0, b' ', b'x'], &[(0, Reason::InvalidByte)]);
    assert_eq!(v.outcome(), GateOutcome::Retry);
    expect(&[b'x', 0xC1, b'l'], &[(1, Reason::InvalidByte)]);
    // At the end of input, and doubled.
    expect(&[b'x', 0xC0], &[(1, Reason::InvalidByte)]);
    expect(
        &[0xC0, 0xC1, 0xAF],
        &[
            (0, Reason::InvalidByte),
            (1, Reason::Overlong),
            (2, Reason::UnexpectedContinuation),
        ],
    );
    // The same verdict whatever the chunking.
    let inlet = inlet();
    let whole = inlet.winnow(&[0xC0, 0xAF]);
    let mut sc = inlet.scanner();
    assert_eq!(sc.feed(&[0xC0]), Feed::Continue);
    assert_eq!(sc.feed(&[0xAF]), Feed::Continue);
    assert_eq!(sc.finish(), whole);
    assert_eq!(whole.outcome(), GateOutcome::TerminalBreach);
}

#[test]
fn overlong_encodings_are_terminal() {
    // C0 AF: '/' in two bytes. The lead is the violation; AF is then a stray.
    let v = expect(
        &[0xC0, 0xAF],
        &[(0, Reason::Overlong), (1, Reason::UnexpectedContinuation)],
    );
    assert_eq!(v.outcome(), GateOutcome::TerminalBreach);
    expect(
        &[0xC1, 0xBF],
        &[(0, Reason::Overlong), (1, Reason::UnexpectedContinuation)],
    );
    // E0 80 AF: '/' in three bytes.
    expect(
        &[0xE0, 0x80, 0xAF],
        &[
            (0, Reason::Overlong),
            (1, Reason::UnexpectedContinuation),
            (2, Reason::UnexpectedContinuation),
        ],
    );
    expect(
        &[0xE0, 0x9F, 0xBF],
        &[
            (0, Reason::Overlong),
            (1, Reason::UnexpectedContinuation),
            (2, Reason::UnexpectedContinuation),
        ],
    );
    // F0 80 80 AF: '/' in four bytes; F0 8F BF BF: U+FFFF in four bytes.
    expect(
        &[0xF0, 0x80, 0x80, 0xAF],
        &[
            (0, Reason::Overlong),
            (1, Reason::UnexpectedContinuation),
            (2, Reason::UnexpectedContinuation),
            (3, Reason::UnexpectedContinuation),
        ],
    );
    let v = expect(
        &[0xF0, 0x8F, 0xBF, 0xBF],
        &[
            (0, Reason::Overlong),
            (1, Reason::UnexpectedContinuation),
            (2, Reason::UnexpectedContinuation),
            (3, Reason::UnexpectedContinuation),
        ],
    );
    assert_eq!(v.resolution(), Some(Resolution::Quarantine));
    // Smallest legal forms pass.
    assert!(judge(&[0xC2, 0xA0]).is_pass());
    assert!(judge(&[0xE0, 0xA0, 0x80]).is_pass());
    assert!(judge(&[0xF0, 0x90, 0x80, 0x80]).is_pass());
}

#[test]
fn surrogates_are_refused() {
    for (a, b) in [(0xA0u8, 0x80u8), (0xAF, 0xBF), (0xB0, 0x80), (0xBF, 0xBF)] {
        let v = expect(
            &[0xED, a, b],
            &[
                (0, Reason::Surrogate),
                (1, Reason::UnexpectedContinuation),
                (2, Reason::UnexpectedContinuation),
            ],
        );
        assert_eq!(v.outcome(), GateOutcome::Retry);
    }
    assert!(judge(&[0xED, 0x9F, 0xBF]).is_pass(), "U+D7FF is legal");
}

#[test]
fn code_points_above_max_are_refused() {
    let v = expect(
        &[0xF4, 0x90, 0x80, 0x80],
        &[
            (0, Reason::AboveMax),
            (1, Reason::UnexpectedContinuation),
            (2, Reason::UnexpectedContinuation),
            (3, Reason::UnexpectedContinuation),
        ],
    );
    assert_eq!(v.outcome(), GateOutcome::Retry);
    for lead in [0xF5u8, 0xF6, 0xF7] {
        expect(
            &[lead, 0x80, 0x80, 0x80],
            &[
                (0, Reason::AboveMax),
                (1, Reason::UnexpectedContinuation),
                (2, Reason::UnexpectedContinuation),
                (3, Reason::UnexpectedContinuation),
            ],
        );
    }
    for b in 0xF8u8..=0xFF {
        expect(&[b], &[(0, Reason::InvalidByte)]);
    }
    assert!(
        judge(&[0xF4, 0x8F, 0xBF, 0xBD]).is_pass(),
        "U+10FFFD is legal"
    );
}

#[test]
fn truncated_sequences_are_refused() {
    // Cut short by end of input.
    expect(&[b'a', 0xC3], &[(1, Reason::Truncated)]);
    expect(&[0xE2, 0x80], &[(0, Reason::Truncated)]);
    expect(&[0xEF, 0xBF], &[(0, Reason::Truncated)]);
    expect(&[0xF0, 0x9F, 0x98], &[(0, Reason::Truncated)]);
    expect(&[0xF4, 0x8F, 0xBF], &[(0, Reason::Truncated)]);
    // Cut short by a non-continuation byte, which is then judged on its own.
    expect(&[0xE2, 0x80, b'a'], &[(0, Reason::Truncated)]);
    expect(
        &[0xE2, 0x80, 0x00],
        &[(0, Reason::Truncated), (2, Reason::C0Control)],
    );
    expect(
        &[0xC3, 0xE2, 0x80, 0xAE],
        &[(0, Reason::Truncated), (1, Reason::BidiControl)],
    );
    expect(
        &[0xF0, 0x9F, 0x98, 0xF0, 0x9F, 0x98, 0x80],
        &[(0, Reason::Truncated)],
    );
    expect(&[0xE0, b'a'], &[(0, Reason::Truncated)]);
    let v = judge(&[0xE2, 0x80]);
    assert_eq!(v.outcome(), GateOutcome::Retry);
    assert_eq!(v.resolution(), Some(Resolution::Reject));
}

#[test]
fn stray_continuation_bytes_are_refused() {
    expect(&[0x80], &[(0, Reason::UnexpectedContinuation)]);
    expect(
        &[b'a', 0xBF, b'b', 0x80],
        &[
            (1, Reason::UnexpectedContinuation),
            (3, Reason::UnexpectedContinuation),
        ],
    );
    expect(&[0xC3, 0xA9, 0xA9], &[(2, Reason::UnexpectedContinuation)]);
}

// ---------- verdict semantics ----------

#[test]
fn every_violation_is_counted_and_the_first_is_reported() {
    let mut s = String::from("ok");
    s.push('\u{FEFF}'); // offset 2, retry
    s.push_str("..");
    s.push('\u{202E}'); // offset 7, terminal
    s.push('\u{0}'); // offset 10
    let v = judge(s.as_bytes());
    assert_eq!(v.count(), 3);
    assert_eq!(v.first_offset(), Some(2));
    assert_eq!(v.reason(), Some(Reason::ZeroWidth));
    assert_eq!(
        v.outcome(),
        GateOutcome::TerminalBreach,
        "any terminal reason wins"
    );
    assert_eq!(v.resolution(), Some(Resolution::Quarantine));
    let r: Vec<Reason> = v.reasons().iter().collect();
    assert_eq!(
        r,
        vec![Reason::C0Control, Reason::BidiControl, Reason::ZeroWidth]
    );
    assert_eq!(v.scanned(), s.len());
}

#[test]
fn length_cap_is_checked_before_the_body() {
    let inlet = Inlet::new(InletConfig { max_len: 8 }).unwrap();
    assert!(inlet.winnow(b"12345678").is_pass());
    let v = inlet.winnow(b"123456789");
    assert_eq!(v.reason(), Some(Reason::Oversize));
    assert_eq!(v.outcome(), GateOutcome::Retry);
    assert_eq!(v.resolution(), Some(Resolution::Reject));
    assert_eq!(v.first_offset(), Some(8));
    assert_eq!(v.scanned(), 0, "body not read");
    assert!(v.sha256().is_none());
    // A bad body over the cap is refused on length, not content.
    assert_eq!(inlet.winnow(&[0u8; 9]).reason(), Some(Reason::Oversize));
    // Declared-length precheck.
    assert!(inlet.precheck(8).is_ok());
    let e = inlet.precheck(u64::MAX).unwrap_err();
    assert_eq!(e.reason(), Some(Reason::Oversize));
}

#[test]
fn default_cap_is_64_kib() {
    let inlet = inlet();
    assert!(inlet.winnow(&vec![b'a'; 64 * 1024]).is_pass());
    assert_eq!(
        inlet.winnow(&vec![b'a'; 64 * 1024 + 1]).reason(),
        Some(Reason::Oversize)
    );
}

#[test]
fn streaming_cap_stops_scanning() {
    let inlet = Inlet::new(InletConfig { max_len: 10 }).unwrap();
    let mut sc = inlet.scanner();
    assert_eq!(sc.feed(b"12345"), Feed::Continue);
    assert_eq!(sc.feed(b"67890x"), Feed::OverLimit);
    assert_eq!(sc.feed(b"y"), Feed::OverLimit);
    let v = sc.finish();
    assert_eq!(v.reason(), Some(Reason::Oversize));
    assert_eq!(v.scanned(), 5);
    assert_eq!(v.len(), 11, "offered length clamped to the cap plus one");
    assert!(v.sha256().is_none());
}

#[test]
fn sha256_is_of_the_exact_bytes() {
    // SHA-256("abc"), FIPS 180-2 test vector.
    let v = judge(b"abc");
    assert_eq!(
        v.sha256_hex().unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

// ---------- exhaustive sweeps ----------

#[test]
fn every_scalar_value_is_classified_like_the_reference() {
    let inlet = Inlet::new(InletConfig {
        max_len: MAX_LEN_CEILING,
    })
    .unwrap();
    let mut buf = [0u8; 4];
    for u in 0u32..=0x10FFFF {
        let Some(c) = char::from_u32(u) else { continue };
        let v = inlet.winnow(c.encode_utf8(&mut buf).as_bytes());
        match classify_char(c) {
            None => assert!(v.is_pass(), "U+{u:04X}"),
            Some(r) => {
                assert_eq!(v.reason(), Some(r), "U+{u:04X}");
                assert_eq!(v.count(), 1, "U+{u:04X}");
            }
        }
    }
}

#[test]
fn banned_set_has_the_expected_size() {
    // 29 C0 + (33 DEL/C1 + 2 line and paragraph separators) + 9 bidi
    // overrides and isolates + 3 bidi marks + (4174 Default_Ignorable - 12
    // Bidi_Control + 3 interlinear annotation) + 32 + 34 noncharacters.
    assert_eq!(
        banned_chars().len(),
        29 + (33 + 2) + 9 + 3 + (4174 - 12 + 3) + 32 + 34
    );
}

#[test]
fn every_one_and_two_byte_string_matches_the_reference() {
    let inlet = inlet();
    for a in 0..=255u8 {
        let v = inlet.winnow(&[a]);
        let e = reference(&[a]);
        assert_eq!(
            (v.count(), v.first_offset().zip(v.reason())),
            (e.count(), e.first()),
            "{a:02x}"
        );
        for b in 0..=255u8 {
            let bytes = [a, b];
            let v = inlet.winnow(&bytes);
            let e = reference(&bytes);
            assert_eq!(
                (v.count(), v.first_offset().zip(v.reason())),
                (e.count(), e.first()),
                "{bytes:02x?}"
            );
        }
    }
}

#[test]
fn byte_class_count_is_documented() {
    assert_eq!(BYTE_CLASS_COUNT, 53);
}
