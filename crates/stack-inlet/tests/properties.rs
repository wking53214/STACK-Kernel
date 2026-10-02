//! Property tests: 10,000 cases each, against the slow reference.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{classify_char, reference};
use proptest::prelude::*;
use stack_inlet::{GateOutcome, Inlet, InletConfig, Reason, Verdict, MAX_LEN_CEILING};

const CASES: u32 = 10_000;

fn inlet() -> Inlet {
    Inlet::new(InletConfig {
        max_len: MAX_LEN_CEILING,
    })
    .unwrap()
}

/// Any scalar value, with banned ones replaced, biased towards the
/// multi-byte ranges that share prefixes with banned characters.
fn clean_char() -> impl Strategy<Value = char> {
    prop_oneof![
        any::<char>(),
        (0x20u32..0x7F).prop_map(|u| char::from_u32(u).unwrap()),
        (0x2000u32..0x2080).prop_map(|u| char::from_u32(u).unwrap()),
        (0xFDC0u32..=0xFFFF).prop_filter_map("scalar", char::from_u32),
        (0u32..=0x10FFFF).prop_filter_map("scalar", char::from_u32),
        Just('\t'),
        Just('\n'),
        Just('\r'),
    ]
    .prop_map(|c| if classify_char(c).is_some() { 'x' } else { c })
}

fn clean_string() -> impl Strategy<Value = String> {
    proptest::collection::vec(clean_char(), 0..64).prop_map(|v| v.into_iter().collect())
}

fn banned_char() -> impl Strategy<Value = char> {
    let ranges: Vec<(u32, u32)> = vec![
        (0x00, 0x08),
        (0x0B, 0x0C),
        (0x0E, 0x1F),
        (0x7F, 0x9F),
        (0x202A, 0x202E),
        (0x2066, 0x2069),
        (0x200B, 0x200D),
        (0x2060, 0x2060),
        (0xFEFF, 0xFEFF),
        (0xFDD0, 0xFDEF),
        (0x2028, 0x2029),
        (0x061C, 0x061C),
        (0x200E, 0x200F),
        (0x00AD, 0x00AD),
        (0x034F, 0x034F),
        (0x115F, 0x1160),
        (0x17B4, 0x17B5),
        (0x180B, 0x180F),
        (0x2061, 0x2065),
        (0x206A, 0x206F),
        (0x3164, 0x3164),
        (0xFE00, 0xFE0F),
        (0xFFA0, 0xFFA0),
        (0xFFF0, 0xFFFB),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0000, 0xE0FFF),
    ];
    let listed = proptest::sample::select(ranges)
        .prop_flat_map(|(lo, hi)| lo..=hi)
        .prop_map(|u| char::from_u32(u).unwrap());
    let plane_end = (0u32..=16, 0u32..=1)
        .prop_map(|(plane, low)| char::from_u32((plane << 16) | 0xFFFE | low).unwrap());
    prop_oneof![listed, plane_end]
}

/// Fragments that exercise every state of the automaton, including the
/// broken and truncated forms.
fn fragment() -> impl Strategy<Value = Vec<u8>> {
    let fixed: Vec<Vec<u8>> = vec![
        vec![0xE2, 0x80, 0xAE],
        vec![0xE2, 0x80, 0x8B],
        vec![0xE2, 0x81, 0xA0],
        vec![0xE2, 0x81, 0xA6],
        vec![0xEF, 0xBB, 0xBF],
        vec![0xEF, 0xB7, 0x90],
        vec![0xEF, 0xBF, 0xBE],
        vec![0xF0, 0x9F, 0xBF, 0xBF],
        vec![0xF4, 0x8F, 0xBF, 0xBE],
        vec![0xF3, 0xAF, 0xBF, 0xBD],
        vec![0xC2, 0x85],
        vec![0xC2, 0xAD],
        vec![0xCD, 0x8F],
        vec![0xD8, 0x9C],
        vec![0xE1, 0x85, 0x9F],
        vec![0xE1, 0xA0, 0x8E],
        vec![0xE2, 0x80, 0xA8],
        vec![0xE3, 0x85, 0xA4],
        vec![0xEF, 0xB8, 0x8F],
        vec![0xEF, 0xBE, 0xA0],
        vec![0xEF, 0xBF, 0xB9],
        vec![0xF0, 0x9B, 0xB2, 0xA0],
        vec![0xF0, 0x9D, 0x85, 0xB3],
        vec![0xF3, 0xA0, 0x80, 0x81],
        vec![0xF3, 0xA0, 0x84, 0x80],
        vec![0xF3, 0xA0],
        vec![0xC0, b' '],
        vec![0xC2, 0xA0],
        vec![0xC0, 0xAF],
        vec![0xE0, 0x80, 0xAF],
        vec![0xF0, 0x80, 0x80, 0xAF],
        vec![0xED, 0xA0, 0x80],
        vec![0xED, 0x9F, 0xBF],
        vec![0xF4, 0x90, 0x80, 0x80],
        vec![0xF5, 0x80],
        vec![0xFF],
        vec![0x80],
        vec![0xE2],
        vec![0xE2, 0x80],
        vec![0xEF, 0xBF],
        vec![0xF0, 0x9F],
        vec![0xF0, 0x9F, 0xBF],
        vec![0x00],
        vec![0x7F],
        vec![b'a'],
        vec![b'\n'],
    ];
    prop_oneof![
        proptest::sample::select(fixed),
        proptest::collection::vec(any::<u8>(), 1..4),
        any::<char>().prop_map(|c| c.to_string().into_bytes()),
    ]
}

fn mixed_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..256),
        proptest::collection::vec(fragment(), 0..24).prop_map(|v| v.concat()),
        (
            clean_string(),
            proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4)
        )
            .prop_map(|(s, edits)| {
                let mut b = s.into_bytes();
                if b.is_empty() {
                    b.push(b'a');
                }
                for (i, v) in edits {
                    let at = i.index(b.len());
                    b[at] = v;
                }
                b
            }),
    ]
}

fn assert_matches_reference(v: &Verdict, bytes: &[u8]) -> Result<(), TestCaseError> {
    let exp = reference(bytes);
    prop_assert_eq!(v.count(), exp.count(), "count for {:02x?}", bytes);
    prop_assert_eq!(
        v.first_offset().zip(v.reason()),
        exp.first(),
        "first for {:02x?}",
        bytes
    );
    let got: Vec<Reason> = v.reasons().iter().collect();
    prop_assert_eq!(got, exp.reasons(), "reasons for {:02x?}", bytes);
    prop_assert_eq!(v.scanned(), bytes.len());
    let terminal = exp
        .violations
        .iter()
        .any(|(_, r)| r.severity() == GateOutcome::TerminalBreach);
    let want = if terminal {
        GateOutcome::TerminalBreach
    } else if exp.count() > 0 {
        GateOutcome::Retry
    } else {
        GateOutcome::Pass
    };
    prop_assert_eq!(v.outcome(), want);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: CASES, ..ProptestConfig::default() })]

    #[test]
    fn clean_utf8_passes(s in clean_string()) {
        let v = inlet().winnow(s.as_bytes());
        prop_assert_eq!(v.outcome(), GateOutcome::Pass, "{:?}", s);
        prop_assert_eq!(v.count(), 0);
        prop_assert!(v.reason().is_none() && v.first_offset().is_none());
        prop_assert!(v.resolution().is_none());
    }

    #[test]
    fn any_banned_code_point_fails(
        s in clean_string(),
        c in banned_char(),
        at in any::<prop::sample::Index>(),
    ) {
        let boundaries: Vec<usize> =
            s.char_indices().map(|(i, _)| i).chain(std::iter::once(s.len())).collect();
        let pos = boundaries[at.index(boundaries.len())];
        let mut t = s.clone();
        t.insert(pos, c);
        let v = inlet().winnow(t.as_bytes());
        let want = classify_char(c).unwrap();
        prop_assert_ne!(v.outcome(), GateOutcome::Pass);
        prop_assert_eq!(v.count(), 1);
        prop_assert_eq!(v.first_offset(), Some(pos));
        prop_assert_eq!(v.reason(), Some(want));
        prop_assert_eq!(v.outcome(), want.severity());
    }

    #[test]
    fn dfa_agrees_with_reference(bytes in mixed_bytes()) {
        let v = inlet().winnow(&bytes);
        assert_matches_reference(&v, &bytes)?;
    }

    #[test]
    fn chunking_does_not_change_the_verdict(
        bytes in mixed_bytes(),
        cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..6),
    ) {
        let inlet = inlet();
        let whole = inlet.winnow(&bytes);
        let mut points: Vec<usize> = cuts.iter().map(|c| c.index(bytes.len() + 1)).collect();
        points.sort_unstable();
        let mut sc = inlet.scanner();
        let mut last = 0;
        for p in points.into_iter().chain(std::iter::once(bytes.len())) {
            prop_assert_eq!(sc.feed(&bytes[last..p]), tack_inlet::Feed::Continue);
            last = p;
        }
        prop_assert_eq!(sc.finish(), whole);
    }

    #[test]
    fn oversize_is_refused_on_length(extra in 1usize..64, fill in any::<u8>(), cap in 1usize..256) {
        let inlet = Inlet::new(InletConfig { max_len: cap }).unwrap();
        let v = inlet.winnow(&vec![fill; cap + extra]);
        prop_assert_eq!(v.outcome(), GateOutcome::Retry);
        prop_assert_eq!(v.reason(), Some(Reason::Oversize));
        prop_assert_eq!(v.first_offset(), Some(cap));
        prop_assert_eq!(v.scanned(), 0);
        prop_assert!(v.sha256().is_none());
    }
}
