//! The inspector: the one place that decides whether an assembled whole is
//! hostile. The gate decides where to look; the inspector decides what is
//! seen. There is no default inspector, because a gate that inspects nothing
//! looks like protection and is none.

use std::fmt;

use super::piece::PuzzleId;
use crate::keys::Fingerprint;

/// What the gate shows the inspector.
#[derive(Debug, Clone, Copy)]
pub struct InspectInput<'a> {
    /// The authenticated sender of the puzzle.
    pub sender: &'a Fingerprint,
    /// The puzzle being released.
    pub puzzle: PuzzleId,
    /// The assembled whole, pieces joined in index order.
    pub whole: &'a [u8],
    /// The trailing bytes of this sender's last released wholes, oldest
    /// first. At most `lookback_wholes` entries of at most
    /// `history_tail_bytes` each. Empty when look-back is off or the sender
    /// has released nothing yet.
    pub history: &'a [Vec<u8>],
}

/// An inspector's finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finding {
    /// Nothing found; release the whole.
    Pass,
    /// Something looks wrong but the inspector is not sure. The puzzle is
    /// destroyed and the sender takes no breach, so a false alarm cannot push
    /// an honest sender toward quarantine.
    Suspicious(&'static str),
    /// The whole is hostile. The puzzle is destroyed and the sender takes a
    /// breach.
    Hostile(&'static str),
}

/// Decides whether an assembled whole may leave.
///
/// An implementation may be slow; it runs while the gate holds its lock, so
/// a slow inspector slows the whole gate. A panic inside it poisons the lock
/// and the gate then refuses everything (it fails closed).
pub trait Inspector: Send + Sync + fmt::Debug {
    /// Looks at a whole, with the tails of the sender's recent wholes.
    fn inspect(&self, input: &InspectInput<'_>) -> Finding;
}

/// Why a [`DenyListInspector`] could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DenyListError {
    /// No patterns were given.
    #[error("the pattern list is empty")]
    NoPatterns,
    /// A pattern is empty, which would match everything.
    #[error("a pattern is empty")]
    EmptyPattern,
}

/// A reference inspector: refuses any whole that contains one of a list of
/// byte patterns, including a pattern that straddles the join with the
/// retained tails of earlier wholes.
///
/// This is a tripwire, not a classifier. It sees exactly the bytes it is
/// told about and misses any paraphrase, encoding or novel form. It exists to
/// show the gate working and to be replaced.
#[derive(Debug, Clone)]
pub struct DenyListInspector {
    patterns: Vec<Vec<u8>>,
    longest: usize,
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

impl DenyListInspector {
    /// An inspector for these patterns. Each must be non-empty.
    pub fn new(patterns: Vec<Vec<u8>>) -> Result<Self, DenyListError> {
        if patterns.is_empty() {
            return Err(DenyListError::NoPatterns);
        }
        if patterns.iter().any(Vec::is_empty) {
            return Err(DenyListError::EmptyPattern);
        }
        let longest = patterns.iter().map(Vec::len).max().unwrap_or(0);
        Ok(Self { patterns, longest })
    }
}

impl Inspector for DenyListInspector {
    fn inspect(&self, input: &InspectInput<'_>) -> Finding {
        if self.patterns.iter().any(|p| contains(input.whole, p)) {
            return Finding::Hostile("deny-list pattern in the whole");
        }
        if !input.history.is_empty() {
            // Only the start of the whole can complete a pattern begun in the
            // tails, so only that much is joined.
            let head = input.whole.get(..self.longest.saturating_sub(1).min(input.whole.len())).unwrap_or(&[]);
            let mut joined: Vec<u8> = input.history.concat();
            joined.extend_from_slice(head);
            if self.patterns.iter().any(|p| contains(&joined, p)) {
                return Finding::Hostile("deny-list pattern across a join");
            }
        }
        Finding::Pass
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fp() -> Fingerprint {
        Fingerprint::from_hex(&"ab".repeat(32)).unwrap()
    }

    fn run(i: &DenyListInspector, whole: &[u8], history: &[Vec<u8>]) -> Finding {
        let sender = fp();
        i.inspect(&InspectInput { sender: &sender, puzzle: PuzzleId::from_bytes([1; 16]), whole, history })
    }

    fn inspector() -> DenyListInspector {
        DenyListInspector::new(vec![b"TROJAN".to_vec(), b"EVIL".to_vec()]).unwrap()
    }

    #[test]
    fn construction_refuses_empty_input() {
        assert_eq!(DenyListInspector::new(vec![]).unwrap_err(), DenyListError::NoPatterns);
        assert_eq!(DenyListInspector::new(vec![b"x".to_vec(), vec![]]).unwrap_err(), DenyListError::EmptyPattern);
    }

    #[test]
    fn a_pattern_inside_the_whole_is_hostile() {
        assert_eq!(run(&inspector(), b"hello TROJAN world", &[]), Finding::Hostile("deny-list pattern in the whole"));
        assert_eq!(run(&inspector(), b"hello world", &[]), Finding::Pass);
    }

    #[test]
    fn a_pattern_split_across_a_join_is_seen_through_the_tails() {
        let tails = vec![b"...TRO".to_vec()];
        assert_eq!(run(&inspector(), b"JAN and more", &tails), Finding::Hostile("deny-list pattern across a join"));
        assert_eq!(run(&inspector(), b"JAN and more", &[]), Finding::Pass, "without the tails the second half is harmless");
    }

    #[test]
    fn a_pattern_split_over_three_wholes_needs_three_tails() {
        let two = vec![b"xx TR".to_vec(), b"OJ".to_vec()];
        assert_eq!(run(&inspector(), b"AN", &two), Finding::Hostile("deny-list pattern across a join"));
        let one = vec![b"OJ".to_vec()];
        assert_eq!(run(&inspector(), b"AN", &one), Finding::Pass, "a look-back that is too short misses it");
    }

    #[test]
    fn only_the_head_of_a_long_whole_is_joined_to_the_tails() {
        let tails = vec![b"TRO".to_vec()];
        let mut whole = b"JAN".to_vec();
        whole.extend(std::iter::repeat_n(b'z', 100_000));
        assert!(matches!(run(&inspector(), &whole, &tails), Finding::Hostile(_)));
    }

    #[test]
    fn a_paraphrase_is_not_seen() {
        assert_eq!(run(&inspector(), b"T R O J A N", &[]), Finding::Pass);
    }
}
