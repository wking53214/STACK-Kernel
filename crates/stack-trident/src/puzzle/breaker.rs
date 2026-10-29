//! Per-sender state: the breaker with a free allowance, the quarantine that
//! ends by itself, the count of open puzzles, and the tails of recently
//! released wholes kept for look-back.

use std::collections::VecDeque;

use super::config::PuzzleConfig;

#[derive(Debug, Default)]
pub(crate) struct SenderState {
    breaches: VecDeque<u64>,
    quarantined_until: Option<u64>,
    pub(crate) open: usize,
    pub(crate) history: VecDeque<Vec<u8>>,
}

/// Breaches inside the window at which a sender is quarantined: the free
/// allowance plus the threshold.
fn quarantine_at(cfg: &PuzzleConfig) -> usize {
    usize::try_from(u64::from(cfg.breaker_free) + u64::from(cfg.breaker_threshold)).unwrap_or(usize::MAX)
}

impl SenderState {
    /// The end of the quarantine if one is running at `now`. An ended
    /// quarantine is cleared.
    pub(crate) fn quarantine_remaining(&mut self, now: u64) -> Option<u64> {
        match self.quarantined_until {
            Some(until) if now < until => Some(until),
            Some(_) => {
                self.quarantined_until = None;
                None
            }
            None => None,
        }
    }

    /// Counts a breach. Returns true when this breach started a quarantine.
    /// The first `breaker_free` breaches inside the window cost nothing.
    pub(crate) fn record_breach(&mut self, now: u64, cfg: &PuzzleConfig) -> bool {
        while let Some(&t) = self.breaches.front() {
            if now.saturating_sub(t) >= cfg.breaker_window_ms {
                self.breaches.pop_front();
            } else {
                break;
            }
        }
        self.breaches.push_back(now);
        let limit = quarantine_at(cfg);
        while self.breaches.len() > limit {
            self.breaches.pop_front();
        }
        if self.breaches.len() >= limit && self.quarantine_remaining(now).is_none() {
            self.quarantined_until = Some(now.saturating_add(cfg.quarantine_ms));
            self.breaches.clear();
            return true;
        }
        false
    }

    /// Nothing worth keeping: no open puzzle, no quarantine, no recent breach.
    pub(crate) fn is_idle(&self, now: u64, cfg: &PuzzleConfig) -> bool {
        self.open == 0
            && self.quarantined_until.is_none_or(|u| now >= u)
            && self.breaches.back().is_none_or(|&t| now.saturating_sub(t) >= cfg.breaker_window_ms)
    }

    /// Keeps the trailing bytes of a released whole for look-back.
    pub(crate) fn push_history(&mut self, whole: &[u8], cfg: &PuzzleConfig) {
        if cfg.lookback_wholes == 0 {
            return;
        }
        let start = whole.len().saturating_sub(cfg.history_tail_bytes);
        self.history.push_back(whole.get(start..).unwrap_or(&[]).to_vec());
        while self.history.len() > cfg.lookback_wholes {
            self.history.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PuzzleConfig {
        PuzzleConfig { breaker_free: 3, breaker_threshold: 3, breaker_window_ms: 1_000, quarantine_ms: 5_000, ..PuzzleConfig::default() }
    }

    #[test]
    fn the_first_breaches_are_free_and_the_sixth_quarantines() {
        let (mut s, c) = (SenderState::default(), cfg());
        for i in 0..5 {
            assert!(!s.record_breach(100 + i, &c), "breach {} must be free or counted, not quarantining", i + 1);
            assert_eq!(s.quarantine_remaining(100 + i), None);
        }
        assert!(s.record_breach(105, &c), "free 3 + threshold 3 = the sixth breach");
        assert_eq!(s.quarantine_remaining(106), Some(105 + 5_000));
    }

    #[test]
    fn a_quarantine_ends_by_itself_and_the_slate_is_clean() {
        let (mut s, c) = (SenderState::default(), cfg());
        for i in 0..6 {
            s.record_breach(100 + i, &c);
        }
        assert!(s.quarantine_remaining(4_000).is_some());
        assert_eq!(s.quarantine_remaining(5_105), None, "ends exactly at the stated time");
        assert!(!s.record_breach(5_106, &c), "the free allowance is back");
    }

    #[test]
    fn breaches_outside_the_window_do_not_add_up() {
        let (mut s, c) = (SenderState::default(), cfg());
        for i in 0..50 {
            assert!(!s.record_breach(i * 1_000, &c), "one breach per window is never enough");
        }
    }

    #[test]
    fn a_breach_during_a_quarantine_does_not_restart_it() {
        let (mut s, c) = (SenderState::default(), cfg());
        for i in 0..6 {
            s.record_breach(100 + i, &c);
        }
        let until = s.quarantine_remaining(200);
        for t in 200..220 {
            assert!(!s.record_breach(t, &c));
        }
        assert_eq!(s.quarantine_remaining(300), until);
    }

    #[test]
    fn idle_means_no_open_puzzle_no_quarantine_and_no_recent_breach() {
        let (mut s, c) = (SenderState::default(), cfg());
        assert!(s.is_idle(0, &c));
        s.open = 1;
        assert!(!s.is_idle(0, &c));
        s.open = 0;
        s.record_breach(10, &c);
        assert!(!s.is_idle(500, &c));
        assert!(s.is_idle(1_010, &c));
    }

    #[test]
    fn history_keeps_only_tails_of_the_last_few_wholes() {
        let c = PuzzleConfig { lookback_wholes: 2, history_tail_bytes: 3, ..PuzzleConfig::default() };
        let mut s = SenderState::default();
        for w in [b"aaaa1".as_slice(), b"bbbb2", b"cccc3"] {
            s.push_history(w, &c);
        }
        let h: Vec<&[u8]> = s.history.iter().map(Vec::as_slice).collect();
        assert_eq!(h, vec![b"bb2".as_slice(), b"cc3"]);
        let off = PuzzleConfig { lookback_wholes: 0, ..PuzzleConfig::default() };
        let mut t = SenderState::default();
        t.push_history(b"xyz", &off);
        assert!(t.history.is_empty());
    }
}
