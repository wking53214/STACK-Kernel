//! The typed verdict the inlet returns, in the CNS gate vocabulary.
//!
//! The enums here mirror `cns.gate` in the CNS repository
//! (`/home/user/CNS/cns/gate.py`): [`GatePosition`] is `ALPHA` or `OMEGA`,
//! and [`GateOutcome`] is `PASS`, `RETRY` or `TERMINAL_BREACH`, with the same
//! string values. They are re-declared here, not imported, because CNS is a
//! Python package; the string values are what must agree across languages.

use core::fmt;

/// Name this gate reports itself under, for a caller building a CNS
/// `GateResult` from a [`Verdict`].
pub const GATE_NAME: &str = "tack_inlet";

/// Which end of a decision a gate belongs to (CNS `GatePosition`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GatePosition {
    /// Runs before execution; failure means the work never starts.
    Alpha,
    /// Runs on the produced result; failure means the result does not leave.
    Omega,
}

impl GatePosition {
    /// The CNS string value (`"alpha"` or `"omega"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alpha => "alpha",
            Self::Omega => "omega",
        }
    }
}

/// A verdict, in increasing order of finality (CNS `GateOutcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GateOutcome {
    /// Nothing objected.
    Pass,
    /// Repairable: the caller may resubmit with a correction.
    Retry,
    /// Abort: no correction repairs it.
    TerminalBreach,
}

impl GateOutcome {
    /// The CNS string value, also used as the `outcome` metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Retry => "retry",
            Self::TerminalBreach => "terminal_breach",
        }
    }
}

/// What happens to state when a check trips (kernel convention 1).
///
/// The inlet only ever produces [`Resolution::Reject`] and
/// [`Resolution::Quarantine`]. It holds no state of its own, so there is
/// nothing to roll back, and it never halts: if a single hostile input could
/// stop the inlet, the inlet would itself be a denial-of-service lever. The
/// other two variants exist so every STACK component shares one vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resolution {
    /// Nothing changed; the input is refused.
    Reject,
    /// The input is refused and marked for review, and the quarantine counter
    /// is incremented. The inlet has no sender identity, so isolating the
    /// sender or agent is the caller's job, using this verdict as the signal.
    Quarantine,
    /// State restored to the last good snapshot. Never produced by the inlet.
    Rollback,
    /// The component stops accepting work until an operator resets it. Never
    /// produced by the inlet.
    Halt,
}

impl Resolution {
    /// Stable lower-case name, for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Quarantine => "quarantine",
            Self::Rollback => "rollback",
            Self::Halt => "halt",
        }
    }
}

/// Why the inlet refused an input. A closed set, safe to use as a metric label.
///
/// The numeric codes (1 to 14) are stable. Codes 1 to 11 and 13 are the values
/// stored in the automaton's transition table; code 0 means "no violation"
/// and has no variant. The reason set is a 16-bit mask, so code 15 is the
/// last one available.
///
/// The banned characters are fixed sets from Unicode 16.0: the
/// `Default_Ignorable_Code_Point` property, the `Bidi_Control` property, the
/// general category `Cc` controls, the noncharacters, and a few named
/// additions (U+2028, U+2029, U+FFF9..U+FFFB).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Reason {
    /// NUL or another C0 control (U+0000 to U+001F) other than tab, LF, CR.
    C0Control = 1,
    /// DEL (U+007F), a C1 control (U+0080 to U+009F), or the Unicode line
    /// and paragraph separators U+2028 and U+2029. The separators are not C1
    /// controls, but JavaScript, many log viewers and terminals treat them as
    /// line breaks, exactly like the C1 control NEL (U+0085), so they share
    /// its reason rather than taking a new one.
    DelOrC1Control = 2,
    /// A bidirectional override or isolate, U+202A to U+202E or U+2066 to
    /// U+2069: the Trojan Source class, text that displays in a different
    /// order from the order a parser reads it.
    BidiControl = 3,
    /// An invisible character: one that renders as nothing and so can carry
    /// content a human reviewer does not see. The set is every
    /// `Default_Ignorable_Code_Point` in Unicode 16.0 except the twelve
    /// `Bidi_Control` characters (which have their own reasons), plus the
    /// interlinear annotation controls U+FFF9..U+FFFB:
    ///
    /// U+00AD, U+034F, U+115F, U+1160, U+17B4, U+17B5, U+180B..U+180F,
    /// U+200B..U+200D, U+2060..U+2065, U+206A..U+206F, U+3164,
    /// U+FE00..U+FE0F, U+FEFF, U+FFA0, U+FFF0..U+FFFB, U+1BCA0..U+1BCA3,
    /// U+1D173..U+1D17A, U+E0000..U+E0FFF.
    ///
    /// That includes the tag characters (U+E0000..U+E007F, "ASCII
    /// smuggling"), all 256 variation selectors (U+FE00..U+FE0F and
    /// U+E0100..U+E01EF, "emoji smuggling") and the Hangul fillers. Every
    /// variation selector is banned, including U+FE0F, which ordinary emoji
    /// use (a red heart is U+2764 U+FE0F): capping selectors at one per base
    /// character would still leave a 4-bit hidden channel per visible
    /// character. Such text draws `RETRY`; a deployment that needs emoji
    /// strips the selectors before the inlet. The subdivision flag emoji
    /// (England, Scotland, Wales) are built from tag characters and draw
    /// `RETRY` for the same reason, which is also why this reason is not
    /// terminal. The metric label stays `zero_width` for compatibility.
    ZeroWidth = 4,
    /// A Unicode noncharacter: U+FDD0 to U+FDEF, or U+xFFFE / U+xFFFF in any
    /// plane.
    Noncharacter = 5,
    /// An overlong encoding: a code point written with more bytes than it
    /// needs (lead byte C0 or C1 followed by a continuation byte, E0 followed
    /// by 80..9F, F0 followed by 80..8F). No conforming encoder produces one; the classic use is to
    /// sneak a character such as `/` past a byte-level filter.
    Overlong = 6,
    /// A UTF-16 surrogate (U+D800 to U+DFFF) encoded as UTF-8 (ED followed by
    /// A0..BF). Produced by CESU-8 and WTF-8 encoders; not valid UTF-8.
    Surrogate = 7,
    /// A sequence that would encode a code point above U+10FFFF (F4 followed
    /// by 90..BF, or a lead byte F5, F6 or F7).
    AboveMax = 8,
    /// A byte that never appears in UTF-8 in any position: F8 to FF, or a
    /// lone C0 or C1 that is not followed by a continuation byte. A lone C0
    /// or C1 cannot disguise anything in any decoder; it is what Latin-1
    /// text (capital A with grave or acute accent) looks like when it is
    /// mislabelled as UTF-8, so it is repairable rather than overlong.
    InvalidByte = 9,
    /// A continuation byte (80..BF) where a character should start.
    UnexpectedContinuation = 10,
    /// A multi-byte sequence cut short, by a non-continuation byte or by the
    /// end of the input.
    Truncated = 11,
    /// The input is longer than the configured cap. Decided on length alone,
    /// before any body byte is read. Never produced by the automaton.
    Oversize = 12,
    /// One of the three implicit directional marks of the `Bidi_Control`
    /// property: ARABIC LETTER MARK (U+061C), LEFT-TO-RIGHT MARK (U+200E)
    /// and RIGHT-TO-LEFT MARK (U+200F). They cannot reorder letters, but they
    /// do change the display order of neutral runs (digits, punctuation,
    /// file extensions). Honest right-to-left text often contains them, so
    /// they are repairable, unlike the overrides and isolates of
    /// [`Reason::BidiControl`]. Together the two reasons cover all 12
    /// `Bidi_Control` characters.
    BidiMark = 13,
    /// A stream arrived in more chunks than
    /// [`crate::StreamConfig::max_chunks`] allows. Decided on the chunk count
    /// alone. Never produced by the automaton.
    ChunkLimit = 14,
}

impl Reason {
    /// Every reason, in code order.
    pub const ALL: [Reason; 14] = [
        Reason::C0Control,
        Reason::DelOrC1Control,
        Reason::BidiControl,
        Reason::ZeroWidth,
        Reason::Noncharacter,
        Reason::Overlong,
        Reason::Surrogate,
        Reason::AboveMax,
        Reason::InvalidByte,
        Reason::UnexpectedContinuation,
        Reason::Truncated,
        Reason::Oversize,
        Reason::BidiMark,
        Reason::ChunkLimit,
    ];

    /// Stable snake-case name, used as the `reason` metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::C0Control => "c0_control",
            Self::DelOrC1Control => "del_or_c1_control",
            Self::BidiControl => "bidi_control",
            Self::ZeroWidth => "zero_width",
            Self::Noncharacter => "noncharacter",
            Self::Overlong => "overlong",
            Self::Surrogate => "surrogate",
            Self::AboveMax => "above_max",
            Self::InvalidByte => "invalid_byte",
            Self::UnexpectedContinuation => "unexpected_continuation",
            Self::Truncated => "truncated",
            Self::Oversize => "oversize",
            Self::BidiMark => "bidi_mark",
            Self::ChunkLimit => "chunk_limit",
        }
    }

    /// The outcome this reason forces on its own.
    ///
    /// Two reasons are terminal: [`Reason::BidiControl`] and
    /// [`Reason::Overlong`]. Both are forms whose main known use is
    /// deception (text that reads differently from how it parses, and a
    /// character disguised from byte-level filters), so "fix it and resend"
    /// is not the right answer to them. Every other reason is something an
    /// honest but buggy client produces (a split buffer, a mislabelled
    /// encoding, a pasted terminal escape, a BOM from an editor, a
    /// zero-width joiner or variation selector inside an emoji, a
    /// right-to-left mark), so it is repairable.
    #[must_use]
    pub const fn severity(self) -> GateOutcome {
        match self {
            Self::BidiControl | Self::Overlong => GateOutcome::TerminalBreach,
            _ => GateOutcome::Retry,
        }
    }

    /// The state resolution that goes with [`Reason::severity`].
    #[must_use]
    pub const fn resolution(self) -> Resolution {
        match self.severity() {
            GateOutcome::TerminalBreach => Resolution::Quarantine,
            _ => Resolution::Reject,
        }
    }

    /// Reason for a table code, or `None` for 0 and unknown codes.
    pub(crate) const fn from_code(code: u8) -> Option<Reason> {
        match code {
            1 => Some(Self::C0Control),
            2 => Some(Self::DelOrC1Control),
            3 => Some(Self::BidiControl),
            4 => Some(Self::ZeroWidth),
            5 => Some(Self::Noncharacter),
            6 => Some(Self::Overlong),
            7 => Some(Self::Surrogate),
            8 => Some(Self::AboveMax),
            9 => Some(Self::InvalidByte),
            10 => Some(Self::UnexpectedContinuation),
            11 => Some(Self::Truncated),
            12 => Some(Self::Oversize),
            13 => Some(Self::BidiMark),
            14 => Some(Self::ChunkLimit),
            _ => None,
        }
    }

    const fn bit(self) -> u16 {
        1u16 << (self as u8)
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Bit mask of the reasons whose severity is terminal.
pub(crate) const TERMINAL_MASK: u16 = Reason::BidiControl.bit() | Reason::Overlong.bit();

/// Bit mask of every valid reason code (bits 1 to 14).
const VALID_MASK: u16 = 0b0111_1111_1111_1110;

/// The set of distinct reasons found in one input. Fixed size (16 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ReasonSet(u16);

impl ReasonSet {
    /// Build from raw bits, discarding any bit that is not a reason code.
    pub(crate) const fn from_bits(bits: u16) -> Self {
        Self(bits & VALID_MASK)
    }

    /// Raw bits: bit `n` is set when the reason with code `n` was seen.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether `reason` was seen.
    #[must_use]
    pub const fn contains(self, reason: Reason) -> bool {
        self.0 & reason.bit() != 0
    }

    /// Whether no reason was seen.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Number of distinct reasons seen (at most 14).
    #[must_use]
    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// The reasons seen, in code order. Always walks the 14 codes.
    pub fn iter(self) -> impl Iterator<Item = Reason> {
        Reason::ALL.into_iter().filter(move |r| self.contains(*r))
    }
}

/// The inlet's decision on one input.
///
/// Fields are private and there is no public constructor: a verdict can only
/// come out of the inlet, so a caller cannot hand-build a PASS and point it at
/// arbitrary content. When the body was read, [`Verdict::sha256`] records the
/// full digest of exactly the bytes judged, so a caller can bind the verdict
/// to its subject (the CNS `subject_digest` idea).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    outcome: GateOutcome,
    resolution: Option<Resolution>,
    reason: Option<Reason>,
    first_offset: Option<usize>,
    count: usize,
    reasons: ReasonSet,
    len: usize,
    scanned: usize,
    sha256: Option<[u8; 32]>,
}

impl Verdict {
    /// Verdict for an input refused on length alone.
    ///
    /// `len` is the declared or offered length, which the sender chose. It is
    /// clamped to `max_len + 1` ("more than the cap"), so the verdict and the
    /// telemetry built from it never carry an attacker-sized number.
    pub(crate) fn oversize(len: usize, max_len: usize, scanned: usize) -> Self {
        let clamped = len.min(max_len.saturating_add(1));
        Self::stopped(Reason::Oversize, clamped, max_len, scanned)
    }

    /// Verdict for a stream refused on its chunk count alone. `len` is the
    /// number of bytes offered, which is within the length cap.
    pub(crate) fn chunk_limit(len: usize, scanned: usize) -> Self {
        Self::stopped(Reason::ChunkLimit, len, scanned, scanned)
    }

    fn stopped(reason: Reason, len: usize, first_offset: usize, scanned: usize) -> Self {
        Self {
            outcome: reason.severity(),
            resolution: Some(reason.resolution()),
            reason: Some(reason),
            first_offset: Some(first_offset),
            count: 1,
            reasons: ReasonSet::from_bits(reason.bit()),
            len,
            scanned,
            sha256: None,
        }
    }

    /// Verdict from a completed automaton scan.
    pub(crate) fn from_scan(
        len: usize,
        scanned: usize,
        count: usize,
        first: Option<(usize, Reason)>,
        seen: ReasonSet,
        sha256: [u8; 32],
    ) -> Self {
        let (outcome, resolution) = if seen.bits() & TERMINAL_MASK != 0 {
            (GateOutcome::TerminalBreach, Some(Resolution::Quarantine))
        } else if count > 0 {
            (GateOutcome::Retry, Some(Resolution::Reject))
        } else {
            (GateOutcome::Pass, None)
        };
        Self {
            outcome,
            resolution,
            reason: first.map(|(_, r)| r),
            first_offset: first.map(|(o, _)| o),
            count,
            reasons: seen,
            len,
            scanned,
            sha256: Some(sha256),
        }
    }

    /// The gate outcome. `TerminalBreach` if any terminal reason was seen
    /// anywhere in the input, else `Retry` if anything was seen, else `Pass`
    /// (the CNS `resolve` precedence applied within one input).
    #[must_use]
    pub const fn outcome(&self) -> GateOutcome {
        self.outcome
    }

    /// Whether the input may cross the boundary.
    #[must_use]
    pub fn is_pass(&self) -> bool {
        self.outcome == GateOutcome::Pass
    }

    /// The state resolution, `None` on a pass.
    #[must_use]
    pub const fn resolution(&self) -> Option<Resolution> {
        self.resolution
    }

    /// Reason for the first violation by byte offset, `None` on a pass.
    ///
    /// This is the first violation, not necessarily the one that decided the
    /// outcome: an input whose first problem is a stray BOM and whose later
    /// problem is a bidi override reports `ZeroWidth` here and
    /// `TerminalBreach` as its outcome. [`Verdict::reasons`] has all of them.
    #[must_use]
    pub const fn reason(&self) -> Option<Reason> {
        self.reason
    }

    /// Byte offset where the first violation starts, `None` on a pass.
    ///
    /// For a banned character or a malformed sequence this is the offset of
    /// its first byte. For [`Reason::Oversize`] it is the configured cap, the
    /// offset of the first byte past the limit. For [`Reason::ChunkLimit`] it
    /// is the number of bytes scanned before the chunk cap was passed.
    #[must_use]
    pub const fn first_offset(&self) -> Option<usize> {
        self.first_offset
    }

    /// Number of violations found. Malformed UTF-8 is counted once per
    /// maximal ill-formed subpart, the same way the Rust standard library and
    /// the WHATWG decoder place replacement characters.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Every distinct reason seen.
    #[must_use]
    pub const fn reasons(&self) -> ReasonSet {
        self.reasons
    }

    /// Input length in bytes.
    ///
    /// For a [`Reason::Oversize`] refusal this is clamped to the configured
    /// cap plus one, meaning "more than the cap": the true declared or
    /// offered length is attacker-chosen and is not kept. With the cap at
    /// most [`crate::MAX_LEN_CEILING`], this value always fits in 32 bits.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the input was empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes the automaton actually examined. Equal to [`Verdict::len`] for
    /// every input within the cap, whatever it contains: the scan never stops
    /// early. Zero for a one-shot oversize refusal; for a stream stopped by a
    /// cap, the bytes scanned before it was passed.
    #[must_use]
    pub const fn scanned(&self) -> usize {
        self.scanned
    }

    /// Full SHA-256 of the bytes judged, or `None` when the input was refused
    /// on length and its body was not read in full.
    #[must_use]
    pub const fn sha256(&self) -> Option<&[u8; 32]> {
        self.sha256.as_ref()
    }

    /// The digest as 64 lower-case hex characters (never truncated).
    #[must_use]
    pub fn sha256_hex(&self) -> Option<String> {
        self.sha256.as_ref().map(|d| Sha256Hex(d).to_string())
    }

    /// Where this gate sits: always [`GatePosition::Alpha`], because the
    /// inlet runs before any work starts.
    #[must_use]
    pub const fn position(&self) -> GatePosition {
        GatePosition::Alpha
    }
}

/// Displays a SHA-256 digest as full lower-case hex without allocating.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sha256Hex<'a>(pub(crate) &'a [u8; 32]);

impl fmt::Display for Sha256Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
