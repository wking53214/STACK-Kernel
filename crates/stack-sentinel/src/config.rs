//! Caps on everything the verifier reads or holds, and the few places where
//! it is deliberately stricter than the Python witness.

use crate::pyjson::ParseLimits;

/// Every bound the verifier enforces. Nothing is sized by a number read
/// from the input: the parser allocates at most in proportion to the input,
/// and the input is capped here before parsing starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifierConfig {
    /// Largest export accepted, in bytes. Default 64 MiB. An export over
    /// the cap is refused by its length alone, before it is hashed or read.
    ///
    /// Memory: the parsed tree may take at most
    /// `json.alloc_bytes_per_input_byte` (default 12) times the export size,
    /// plus `json.alloc_floor_bytes` (1 MiB), by the reader's own upper-bound
    /// count; an export that would take more is refused as unreadable. Only
    /// the `format` and `rows` members are built. Verification adds little
    /// on top, because the canonical form borrows the parsed values and
    /// every hash and HMAC is streamed. Peak memory added by verification is
    /// therefore at most about twelve times the export size (measured: about
    /// six to seven times for ordinary rows, under eleven times for the
    /// worst hostile shapes), so at most about 770 MiB at this default, plus
    /// the export bytes the caller already holds.
    pub max_export_bytes: usize,
    /// Largest anchor accepted, in bytes. Default 64 KiB; a real anchor is
    /// about 300 bytes. An anchor over the cap is `TRUNCATED`
    /// (`anchor_unreadable`), as an unreadable anchor is in Python, and is
    /// refused by its length alone, before it is hashed.
    pub max_anchor_bytes: usize,
    /// Most rows accepted in one export. Default 1,000,000.
    pub max_rows: usize,
    /// Most keys accepted from one key file. Default 64.
    pub max_keys: usize,
    /// Largest key file accepted, in bytes. Default 1 MiB.
    pub max_key_file_bytes: usize,
    /// Most bytes one export may feed to HMAC-SHA256, summed over every
    /// seed and signature check and every key each is tried under. Default
    /// 512 MiB, about one to two seconds of work. An export that needs more
    /// is refused with `VerifyError::KeyedWorkOverBudget` (RETRY, reject)
    /// before any row is checked. Honest exports need far less: an `abv2`
    /// or `abv3` signature names its key and is checked once; only legacy
    /// bare-digest signatures and seeds are tried under every held key.
    pub max_keyed_bytes: usize,
    /// Accept a row signature that is valid only under a retired key.
    /// Default `false`: such a signature is `UNATTESTED`
    /// (`signature_retired_key`, TERMINAL_BREACH), as `sentinel_os`'s
    /// `ledger_postgres.verify_chain` treats a retired-key signature under
    /// enforcement, which is on by default. `sentinel_os`'s `twin_custody`
    /// witness, and so the Python offline tool, accepts it; `true` restores
    /// that. An operator who still trusts old signatures under a rotated key
    /// should list that key as previous (trusted), not retired.
    pub accept_retired_key_signatures: bool,
    /// Accept a head anchor sealed with a retired key. Default `false`: such
    /// an anchor is `TRUNCATED` (`anchor_retired_key`, RETRY, reject): the
    /// auditor should obtain an anchor sealed with a current key. The Python
    /// tool accepts it; `true` restores that.
    pub accept_retired_key_anchor: bool,
    /// Fewest rows a genuine anchor must seal for it to vouch for a
    /// non-empty chain. Default 1: an anchor sealing zero rows (one written
    /// at ledger setup, say) makes no claim, so it is `TRUNCATED`
    /// (`anchor_makes_no_claim`, RETRY, reject) instead of `VERIFIED`. The
    /// Python tool prints `VERIFIED` for it; 0 restores that. A higher value
    /// refuses an anchor older than that many rows, which limits how far
    /// back an attacker can cut a chain by replaying an old, genuine anchor.
    pub min_anchor_entries: u64,
    /// JSON nesting, integer-length and allocation caps. Defaults: depth
    /// 256, 4300 digits, 12 bytes of tree per byte of input plus 1 MiB.
    pub json: ParseLimits,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        VerifierConfig {
            max_export_bytes: 64 * 1024 * 1024,
            max_anchor_bytes: 64 * 1024,
            max_rows: 1_000_000,
            max_keys: 64,
            max_key_file_bytes: 1024 * 1024,
            max_keyed_bytes: 512 * 1024 * 1024,
            accept_retired_key_signatures: false,
            accept_retired_key_anchor: false,
            min_anchor_entries: 1,
            json: ParseLimits::default(),
        }
    }
}

impl VerifierConfig {
    /// The default caps with the three Python behaviours restored: retired
    /// keys accepted for signatures and anchors, and a zero-entry anchor
    /// accepted. With this configuration the verifier prints the same
    /// verdict as `tools/verify_receipts.py` on every input the differential
    /// suite covers. It is for parity testing, not for audits.
    pub fn python_compatible() -> Self {
        VerifierConfig {
            accept_retired_key_signatures: true,
            accept_retired_key_anchor: true,
            min_anchor_entries: 0,
            ..VerifierConfig::default()
        }
    }
}
