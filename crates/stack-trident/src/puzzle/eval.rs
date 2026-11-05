//! Offline evaluation harness for [`RuleInspector`].
//!
//! **Status: tooling, not a defense.** The inspector is a supplemental layer
//! (see `RULE_INSPECTOR_EVAL.md`). This module measures how many labelled
//! examples it flags. It reads rows, runs a fixed evidence configuration over
//! them and builds a deterministic JSON report. File access lives in the
//! `rules_eval` example; nothing here touches the file system.
//!
//! A corpus row is one JSON object per line:
//!
//! - `id`, `family`, `label` (`hostile` or `benign`), `provenance`,
//!   `added_commit`;
//! - exactly one of `text` (a string), `text_b64` (standard base64 of the raw
//!   bytes) or `parts` (an array of strings inspected in order, the way the
//!   gate would, each with the tails of the parts that passed before it);
//! - optional `lookback` (how many earlier parts are shown; default 3).
//!
//! Counting: a hostile row is a true positive when the inspector says
//! `Hostile` (for `parts`, on any part); `Suspicious` and `Pass` are false
//! negatives. A benign row is a false positive only on `Hostile`;
//! `Suspicious` is counted apart.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::inspect::{Finding, InspectInput, Inspector};
use super::piece::PuzzleId;
use super::rules::{RuleConfig, RuleInspector};
use crate::keys::Fingerprint;

/// Default number of earlier parts shown to the inspector for a `parts` row.
pub const DEFAULT_LOOKBACK: usize = 3;

/// Why a corpus could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvalError {
    /// A line is not valid JSON or is missing a field.
    #[error("{set}:{line}: {why}")]
    Row {
        /// The corpus file stem.
        set: String,
        /// One-based line number.
        line: usize,
        /// What is wrong.
        why: String,
    },
    /// The inspector for the evidence configuration could not be built.
    #[error("evidence inspector: {0}")]
    Inspector(String),
}

/// A row's ground truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    /// The row is an attack the inspector should flag.
    Hostile,
    /// The row is ordinary text the inspector should leave alone.
    Benign,
}

/// What the inspector is shown for one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// One whole.
    Single(Vec<u8>),
    /// Several wholes, in order.
    Parts(Vec<Vec<u8>>),
}

/// One labelled example.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The corpus file stem the row came from.
    pub set: String,
    /// Row id.
    pub id: String,
    /// Family (`plain_injection`, `homoglyph`, ...).
    pub family: String,
    /// Ground truth.
    pub label: Label,
    /// What is inspected.
    pub input: Input,
    /// How many earlier parts are shown (parts rows only).
    pub lookback: usize,
}

impl Row {
    // The raw text of a row, joined, for classification.
    fn all_text(&self) -> String {
        match &self.input {
            Input::Single(b) => String::from_utf8_lossy(b).into_owned(),
            Input::Parts(p) => p.iter().map(|b| String::from_utf8_lossy(b).into_owned()).collect::<Vec<_>>().join(""),
        }
    }

    /// Number of cuts: parts minus one; 0 for a single whole.
    pub fn cuts(&self) -> usize {
        match &self.input {
            Input::Single(_) => 0,
            Input::Parts(p) => p.len().saturating_sub(1),
        }
    }
}

fn b64_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Standard base64 (with padding) to bytes. `None` on any malformed input.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut acc = 0u32;
        for (k, c) in chunk.iter().enumerate() {
            let v = if k >= 4 - pad { if *c == b'=' { 0 } else { return None } } else { b64_value(*c)? };
            acc = (acc << 6) | v;
        }
        let triple = [(acc >> 16) as u8, (acc >> 8) as u8, acc as u8];
        out.extend_from_slice(&triple[..3 - pad]);
    }
    Some(out)
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 15), 16).unwrap_or('0'));
    }
    s
}

/// Parses one corpus file. Blank lines are skipped.
pub fn parse_rows(set: &str, jsonl: &str) -> Result<Vec<Row>, EvalError> {
    let mut rows = Vec::new();
    for (n, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fail = |why: &str| EvalError::Row { set: set.to_owned(), line: n + 1, why: why.to_owned() };
        let v: Value = serde_json::from_str(line).map_err(|e| fail(&e.to_string()))?;
        let text_field = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let id = text_field("id").ok_or_else(|| fail("missing id"))?;
        let family = text_field("family").ok_or_else(|| fail("missing family"))?;
        let label = match text_field("label").as_deref() {
            Some("hostile") => Label::Hostile,
            Some("benign") => Label::Benign,
            _ => return Err(fail("label must be hostile or benign")),
        };
        for k in ["provenance", "added_commit"] {
            if text_field(k).is_none() {
                return Err(fail(&format!("missing {k}")));
            }
        }
        let input = match (v.get("text"), v.get("text_b64"), v.get("parts")) {
            (Some(t), None, None) => Input::Single(t.as_str().ok_or_else(|| fail("text must be a string"))?.as_bytes().to_vec()),
            (None, Some(t), None) => Input::Single(
                base64_decode(t.as_str().ok_or_else(|| fail("text_b64 must be a string"))?)
                    .ok_or_else(|| fail("text_b64 is not valid base64"))?,
            ),
            (None, None, Some(p)) => {
                let arr = p.as_array().ok_or_else(|| fail("parts must be an array"))?;
                let mut parts = Vec::with_capacity(arr.len());
                for item in arr {
                    parts.push(item.as_str().ok_or_else(|| fail("a part must be a string"))?.as_bytes().to_vec());
                }
                if parts.len() < 2 {
                    return Err(fail("parts needs at least two parts"));
                }
                Input::Parts(parts)
            }
            _ => return Err(fail("exactly one of text, text_b64, parts is required")),
        };
        let lookback = match v.get("lookback") {
            None => DEFAULT_LOOKBACK,
            Some(l) => l.as_u64().and_then(|l| usize::try_from(l).ok()).ok_or_else(|| fail("lookback must be a number"))?,
        };
        rows.push(Row { set: set.to_owned(), id, family, label, input, lookback });
    }
    Ok(rows)
}

/// The fixed configuration every number in the report is measured with: the
/// default rules plus two operator deny markers.
pub fn evidence_inspector() -> Result<RuleInspector, EvalError> {
    RuleInspector::new(evidence_config()).map_err(|e| EvalError::Inspector(e.to_string()))
}

/// The deny markers of the evidence configuration.
pub const EVIDENCE_DENY: [&str; 2] = ["TROJAN", "EXFIL-TOKEN"];

/// The evidence configuration.
pub fn evidence_config() -> RuleConfig {
    RuleConfig { deny_patterns: EVIDENCE_DENY.iter().map(|s| (*s).to_owned()).collect(), ..RuleConfig::default() }
}

/// What the inspector said about a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// `Hostile` on any part.
    pub hostile: bool,
    /// `Suspicious` on any part and not hostile on any.
    pub suspicious: bool,
}

/// Runs one row through an inspector.
pub fn evaluate_row(inspector: &RuleInspector, row: &Row) -> Verdict {
    let Some(sender) = Fingerprint::from_hex(&"ab".repeat(32)) else {
        return Verdict { hostile: false, suspicious: false };
    };
    let puzzle = PuzzleId::from_bytes([7; 16]);
    let (mut hostile, mut suspicious) = (false, false);
    let mut note = |f: Finding| match f {
        Finding::Hostile(_) => hostile = true,
        Finding::Suspicious(_) => suspicious = true,
        Finding::Pass => {}
    };
    match &row.input {
        Input::Single(whole) => note(inspector.inspect(&InspectInput { sender: &sender, puzzle, whole, history: &[] })),
        Input::Parts(parts) => {
            let mut history: Vec<Vec<u8>> = Vec::new();
            for part in parts {
                let from = history.len().saturating_sub(row.lookback);
                let f = inspector.inspect(&InspectInput { sender: &sender, puzzle, whole: part, history: &history[from..] });
                if f == Finding::Pass {
                    history.push(part.clone());
                }
                note(f);
            }
        }
    }
    Verdict { hostile, suspicious: suspicious && !hostile }
}

// ---------------------------------------------------------------------------
// Counting
// ---------------------------------------------------------------------------

/// Confusion counts for a group of rows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    /// Hostile rows flagged.
    pub tp: u64,
    /// Hostile rows not flagged.
    pub fn_: u64,
    /// Benign rows flagged.
    pub fp: u64,
    /// Benign rows not flagged.
    pub tn: u64,
    /// Benign rows reported `Suspicious` (shape), not counted as false positives.
    pub benign_suspicious: u64,
}

impl Tally {
    fn add(&mut self, label: Label, v: Verdict) {
        match (label, v.hostile) {
            (Label::Hostile, true) => self.tp += 1,
            (Label::Hostile, false) => self.fn_ += 1,
            (Label::Benign, true) => self.fp += 1,
            (Label::Benign, false) => {
                self.tn += 1;
                if v.suspicious {
                    self.benign_suspicious += 1;
                }
            }
        }
    }

    /// Hostile rows seen.
    pub fn hostile(&self) -> u64 {
        self.tp + self.fn_
    }

    /// Benign rows seen.
    pub fn benign(&self) -> u64 {
        self.fp + self.tn
    }
}

/// Wilson score interval at 95 percent for `k` of `n`. `None` when `n` is 0.
pub fn wilson95(k: u64, n: u64) -> Option<(f64, f64)> {
    if n == 0 {
        return None;
    }
    let z = 1.959_963_984_540_054_f64;
    let (k, n) = (k as f64, n as f64);
    let p = k / n;
    let z2 = z * z;
    let denom = 1.0 + z2 / n;
    let centre = (p + z2 / (2.0 * n)) / denom;
    let half = z * ((p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt()) / denom;
    Some(((centre - half).max(0.0), (centre + half).min(1.0)))
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

fn rate(k: u64, n: u64) -> Value {
    match wilson95(k, n) {
        None => json!({ "k": k, "n": n, "rate": null, "ci95": null }),
        Some((lo, hi)) => json!({ "k": k, "n": n, "rate": round4(k as f64 / n as f64), "ci95": [round4(lo), round4(hi)] }),
    }
}

fn tally_json(t: &Tally) -> Value {
    json!({
        "tp": t.tp, "fn": t.fn_, "fp": t.fp, "tn": t.tn,
        "benign_suspicious": t.benign_suspicious,
        "recall": rate(t.tp, t.hostile()),
        "false_positive_rate": rate(t.fp, t.benign()),
    })
}

// ---------------------------------------------------------------------------
// Unicode classes of a row's text (independent of the rules)
// ---------------------------------------------------------------------------

fn in_any(c: u32, ranges: &[(u32, u32)]) -> bool {
    ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&c))
}

/// The Unicode classes present in `text`, by this harness's own ranges. These
/// are independent of the inspector's tables on purpose, so a wrong table in
/// the rules cannot hide behind a matching wrong table here.
pub fn unicode_classes(text: &str) -> BTreeSet<&'static str> {
    let mut out = BTreeSet::new();
    let mut singles = 0usize;
    let mut best_run = 0usize;
    let mut tok_len = 0usize;
    let mut tok_alpha = true;
    let flush = |len: usize, alpha: bool, singles: &mut usize, best: &mut usize| {
        if len == 1 && alpha {
            *singles += 1;
            *best = (*best).max(*singles);
        } else if len > 0 {
            *singles = 0;
        }
    };
    let bytes = text.as_bytes();
    for (i, c) in text.char_indices() {
        let u = c as u32;
        if c.is_alphanumeric() {
            tok_len += 1;
            tok_alpha &= c.is_alphabetic();
        } else {
            flush(tok_len, tok_alpha, &mut singles, &mut best_run);
            tok_len = 0;
            tok_alpha = true;
        }
        if c == '_' {
            out.insert("underscore");
        }
        if c == '%' && bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit) && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit) {
            out.insert("percent_escape");
        }
        if c == '&' && bytes.get(i + 1) == Some(&b'#') {
            out.insert("html_entity");
        }
        if u < 0x80 {
            if u == 0 || (u < 0x20 && !matches!(c, '\t' | '\n' | '\r')) || u == 0x7F {
                out.insert("control_char");
            }
            continue;
        }
        let class = if in_any(u, &[(0x200E, 0x200F), (0x202A, 0x202E), (0x2066, 0x2069), (0x061C, 0x061C)]) {
            "bidi_control"
        } else if in_any(u, &[(0x200B, 0x200D), (0x2060, 0x2064), (0xFEFF, 0xFEFF), (0x00AD, 0x00AD), (0x180E, 0x180E)]) {
            "zero_width_format"
        } else if in_any(u, &[(0xFE00, 0xFE0F), (0xE0100, 0xE01EF), (0x180B, 0x180D)]) {
            "variation_selector"
        } else if in_any(u, &[(0xE0000, 0xE007F)]) {
            "tag_character"
        } else if in_any(u, &[(0xFFF9, 0xFFFB)]) {
            "interlinear_annotation"
        } else if in_any(u, &[(0x3164, 0x3164), (0x115F, 0x1160), (0xFFA0, 0xFFA0)]) {
            "hangul_filler"
        } else if in_any(u, &[(0x0300, 0x036F), (0x1AB0, 0x1AFF), (0x1DC0, 0x1DFF), (0x20D0, 0x20FF), (0xFE20, 0xFE2F)]) {
            "combining_mark"
        } else if in_any(u, &[(0xFF01, 0xFF5E)]) {
            "fullwidth_form"
        } else if in_any(u, &[(0x1D400, 0x1D7FF)]) {
            "math_alphanumeric"
        } else if in_any(u, &[(0x24B6, 0x24E9)]) {
            "enclosed_alphanumeric"
        } else if in_any(u, &[(0x0400, 0x04FF)]) {
            "cyrillic"
        } else if in_any(u, &[(0x0370, 0x03FF)]) {
            "greek"
        } else if in_any(u, &[(0x00C0, 0x017F)]) {
            "latin_accented"
        } else {
            "other_non_ascii"
        };
        out.insert(class);
    }
    flush(tok_len, tok_alpha, &mut singles, &mut best_run);
    if best_run >= 4 {
        out.insert("single_letter_spelling");
    }
    out
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// Builds the report section for a set of rows: totals, per family, per file,
/// split-phrase coverage by cuts, per Unicode class, and the ids of every
/// false negative and false positive.
pub fn report_rows(inspector: &RuleInspector, rows: &[Row]) -> Value {
    let mut total = Tally::default();
    let mut families: BTreeMap<String, Tally> = BTreeMap::new();
    let mut sets: BTreeMap<String, Tally> = BTreeMap::new();
    let mut cuts: BTreeMap<usize, (u64, u64)> = BTreeMap::new();
    let mut classes_h: BTreeMap<&'static str, (u64, u64)> = BTreeMap::new();
    let mut classes_b: BTreeMap<&'static str, (u64, u64)> = BTreeMap::new();
    let (mut fns, mut fps) = (Vec::new(), Vec::new());
    for row in rows {
        let v = evaluate_row(inspector, row);
        total.add(row.label, v);
        families.entry(row.family.clone()).or_default().add(row.label, v);
        sets.entry(row.set.clone()).or_default().add(row.label, v);
        match (row.label, v.hostile) {
            (Label::Hostile, false) => fns.push(format!("{}/{}", row.set, row.id)),
            (Label::Benign, true) => fps.push(format!("{}/{}", row.set, row.id)),
            _ => {}
        }
        if row.cuts() > 0 && row.label == Label::Hostile {
            let e = cuts.entry(row.cuts()).or_insert((0, 0));
            e.0 += 1;
            e.1 += u64::from(v.hostile);
        }
        for class in unicode_classes(&row.all_text()) {
            let target = if row.label == Label::Hostile { &mut classes_h } else { &mut classes_b };
            let e = target.entry(class).or_insert((0, 0));
            e.0 += 1;
            e.1 += u64::from(v.hostile);
        }
    }
    let map_tally = |m: &BTreeMap<String, Tally>| -> Value {
        Value::Object(m.iter().map(|(k, t)| (k.clone(), tally_json(t))).collect::<Map<_, _>>())
    };
    let map_pairs = |m: &BTreeMap<&'static str, (u64, u64)>, caught_key: &str| -> Value {
        Value::Object(
            m.iter()
                .map(|(k, (n, c))| ((*k).to_owned(), json!({ "rows": n, caught_key: c })))
                .collect::<Map<_, _>>(),
        )
    };
    json!({
        "rows": rows.len(),
        "totals": tally_json(&total),
        "families": map_tally(&families),
        "sets": map_tally(&sets),
        "split_phrase_by_cuts": Value::Object(
            cuts.iter().map(|(k, (n, c))| (k.to_string(), json!({ "rows": n, "caught": c }))).collect::<Map<_, _>>()
        ),
        "unicode_class_hostile": map_pairs(&classes_h, "caught"),
        "unicode_class_benign": map_pairs(&classes_b, "flagged"),
        "false_negatives": fns,
        "false_positives": fps,
    })
}

/// The evidence configuration as JSON, for the report header.
pub fn config_json() -> Value {
    let c = evidence_config();
    json!({
        "deny_patterns": c.deny_patterns,
        "deny_through_spacing": c.deny_through_spacing,
        "injection_phrases": c.injection_phrases,
        "harmful_build": c.harmful_build,
        "lookback_head_bytes": c.lookback_head_bytes,
        "max_whole_bytes": c.max_whole_bytes,
        "max_control_percent": c.max_control_percent,
        "binary_allowed": c.binary_allowed,
    })
}
