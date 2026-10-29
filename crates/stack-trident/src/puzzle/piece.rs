//! The wire form of a puzzle piece: a strict JSON object carried as the
//! payload of a verified envelope. Anything the label does not account for
//! is refused.

use std::fmt;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::config::PuzzleConfig;
use crate::canonical::{decode_hex_lower, to_hex};

/// Domain separator for [`root_of`]. It stops a root from matching a digest
/// made for another purpose.
pub const ROOT_DOMAIN: &[u8] = b"stack-trident/puzzle-root/v1\n";

/// A puzzle's identifier, chosen by its sender. 16 bytes, written as 32
/// lowercase hex characters. Puzzles are namespaced by sender, so two senders
/// may use the same id without touching each other.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PuzzleId([u8; 16]);

impl PuzzleId {
    /// An id from raw bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Parses exactly 32 lowercase hex characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        decode_hex_lower::<16>(s).map(Self)
    }

    /// The id as 32 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for PuzzleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PuzzleId({})", self.to_hex())
    }
}

/// One piece of a puzzle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    /// The puzzle this piece belongs to.
    pub puzzle: PuzzleId,
    /// This piece's place, counted from 0.
    pub index: u32,
    /// How many pieces the puzzle has.
    pub total: u32,
    /// The commitment to the finished picture; see [`root_of`].
    pub root: [u8; 32],
    /// The bytes of this piece. Never empty.
    pub data: Vec<u8>,
}

/// What a verified envelope's payload may say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Add a piece.
    Piece(Piece),
    /// Cancel an open puzzle of this sender.
    Abort(PuzzleId),
}

/// Why a payload is not a puzzle message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PieceError {
    /// The payload is not a JSON object.
    #[error("payload is not a JSON object")]
    NotObject,
    /// The keys are not exactly the keys of the message kind.
    #[error("payload keys are not exactly the keys of its kind")]
    WrongKeys,
    /// `kind` is neither `piece` nor `abort`.
    #[error("`kind` is not `piece` or `abort`")]
    UnknownKind,
    /// A field is missing or not in its exact form.
    #[error("field `{0}` is missing or not in its exact form")]
    BadField(&'static str),
    /// `total` is zero or over the configured limit.
    #[error("`total` is zero or over the limit")]
    TotalOutOfRange,
    /// `index` is not below `total`.
    #[error("`index` is not below `total`")]
    IndexOutOfRange,
    /// `data` is empty or over the piece limit.
    #[error("`data` is empty or over the piece limit")]
    DataSize,
}

const PIECE_KEYS: [&str; 6] = ["kind", "puzzle", "index", "total", "root", "data"];
const ABORT_KEYS: [&str; 2] = ["kind", "puzzle"];

fn exact_keys(obj: &serde_json::Map<String, Value>, keys: &[&str]) -> bool {
    obj.len() == keys.len() && keys.iter().all(|k| obj.contains_key(*k))
}

/// Lowercase hex of any even length to bytes. Upper case, odd length and
/// non-hex characters give `None`, so every byte string has one spelling.
fn decode_hex_vec(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    b.chunks(2)
        .map(|p| match (p.first().and_then(|c| nib(*c)), p.get(1).and_then(|c| nib(*c))) {
            (Some(hi), Some(lo)) => Some((hi << 4) | lo),
            _ => None,
        })
        .collect()
}

fn small_uint(obj: &serde_json::Map<String, Value>, key: &'static str) -> Result<u32, PieceError> {
    obj.get(key)
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(PieceError::BadField(key))
}

fn puzzle_id(obj: &serde_json::Map<String, Value>) -> Result<PuzzleId, PieceError> {
    obj.get("puzzle")
        .and_then(Value::as_str)
        .and_then(PuzzleId::from_hex)
        .ok_or(PieceError::BadField("puzzle"))
}

/// Reads a verified envelope's payload as a puzzle message.
///
/// The work is bounded before any decoding: the length of `data` is compared
/// with the limit first.
pub fn parse_message(payload: &Value, cfg: &PuzzleConfig) -> Result<Message, PieceError> {
    let obj = payload.as_object().ok_or(PieceError::NotObject)?;
    let kind = obj.get("kind").and_then(Value::as_str).ok_or(PieceError::BadField("kind"))?;
    match kind {
        "abort" => {
            if !exact_keys(obj, &ABORT_KEYS) {
                return Err(PieceError::WrongKeys);
            }
            Ok(Message::Abort(puzzle_id(obj)?))
        }
        "piece" => {
            if !exact_keys(obj, &PIECE_KEYS) {
                return Err(PieceError::WrongKeys);
            }
            let puzzle = puzzle_id(obj)?;
            let index = small_uint(obj, "index")?;
            let total = small_uint(obj, "total")?;
            if total == 0 || total > cfg.max_pieces {
                return Err(PieceError::TotalOutOfRange);
            }
            if index >= total {
                return Err(PieceError::IndexOutOfRange);
            }
            let root = obj
                .get("root")
                .and_then(Value::as_str)
                .and_then(decode_hex_lower::<32>)
                .ok_or(PieceError::BadField("root"))?;
            let hex = obj.get("data").and_then(Value::as_str).ok_or(PieceError::BadField("data"))?;
            if hex.is_empty() || hex.len() > cfg.max_piece_bytes.saturating_mul(2) {
                return Err(PieceError::DataSize);
            }
            let data = decode_hex_vec(hex).ok_or(PieceError::BadField("data"))?;
            Ok(Message::Piece(Piece { puzzle, index, total, root, data }))
        }
        _ => Err(PieceError::UnknownKind),
    }
}

/// The commitment to a finished puzzle: SHA-256 over [`ROOT_DOMAIN`] and then
/// the SHA-256 digest of each piece, in index order. The sender states it
/// first; the receiver recomputes it from what it holds. A piece that does
/// not belong, or a missing or swapped piece, makes the two disagree.
pub fn root_of<'a>(pieces: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut outer = Sha256::new();
    outer.update(ROOT_DOMAIN);
    for p in pieces {
        outer.update(Sha256::digest(p));
    }
    outer.finalize().into()
}

/// Why a whole could not be split.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SplitError {
    /// There is nothing to split.
    #[error("the whole is empty")]
    Empty,
    /// The piece size is zero.
    #[error("the piece size is zero")]
    ZeroPieceSize,
    /// The whole needs more pieces than allowed.
    #[error("the whole needs more than the allowed number of pieces")]
    TooManyPieces,
}

/// Cuts `whole` into pieces of at most `piece_bytes` and returns one payload
/// per piece, in index order, ready to be sealed as envelopes. This is the
/// producer's side of the format.
pub fn split(whole: &[u8], piece_bytes: usize, puzzle: PuzzleId, max_pieces: u32) -> Result<Vec<Value>, SplitError> {
    if whole.is_empty() {
        return Err(SplitError::Empty);
    }
    if piece_bytes == 0 {
        return Err(SplitError::ZeroPieceSize);
    }
    let chunks: Vec<&[u8]> = whole.chunks(piece_bytes).collect();
    let total = u32::try_from(chunks.len()).map_err(|_| SplitError::TooManyPieces)?;
    if total > max_pieces {
        return Err(SplitError::TooManyPieces);
    }
    let root = to_hex(&root_of(chunks.iter().copied()));
    Ok(chunks
        .iter()
        .enumerate()
        .map(|(i, c)| {
            json!({"kind": "piece", "puzzle": puzzle.to_hex(), "index": i, "total": total, "root": root, "data": to_hex(c)})
        })
        .collect())
}

/// The payload that cancels an open puzzle.
pub fn abort_payload(puzzle: PuzzleId) -> Value {
    json!({"kind": "abort", "puzzle": puzzle.to_hex()})
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn id() -> PuzzleId {
        PuzzleId::from_bytes([7; 16])
    }

    fn piece_of(v: &Value) -> Piece {
        match parse_message(v, &PuzzleConfig::default()).unwrap() {
            Message::Piece(p) => p,
            Message::Abort(_) => panic!("expected a piece"),
        }
    }

    #[test]
    fn split_then_parse_round_trips_and_the_root_matches() {
        let whole: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let payloads = split(&whole, 300, id(), 64).unwrap();
        assert_eq!(payloads.len(), 4);
        let pieces: Vec<Piece> = payloads.iter().map(piece_of).collect();
        let joined: Vec<u8> = pieces.iter().flat_map(|p| p.data.clone()).collect();
        assert_eq!(joined, whole);
        for (i, p) in pieces.iter().enumerate() {
            assert_eq!(p.index as usize, i);
            assert_eq!(p.total, 4);
            assert_eq!(p.puzzle, id());
        }
        let root = root_of(pieces.iter().map(|p| p.data.as_slice()));
        assert!(pieces.iter().all(|p| p.root == root));
    }

    #[test]
    fn the_root_is_the_documented_construction() {
        let (a, b) = (b"alpha".as_slice(), b"beta".as_slice());
        let mut h = Sha256::new();
        h.update(b"stack-trident/puzzle-root/v1\n");
        h.update(Sha256::digest(a));
        h.update(Sha256::digest(b));
        let expect: [u8; 32] = h.finalize().into();
        assert_eq!(root_of([a, b]), expect);
        assert_ne!(root_of([a, b]), root_of([b, a]), "order matters");
        assert_ne!(root_of([a, b]), root_of([a]), "a missing piece changes the root");
    }

    #[test]
    fn abort_round_trips() {
        let msg = parse_message(&abort_payload(id()), &PuzzleConfig::default()).unwrap();
        assert_eq!(msg, Message::Abort(id()));
    }

    #[test]
    fn splitting_refuses_degenerate_input() {
        assert_eq!(split(b"", 10, id(), 64), Err(SplitError::Empty));
        assert_eq!(split(b"x", 0, id(), 64), Err(SplitError::ZeroPieceSize));
        assert_eq!(split(&[0u8; 100], 1, id(), 64), Err(SplitError::TooManyPieces));
    }

    #[test]
    fn anything_the_label_does_not_account_for_is_refused() {
        let cfg = PuzzleConfig::default();
        let good = split(b"hello world", 4, id(), 64).unwrap()[1].clone();
        assert!(parse_message(&good, &cfg).is_ok());
        let mut cases: Vec<(&str, Value, PieceError)> = Vec::new();
        let edit = |f: &dyn Fn(&mut serde_json::Map<String, Value>)| {
            let mut v = good.clone();
            f(v.as_object_mut().unwrap());
            v
        };
        cases.push(("extra key", edit(&|o| { o.insert("note".into(), json!("hi")); }), PieceError::WrongKeys));
        cases.push(("missing key", edit(&|o| { o.remove("root"); }), PieceError::WrongKeys));
        cases.push(("unknown kind", edit(&|o| { o.insert("kind".into(), json!("blob")); }), PieceError::UnknownKind));
        cases.push(("kind not a string", edit(&|o| { o.insert("kind".into(), json!(1)); }), PieceError::BadField("kind")));
        cases.push(("upper-case id", edit(&|o| { o.insert("puzzle".into(), json!("0A".repeat(16))); }), PieceError::BadField("puzzle")));
        cases.push(("short id", edit(&|o| { o.insert("puzzle".into(), json!("07")); }), PieceError::BadField("puzzle")));
        cases.push(("index is text", edit(&|o| { o.insert("index".into(), json!("1")); }), PieceError::BadField("index")));
        cases.push(("index is a float", edit(&|o| { o.insert("index".into(), json!(1.5)); }), PieceError::BadField("index")));
        cases.push(("index negative", edit(&|o| { o.insert("index".into(), json!(-1)); }), PieceError::BadField("index")));
        cases.push(("index past total", edit(&|o| { o.insert("index".into(), json!(9)); }), PieceError::IndexOutOfRange));
        cases.push(("total zero", edit(&|o| { o.insert("total".into(), json!(0)); }), PieceError::TotalOutOfRange));
        cases.push(("total over limit", edit(&|o| { o.insert("total".into(), json!(65)); }), PieceError::TotalOutOfRange));
        cases.push(("root upper case", edit(&|o| { o.insert("root".into(), json!("A".repeat(64))); }), PieceError::BadField("root")));
        cases.push(("root short", edit(&|o| { o.insert("root".into(), json!("ab")); }), PieceError::BadField("root")));
        cases.push(("data upper case", edit(&|o| { o.insert("data".into(), json!("AB")); }), PieceError::BadField("data")));
        cases.push(("data odd length", edit(&|o| { o.insert("data".into(), json!("abc")); }), PieceError::BadField("data")));
        cases.push(("data not hex", edit(&|o| { o.insert("data".into(), json!("zz")); }), PieceError::BadField("data")));
        cases.push(("data empty", edit(&|o| { o.insert("data".into(), json!("")); }), PieceError::DataSize));
        cases.push(("data over limit", edit(&|o| { o.insert("data".into(), json!("ab".repeat(4097))); }), PieceError::DataSize));
        cases.push(("not an object", json!([1, 2]), PieceError::NotObject));
        for (name, payload, want) in cases {
            assert_eq!(parse_message(&payload, &cfg), Err(want), "{name}");
        }
    }

    #[test]
    fn an_abort_with_extra_keys_is_refused() {
        let mut v = abort_payload(id());
        v.as_object_mut().unwrap().insert("data".into(), json!("ab"));
        assert_eq!(parse_message(&v, &PuzzleConfig::default()), Err(PieceError::WrongKeys));
    }

    #[test]
    fn puzzle_ids_parse_only_in_one_spelling() {
        assert_eq!(PuzzleId::from_hex(&id().to_hex()), Some(id()));
        assert_eq!(PuzzleId::from_hex(&"0A".repeat(16)), None);
        assert_eq!(format!("{:?}", id()), format!("PuzzleId({})", "07".repeat(16)));
    }
}
