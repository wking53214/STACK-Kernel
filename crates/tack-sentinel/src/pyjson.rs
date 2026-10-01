//! Python-compatible JSON: read like `json.loads`, write like `json.dumps`.
//!
//! The Sentinel chain hashes bytes that Python produced, so this module has
//! one job: given the same JSON text Python read, produce byte for byte the
//! same serialization Python produces. Three Python details decide that:
//!
//! * **Numbers keep their Python type.** `json.loads` turns `3` into an `int`
//!   and `3.0` into a `float`, and `json.dumps` writes them back as `3` and
//!   `3.0`. [`Value::Int`] keeps the exact decimal digits (Python ints have no
//!   size limit) and [`Value::Float`] holds an `f64` rendered with
//!   [`float_repr`], which reproduces Python's `repr(float)`.
//! * **Separators.** The ledger hashes `json.dumps(obj, sort_keys=True,
//!   default=str)`, whose default separators are a comma followed by a space
//!   and a colon followed by a space ([`Separators::Python`]). The HMAC
//!   payloads and the head anchor use `separators=(",", ":")`
//!   ([`Separators::Compact`]). Both sort keys.
//! * **`ensure_ascii`.** Every character outside printable ASCII is written
//!   as a lowercase `\uXXXX` escape, and characters above U+FFFF become a
//!   surrogate pair.
//!
//! `default=str` never fires on values that came from JSON (every such value
//! already has a JSON type), so it needs no counterpart here.
//!
//! The reader is stricter than Python in three documented ways, each of
//! which fails closed: a duplicate object key is an error (Python keeps the
//! last one silently), an unpaired surrogate escape is an error (Python keeps
//! it and later cannot encode it), and nesting is capped at
//! [`ParseLimits::max_depth`]. Integer literals longer than
//! [`ParseLimits::max_int_digits`] are refused, which is the same limit
//! Python applies by default (`sys.int_info.default_max_str_digits`, 4300).
//!
//! **Memory.** The reader keeps a running estimate of what it has allocated
//! (string buffers, list buffers, and dict nodes, at the sizes the allocator
//! really hands out) and refuses the input with [`JsonError::OverBudget`]
//! once that estimate passes [`ParseLimits::alloc_bytes_per_input_byte`]
//! times the input length (plus [`ParseLimits::alloc_floor_bytes`]). Without
//! it, a list of small values or of one-key dicts grows 16 to 75 times its
//! text in memory. [`parse_object_keeping`] reads a top-level object and
//! keeps only the keys the caller names, checking the rest for syntax
//! without building them.
//!
//! **Writing.** Every writer streams into a [`Sink`], so a value can be
//! hashed or HMACed in its serialized form without first building the whole
//! string.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

/// A JSON object. Keys are unique; iteration is in code point order, which is
/// the order `sort_keys=True` writes them in.
pub type Object = BTreeMap<String, Value>;

/// One JSON value with Python's type distinctions kept.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`, Python `None`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer literal, Python `int`, exact at any length.
    Int(PyInt),
    /// A literal with a fraction or exponent, or `NaN` / `Infinity`, Python `float`.
    Float(f64),
    /// A string.
    Str(String),
    /// A list.
    Array(Vec<Value>),
    /// A dict.
    Object(Object),
}

impl Value {
    /// Python truthiness: `None`, `False`, `0`, `0.0`, `""`, `[]` and `{}`
    /// are false; everything else, including `NaN`, is true.
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Int(i) => !i.is_zero(),
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
        }
    }

    /// A closed name for the value's type, safe to put in a log line.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Str(_) => "str",
            Value::Array(_) => "list",
            Value::Object(_) => "dict",
        }
    }

    /// Python's `str(value)` for the two types whose rendering can ever equal
    /// a hex digest: a string is itself and an int is its decimal digits.
    /// Every other type returns `None`, because its `str()` contains a
    /// character (`.`, `[`, `{`, a letter outside `a` to `f`, or a space)
    /// that a lowercase hex digest never does.
    ///
    /// A string is borrowed, not copied, so a very long one costs nothing
    /// here.
    pub fn python_str_if_hexable(&self) -> Option<Cow<'_, str>> {
        match self {
            Value::Str(s) => Some(Cow::Borrowed(s.as_str())),
            Value::Int(i) => Some(Cow::Owned(i.to_string())),
            _ => None,
        }
    }

    /// The string inside, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The object inside, if this is an object.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }
}

/// A Python `int` kept exactly. A value that fits in `i64` is held inline;
/// a longer one keeps its decimal digits behind one pointer, so a `PyInt`
/// is 16 bytes and a list of small ints costs no heap allocation per item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyInt {
    repr: IntRepr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IntRepr {
    /// Every value that fits in `i64`, and only those.
    Small(i64),
    /// A value outside `i64`: its sign and its digits (no leading zeros).
    Big(Box<BigDigits>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BigDigits {
    negative: bool,
    digits: String,
}

impl PyInt {
    /// Build from a machine integer.
    pub fn from_i64(v: i64) -> Self {
        PyInt {
            repr: IntRepr::Small(v),
        }
    }

    fn from_literal(negative: bool, digits: &str) -> Self {
        let trimmed = digits.trim_start_matches('0');
        if trimmed.is_empty() {
            return PyInt::from_i64(0);
        }
        // Parse with the sign attached so i64::MIN stays inline.
        let parsed = if negative {
            format!("-{trimmed}").parse::<i64>().ok()
        } else {
            trimmed.parse::<i64>().ok()
        };
        match parsed {
            Some(v) => PyInt::from_i64(v),
            None => PyInt {
                repr: IntRepr::Big(Box::new(BigDigits {
                    negative,
                    digits: trimmed.to_owned(),
                })),
            },
        }
    }

    /// Whether the value is zero.
    pub fn is_zero(&self) -> bool {
        matches!(self.repr, IntRepr::Small(0))
    }

    /// Whether the value is below zero.
    pub fn is_negative(&self) -> bool {
        match &self.repr {
            IntRepr::Small(v) => *v < 0,
            IntRepr::Big(b) => b.negative,
        }
    }

    /// The value as `i64`, or `None` when it does not fit.
    pub fn to_i64(&self) -> Option<i64> {
        match &self.repr {
            IntRepr::Small(v) => Some(*v),
            IntRepr::Big(_) => None,
        }
    }

    /// The magnitude as `u64`, or `None` when it does not fit.
    pub fn magnitude_u64(&self) -> Option<u64> {
        match &self.repr {
            IntRepr::Small(v) => Some(v.unsigned_abs()),
            IntRepr::Big(b) => b.digits.parse::<u64>().ok(),
        }
    }
}

impl fmt::Display for PyInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.repr {
            IntRepr::Small(v) => write!(f, "{v}"),
            IntRepr::Big(b) => {
                if b.negative {
                    f.write_str("-")?;
                }
                f.write_str(&b.digits)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// Caps applied while reading JSON. Every allocation the reader makes is
/// bounded by the input length, which the caller caps first, and by the
/// allocation budget below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseLimits {
    /// Deepest nesting of lists and dicts accepted. Default 256.
    pub max_depth: usize,
    /// Longest integer literal accepted, in digits. Default 4300, Python's
    /// own default limit for converting a decimal string to an `int`.
    pub max_int_digits: usize,
    /// Most bytes the parsed tree may take, per byte of input text. Default
    /// 12. The reader counts every string buffer, list buffer and dict node
    /// at the size the allocator hands out, and refuses the input with
    /// [`JsonError::OverBudget`] when the running count passes
    /// `alloc_bytes_per_input_byte * input length + alloc_floor_bytes`.
    /// The count is an upper bound: dict nodes are charged as if every node
    /// were as empty as a B-tree allows, so it runs ahead of real use. Real
    /// ledger exports use about six to seven times their text and count at
    /// about eight to ten, which is why the default is 12 and not 8 (at 8 a
    /// 16 MiB export of ordinary rows was refused). Measured peaks for the
    /// hostile shapes that hit the cap (lists of one-key dicts, lists of
    /// small values) stay under 11 times the text.
    pub alloc_bytes_per_input_byte: usize,
    /// Budget allowance added for every input, so a small document is never
    /// refused for the fixed cost of a few nodes. Default 1 MiB.
    pub alloc_floor_bytes: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        ParseLimits {
            max_depth: 256,
            max_int_digits: 4300,
            alloc_bytes_per_input_byte: 12,
            alloc_floor_bytes: 1024 * 1024,
        }
    }
}

impl ParseLimits {
    /// The allocation budget for an input of `len` bytes.
    pub fn alloc_budget(&self, len: usize) -> usize {
        self.alloc_bytes_per_input_byte
            .saturating_mul(len)
            .saturating_add(self.alloc_floor_bytes)
    }
}

/// Why a JSON text was refused. Positions are byte offsets; no input bytes
/// are ever copied into an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JsonError {
    /// The bytes are not UTF-8.
    #[error("input is not valid UTF-8")]
    InvalidUtf8,
    /// The text starts with U+FEFF, which Python's `json.loads` also refuses.
    #[error("input starts with a byte order mark")]
    ByteOrderMark,
    /// The text ended inside a value.
    #[error("unexpected end of input at byte {0}")]
    UnexpectedEnd(usize),
    /// A byte that cannot start or continue a value here.
    #[error("unexpected byte at offset {0}")]
    UnexpectedByte(usize),
    /// A backslash escape Python does not accept.
    #[error("invalid escape at byte {0}")]
    InvalidEscape(usize),
    /// A raw control character inside a string (Python's strict mode).
    #[error("control character in string at byte {0}")]
    ControlCharacter(usize),
    /// A `\u` escape for half of a surrogate pair with no other half.
    #[error("unpaired surrogate escape at byte {0}")]
    LoneSurrogate(usize),
    /// Nesting deeper than the configured cap.
    #[error("nesting deeper than {0} levels")]
    TooDeep(usize),
    /// An integer literal longer than the configured cap.
    #[error("integer literal longer than {0} digits")]
    IntegerTooLong(usize),
    /// The same key twice in one object.
    #[error("duplicate object key at byte {0}")]
    DuplicateKey(usize),
    /// Bytes after the top-level value.
    #[error("trailing data at byte {0}")]
    TrailingData(usize),
    /// The parsed tree would take more memory than
    /// [`ParseLimits::alloc_budget`] allows for this input.
    #[error("parsing would allocate more than the {0} byte budget for this input")]
    OverBudget(usize),
}

impl JsonError {
    /// A closed label for this error, for metrics.
    pub fn label(&self) -> &'static str {
        match self {
            JsonError::InvalidUtf8 => "invalid_utf8",
            JsonError::ByteOrderMark => "byte_order_mark",
            JsonError::UnexpectedEnd(_) => "unexpected_end",
            JsonError::UnexpectedByte(_) => "unexpected_byte",
            JsonError::InvalidEscape(_) => "invalid_escape",
            JsonError::ControlCharacter(_) => "control_character",
            JsonError::LoneSurrogate(_) => "lone_surrogate",
            JsonError::TooDeep(_) => "too_deep",
            JsonError::IntegerTooLong(_) => "integer_too_long",
            JsonError::DuplicateKey(_) => "duplicate_key",
            JsonError::TrailingData(_) => "trailing_data",
            JsonError::OverBudget(_) => "over_budget",
        }
    }
}

/// Bytes glibc's allocator really uses for a request of `size` bytes: the
/// request plus an 8-byte header, rounded up to 16, never below 32.
const fn chunk(size: usize) -> usize {
    if size == 0 {
        0
    } else {
        let c = (size.saturating_add(8 + 15)) & !15;
        if c < 32 {
            32
        } else {
            c
        }
    }
}

const VALUE_BYTES: usize = std::mem::size_of::<Value>();
const STRING_BYTES: usize = std::mem::size_of::<String>();
/// One B-tree node of an [`Object`], charged at the size of an internal
/// node (a leaf plus twelve child pointers), the larger of the two: eleven
/// keys, eleven values, a parent pointer, two counters and the edges.
const NODE_BYTES: usize = chunk(16 + 11 * (STRING_BYTES + VALUE_BYTES) + 12 * 8);
const BIG_INT_BYTES: usize = chunk(std::mem::size_of::<BigDigits>());

/// An upper bound on the B-tree nodes holding `len` entries. Every entry
/// sits in exactly one node, the root holds at least one, and under
/// insertion alone every other node keeps at least 5 (a full node of 11
/// splits into halves of at least 5 each), so there are at most
/// `1 + (len - 1) / 5` nodes whatever order the keys arrive in.
const fn btree_nodes(len: usize) -> usize {
    if len == 0 {
        0
    } else {
        1 + (len - 1) / 5
    }
}

/// Parse a JSON text the way Python's `json.loads` does, within `limits`.
pub fn parse(bytes: &[u8], limits: ParseLimits) -> Result<Value, JsonError> {
    let mut p = Parser::new(bytes, limits)?;
    p.skip_ws();
    let v = p.value(0)?;
    p.finish()?;
    Ok(v)
}

/// Parse a JSON text whose top level should be an object, building only the
/// members named in `keep`. Every other member is checked for syntax (and
/// against the depth and integer caps) exactly as [`parse`] would, but not
/// built, so it costs no memory.
///
/// Returns `Ok(None)` when the text is valid JSON whose top level is not an
/// object. A kept key that appears twice is [`JsonError::DuplicateKey`];
/// duplicates among skipped keys, or inside skipped values, are not
/// detected, because the skipped values are never used (Python keeps the
/// last of any duplicates silently).
pub fn parse_object_keeping(bytes: &[u8], limits: ParseLimits, keep: &[&str]) -> Result<Option<Object>, JsonError> {
    let mut p = Parser::new(bytes, limits)?;
    p.skip_ws();
    let out = if p.peek() == Some(b'{') {
        Some(p.object_keeping(keep)?)
    } else {
        p.skip(0)?;
        None
    };
    p.finish()?;
    Ok(out)
}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
    limits: ParseLimits,
    /// Estimated bytes the tree built so far holds.
    live: usize,
    /// The most `live` may reach.
    budget: usize,
}

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8], limits: ParseLimits) -> Result<Self, JsonError> {
        let text = std::str::from_utf8(bytes).map_err(|_| JsonError::InvalidUtf8)?;
        if text.starts_with('\u{feff}') {
            return Err(JsonError::ByteOrderMark);
        }
        Ok(Parser {
            b: text.as_bytes(),
            pos: 0,
            limits,
            live: 0,
            budget: limits.alloc_budget(bytes.len()),
        })
    }

    fn finish(&mut self) -> Result<(), JsonError> {
        self.skip_ws();
        if self.pos != self.b.len() {
            return Err(JsonError::TrailingData(self.pos));
        }
        Ok(())
    }

    fn charge(&mut self, bytes: usize) -> Result<(), JsonError> {
        self.live = self.live.saturating_add(bytes);
        if self.live > self.budget {
            return Err(JsonError::OverBudget(self.budget));
        }
        Ok(())
    }

    fn refund(&mut self, bytes: usize) {
        self.live = self.live.saturating_sub(bytes);
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if matches!(c, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn starts_with(&self, lit: &[u8]) -> bool {
        self.b.get(self.pos..self.pos + lit.len()) == Some(lit)
    }

    /// The literals `null`, `true`, `false`, `NaN`, `Infinity`, `-Infinity`.
    fn literal(&mut self) -> Option<Value> {
        let (len, v) = match self.peek()? {
            b'n' if self.starts_with(b"null") => (4, Value::Null),
            b't' if self.starts_with(b"true") => (4, Value::Bool(true)),
            b'f' if self.starts_with(b"false") => (5, Value::Bool(false)),
            b'N' if self.starts_with(b"NaN") => (3, Value::Float(f64::NAN)),
            b'I' if self.starts_with(b"Infinity") => (8, Value::Float(f64::INFINITY)),
            b'-' if self.starts_with(b"-Infinity") => (9, Value::Float(f64::NEG_INFINITY)),
            _ => return None,
        };
        self.pos += len;
        Some(v)
    }

    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        let c = self.peek().ok_or(JsonError::UnexpectedEnd(self.pos))?;
        if let Some(v) = self.literal() {
            return Ok(v);
        }
        match c {
            b'"' => self.string().map(Value::Str),
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            b'-' | b'0'..=b'9' => {
                let v = self.number()?;
                if let Value::Int(PyInt { repr: IntRepr::Big(b) }) = &v {
                    self.charge(BIG_INT_BYTES.saturating_add(chunk(b.digits.len())))?;
                }
                Ok(v)
            }
            _ => Err(JsonError::UnexpectedByte(self.pos)),
        }
    }

    /// Check one value's syntax without building it.
    fn skip(&mut self, depth: usize) -> Result<(), JsonError> {
        let c = self.peek().ok_or(JsonError::UnexpectedEnd(self.pos))?;
        if self.literal().is_some() {
            return Ok(());
        }
        match c {
            b'"' => self.scan_string(None),
            b'{' | b'[' => {
                let depth = depth + 1;
                if depth > self.limits.max_depth {
                    return Err(JsonError::TooDeep(self.limits.max_depth));
                }
                let (close, is_object) = if c == b'{' { (b'}', true) } else { (b']', false) };
                self.pos += 1;
                self.skip_ws();
                if self.peek() == Some(close) {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    self.skip_ws();
                    if is_object {
                        match self.peek() {
                            Some(b'"') => self.scan_string(None)?,
                            Some(_) => return Err(JsonError::UnexpectedByte(self.pos)),
                            None => return Err(JsonError::UnexpectedEnd(self.pos)),
                        }
                        self.skip_ws();
                        match self.peek() {
                            Some(b':') => self.pos += 1,
                            Some(_) => return Err(JsonError::UnexpectedByte(self.pos)),
                            None => return Err(JsonError::UnexpectedEnd(self.pos)),
                        }
                        self.skip_ws();
                    }
                    self.skip(depth)?;
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(x) if x == close => {
                            self.pos += 1;
                            return Ok(());
                        }
                        Some(_) => return Err(JsonError::UnexpectedByte(self.pos)),
                        None => return Err(JsonError::UnexpectedEnd(self.pos)),
                    }
                }
            }
            b'-' | b'0'..=b'9' => self.number().map(drop),
            _ => Err(JsonError::UnexpectedByte(self.pos)),
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        self.pos - start
    }

    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.pos;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.pos += 1;
        }
        let int_start = self.pos;
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            Some(_) => return Err(JsonError::UnexpectedByte(self.pos)),
            None => return Err(JsonError::UnexpectedEnd(self.pos)),
        }
        let int_end = self.pos;
        let mut is_float = false;
        // Python's number pattern takes a fraction only when a digit follows
        // the point, and an exponent only when a digit follows `e` and an
        // optional sign. Otherwise the number ends and the next byte is
        // judged by the caller, exactly as Python's scanner does.
        if self.peek() == Some(b'.') && matches!(self.b.get(self.pos + 1), Some(b'0'..=b'9')) {
            self.pos += 1;
            self.digits();
            is_float = true;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let mut look = self.pos + 1;
            if matches!(self.b.get(look), Some(b'+' | b'-')) {
                look += 1;
            }
            if matches!(self.b.get(look), Some(b'0'..=b'9')) {
                self.pos = look;
                self.digits();
                is_float = true;
            }
        }
        let text = std::str::from_utf8(&self.b[start..self.pos]).map_err(|_| JsonError::InvalidUtf8)?;
        if is_float {
            // Rust's parser rounds correctly, as Python's float() does, and
            // overflows to an infinity the same way.
            let f = text
                .parse::<f64>()
                .map_err(|_| JsonError::UnexpectedByte(start))?;
            return Ok(Value::Float(f));
        }
        let digits = std::str::from_utf8(&self.b[int_start..int_end]).map_err(|_| JsonError::InvalidUtf8)?;
        if digits.len() > self.limits.max_int_digits {
            return Err(JsonError::IntegerTooLong(self.limits.max_int_digits));
        }
        Ok(Value::Int(PyInt::from_literal(negative, digits)))
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let at = self.pos;
        let chunk = self.b.get(self.pos..self.pos + 4).ok_or(JsonError::InvalidEscape(at))?;
        let mut v: u32 = 0;
        for &c in chunk {
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(JsonError::InvalidEscape(at)),
            };
            v = (v << 4) | u32::from(d);
        }
        self.pos += 4;
        Ok(v)
    }

    /// Read a string, allocating its buffer once: the raw text between the
    /// quotes is never shorter than what it decodes to.
    fn string(&mut self) -> Result<String, JsonError> {
        let mut end = self.pos + 1;
        while let Some(&c) = self.b.get(end) {
            match c {
                b'"' => break,
                b'\\' => end += 2,
                _ => end += 1,
            }
        }
        let raw_len = end.min(self.b.len()).saturating_sub(self.pos + 1);
        self.charge(chunk(raw_len))?;
        let mut out = String::with_capacity(raw_len);
        self.scan_string(Some(&mut out))?;
        Ok(out)
    }

    /// Scan a string from its opening quote, checking it as Python does and
    /// decoding it into `out` when one is given.
    fn scan_string(&mut self, mut out: Option<&mut String>) -> Result<(), JsonError> {
        // at the opening quote
        self.pos += 1;
        loop {
            let run_start = self.pos;
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            if let Some(o) = out.as_deref_mut() {
                // The run ends on an ASCII byte or at the end, never inside a
                // multi-byte character, so it is valid UTF-8 on its own.
                let run = std::str::from_utf8(&self.b[run_start..self.pos]).map_err(|_| JsonError::InvalidUtf8)?;
                o.push_str(run);
            }
            let c = self.peek().ok_or(JsonError::UnexpectedEnd(self.pos))?;
            match c {
                b'"' => {
                    self.pos += 1;
                    return Ok(());
                }
                b'\\' => {
                    let at = self.pos;
                    self.pos += 1;
                    let e = self.peek().ok_or(JsonError::UnexpectedEnd(self.pos))?;
                    self.pos += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..=0xDBFF).contains(&hi) {
                                if !self.starts_with(b"\\u") {
                                    return Err(JsonError::LoneSurrogate(at));
                                }
                                self.pos += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    return Err(JsonError::LoneSurrogate(at));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..=0xDFFF).contains(&hi) {
                                return Err(JsonError::LoneSurrogate(at));
                            } else {
                                hi
                            };
                            char::from_u32(cp).ok_or(JsonError::InvalidEscape(at))?
                        }
                        _ => return Err(JsonError::InvalidEscape(at)),
                    };
                    if let Some(o) = out.as_deref_mut() {
                        o.push(ch);
                    }
                }
                _ => return Err(JsonError::ControlCharacter(self.pos)),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > self.limits.max_depth {
            return Err(JsonError::TooDeep(self.limits.max_depth));
        }
        self.pos += 1;
        let mut items: Vec<Value> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            let v = self.value(depth)?;
            if items.len() == items.capacity() {
                // Grow by doubling, charging the new buffer while the old
                // one still exists, as it does during the copy.
                let old = items.capacity();
                let new = old.saturating_mul(2).max(4);
                self.charge(chunk(new.saturating_mul(VALUE_BYTES)))?;
                items.reserve_exact(new - items.len());
                self.refund(chunk(old.saturating_mul(VALUE_BYTES)));
            }
            items.push(v);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                Some(_) => return Err(JsonError::UnexpectedByte(self.pos)),
                None => return Err(JsonError::UnexpectedEnd(self.pos)),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > self.limits.max_depth {
            return Err(JsonError::TooDeep(self.limits.max_depth));
        }
        self.members(depth, None).map(Value::Object)
    }

    /// The top-level object, keeping only the members named in `keep`.
    fn object_keeping(&mut self, keep: &[&str]) -> Result<Object, JsonError> {
        if 1 > self.limits.max_depth {
            return Err(JsonError::TooDeep(self.limits.max_depth));
        }
        self.members(1, Some(keep))
    }

    fn members(&mut self, depth: usize, keep: Option<&[&str]>) -> Result<Object, JsonError> {
        self.pos += 1;
        let mut map = Object::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(map);
        }
        loop {
            self.skip_ws();
            let key_at = self.pos;
            match self.peek() {
                Some(b'"') => {}
                Some(_) => return Err(JsonError::UnexpectedByte(self.pos)),
                None => return Err(JsonError::UnexpectedEnd(self.pos)),
            }
            let key = self.string()?;
            self.skip_ws();
            match self.peek() {
                Some(b':') => self.pos += 1,
                Some(_) => return Err(JsonError::UnexpectedByte(self.pos)),
                None => return Err(JsonError::UnexpectedEnd(self.pos)),
            }
            self.skip_ws();
            if keep.is_some_and(|k| !k.contains(&key.as_str())) {
                self.refund(chunk(key.capacity()));
                drop(key);
                self.skip(depth)?;
            } else {
                let v = self.value(depth)?;
                let len = map.len();
                if map.insert(key, v).is_some() {
                    return Err(JsonError::DuplicateKey(key_at));
                }
                let grew = btree_nodes(len + 1) - btree_nodes(len);
                self.charge(grew.saturating_mul(NODE_BYTES))?;
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(map);
                }
                Some(_) => return Err(JsonError::UnexpectedByte(self.pos)),
                None => return Err(JsonError::UnexpectedEnd(self.pos)),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Which separators `json.dumps` was called with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Separators {
    /// Python's default: `", "` between items and `": "` after keys. The
    /// ledger hashes this form (`twin_custody._ledger_dumps`).
    Python,
    /// `separators=(",", ":")`: the HMAC payloads and the head anchor
    /// (`twin_custody.canonical_json`).
    Compact,
}

impl Separators {
    fn item(self) -> &'static str {
        match self {
            Separators::Python => ", ",
            Separators::Compact => ",",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Separators::Python => ": ",
            Separators::Compact => ":",
        }
    }
}

/// Where serialized text goes: a `String`, a hash, an HMAC, or a counter.
/// Streaming into a hash means a large value is never copied into a second
/// buffer just to be hashed.
pub trait Sink {
    /// Append `s`.
    fn put(&mut self, s: &str);
}

impl Sink for String {
    fn put(&mut self, s: &str) {
        self.push_str(s);
    }
}

/// Counts the bytes written to it and keeps none of them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CountingSink(pub usize);

impl Sink for CountingSink {
    fn put(&mut self, s: &str) {
        self.0 = self.0.saturating_add(s.len());
    }
}

struct FmtSink<'a, S: Sink + ?Sized>(&'a mut S);

impl<S: Sink + ?Sized> fmt::Write for FmtSink<'_, S> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.put(s);
        Ok(())
    }
}

/// `json.dumps(value, sort_keys=True, default=str, separators=...)` with
/// `ensure_ascii=True` and `allow_nan=True`, Python's defaults.
pub fn dumps(value: &Value, seps: Separators) -> String {
    let mut out = String::new();
    write_value(&mut out, value, seps);
    out
}

/// [`dumps`] into any [`Sink`].
pub fn write_value<S: Sink + ?Sized>(out: &mut S, value: &Value, seps: Separators) {
    match value {
        Value::Null => out.put("null"),
        Value::Bool(true) => out.put("true"),
        Value::Bool(false) => out.put("false"),
        Value::Int(i) => {
            let _ = fmt::Write::write_fmt(&mut FmtSink(out), format_args!("{i}"));
        }
        Value::Float(f) => {
            if f.is_nan() {
                out.put("NaN");
            } else if f.is_infinite() {
                out.put(if *f > 0.0 { "Infinity" } else { "-Infinity" });
            } else {
                out.put(&float_repr(*f));
            }
        }
        Value::Str(s) => write_str(out, s),
        Value::Array(items) => {
            out.put("[");
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.put(seps.item());
                }
                write_value(out, v, seps);
            }
            out.put("]");
        }
        Value::Object(map) => write_entries(out, map.iter().map(|(k, v)| (k.as_str(), v)), seps),
    }
}

/// An object from `(key, value)` pairs that the caller yields in sorted
/// key order, as `sort_keys=True` writes them.
pub fn write_entries<'v, S, I>(out: &mut S, entries: I, seps: Separators)
where
    S: Sink + ?Sized,
    I: IntoIterator<Item = (&'v str, &'v Value)>,
{
    out.put("{");
    for (i, (k, v)) in entries.into_iter().enumerate() {
        if i > 0 {
            out.put(seps.item());
        }
        write_str(out, k);
        out.put(seps.key());
        write_value(out, v, seps);
    }
    out.put("}");
}

/// [`dumps`] of an object, leaving out the key `skip` when given, without
/// copying the object.
pub fn dumps_object(map: &Object, seps: Separators, skip: Option<&str>) -> String {
    let mut out = String::new();
    write_entries(
        &mut out,
        map.iter()
            .filter(|(k, _)| skip != Some(k.as_str()))
            .map(|(k, v)| (k.as_str(), v)),
        seps,
    );
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_u16_escape<S: Sink + ?Sized>(out: &mut S, unit: u16) {
    let mut buf = [b'\\', b'u', 0, 0, 0, 0];
    for (slot, shift) in buf[2..].iter_mut().zip([12u16, 8, 4, 0]) {
        *slot = HEX[usize::from((unit >> shift) & 0xF)];
    }
    // Six ASCII bytes are always valid UTF-8.
    if let Ok(text) = std::str::from_utf8(&buf) {
        out.put(text);
    }
}

/// Python's `ensure_ascii` string encoder (`py_encode_basestring_ascii`).
/// Runs of printable ASCII are written as one slice.
pub fn write_str<S: Sink + ?Sized>(out: &mut S, s: &str) {
    out.put("\"");
    let mut run_start = 0;
    for (i, ch) in s.char_indices() {
        let escape = match ch {
            '"' => "\\\"",
            '\\' => "\\\\",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            '\u{8}' => "\\b",
            '\u{c}' => "\\f",
            ' '..='~' => continue,
            _ => "",
        };
        out.put(&s[run_start..i]);
        run_start = i + ch.len_utf8();
        if escape.is_empty() {
            let mut buf = [0u16; 2];
            for unit in ch.encode_utf16(&mut buf) {
                push_u16_escape(out, *unit);
            }
        } else {
            out.put(escape);
        }
    }
    out.put(&s[run_start..]);
    out.put("\"");
}

/// Python's `repr(float)`: the shortest decimal string that reads back to
/// the same double, in fixed notation when the decimal exponent is from -4
/// to 15 and in scientific notation otherwise (`1e+16`, `1.5e-05`).
///
/// Rust's `{:e}` formatting yields the same shortest round-trip digits that
/// CPython's `repr` does; this function only rearranges them into Python's
/// layout. `NaN` and the infinities render as Python's `nan`, `inf`, `-inf`;
/// [`dumps`] writes them as `NaN`, `Infinity`, `-Infinity` instead.
pub fn float_repr(v: f64) -> String {
    if v.is_nan() {
        return "nan".to_owned();
    }
    if v.is_infinite() {
        return if v > 0.0 { "inf".to_owned() } else { "-inf".to_owned() };
    }
    let sci = format!("{:e}", v.abs());
    let mut digits = String::new();
    let mut exp_negative = false;
    let mut exp: i32 = 0;
    let mut in_exp = false;
    for c in sci.chars() {
        if in_exp {
            match c {
                '-' => exp_negative = true,
                '0'..='9' => exp = exp * 10 + (c as i32 - '0' as i32),
                _ => {}
            }
        } else {
            match c {
                'e' => in_exp = true,
                '0'..='9' => digits.push(c),
                _ => {}
            }
        }
    }
    if exp_negative {
        exp = -exp;
    }
    let mut out = String::new();
    if v.is_sign_negative() {
        out.push('-');
    }
    if (-4..16).contains(&exp) {
        if exp >= 0 {
            let int_len = exp.unsigned_abs() as usize + 1;
            if digits.len() > int_len {
                out.push_str(&digits[..int_len]);
                out.push('.');
                out.push_str(&digits[int_len..]);
            } else {
                out.push_str(&digits);
                for _ in digits.len()..int_len {
                    out.push('0');
                }
                out.push_str(".0");
            }
        } else {
            out.push_str("0.");
            for _ in 1..exp.unsigned_abs() {
                out.push('0');
            }
            out.push_str(&digits);
        }
    } else {
        let (first, rest) = digits.split_at(1.min(digits.len()));
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        out.push('e');
        out.push(if exp < 0 { '-' } else { '+' });
        let mag = exp.unsigned_abs();
        if mag < 10 {
            out.push('0');
        }
        out.push_str(&mag.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Value {
        parse(s.as_bytes(), ParseLimits::default()).unwrap()
    }

    #[test]
    fn float_repr_matches_python_layout() {
        let cases: &[(f64, &str)] = &[
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (0.1, "0.1"),
            (0.6, "0.6"),
            (1e15, "1000000000000000.0"),
            (1e16, "1e+16"),
            (1.5e16, "1.5e+16"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.5e-7, "1.5e-07"),
            (1e100, "1e+100"),
            (5e-324, "5e-324"),
            (123456789.125, "123456789.125"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (3600.0, "3600.0"),
            (-2.5, "-2.5"),
        ];
        for (v, want) in cases {
            assert_eq!(float_repr(*v), *want, "{v}");
        }
    }

    #[test]
    fn dumps_uses_python_separators_and_sorted_keys() {
        let v = p(r#"{"b": [1, 2.0, null], "a": {"y": true, "x": "\u00e9\ud83d\ude00"}}"#);
        assert_eq!(
            dumps(&v, Separators::Python),
            r#"{"a": {"x": "\u00e9\ud83d\ude00", "y": true}, "b": [1, 2.0, null]}"#
        );
        assert_eq!(
            dumps(&v, Separators::Compact),
            r#"{"a":{"x":"\u00e9\ud83d\ude00","y":true},"b":[1,2.0,null]}"#
        );
    }

    #[test]
    fn numbers_keep_their_python_type() {
        assert_eq!(dumps(&p("-0"), Separators::Python), "0");
        assert_eq!(dumps(&p("-0.0"), Separators::Python), "-0.0");
        assert_eq!(dumps(&p("1E5"), Separators::Python), "100000.0");
        assert_eq!(dumps(&p("1e400"), Separators::Python), "Infinity");
        assert_eq!(dumps(&p("NaN"), Separators::Python), "NaN");
        let big = "123456789012345678901234567890";
        assert_eq!(dumps(&p(big), Separators::Python), big);
    }

    #[test]
    fn control_and_delete_characters_are_escaped() {
        let v = Value::Str("\u{1}\u{7f}\u{8}\u{c}/".to_owned());
        assert_eq!(dumps(&v, Separators::Python), r#""\u0001\u007f\b\f/""#);
    }

    #[test]
    fn strict_reader_refuses_what_it_should() {
        let lim = ParseLimits::default();
        assert_eq!(parse(br#"{"a":1,"a":2}"#, lim), Err(JsonError::DuplicateKey(7)));
        assert!(matches!(parse(br#""\ud800""#, lim), Err(JsonError::LoneSurrogate(_))));
        assert!(matches!(parse(b"\"a\nb\"", lim), Err(JsonError::ControlCharacter(_))));
        assert!(matches!(parse(b"[1,]", lim), Err(JsonError::UnexpectedByte(_))));
        assert!(matches!(parse(b"1.", lim), Err(JsonError::TrailingData(_))));
        assert!(matches!(parse(b"01", lim), Err(JsonError::TrailingData(_))));
        assert!(matches!(parse("\u{feff}1".as_bytes(), lim), Err(JsonError::ByteOrderMark)));
        let deep = "[".repeat(300) + &"]".repeat(300);
        assert_eq!(parse(deep.as_bytes(), lim), Err(JsonError::TooDeep(256)));
        let long = "9".repeat(4301);
        assert_eq!(parse(long.as_bytes(), lim), Err(JsonError::IntegerTooLong(4300)));
    }

    #[test]
    fn truthiness_matches_python() {
        for (s, t) in [
            ("null", false),
            ("0", false),
            ("0.0", false),
            ("-0.0", false),
            ("\"\"", false),
            ("[]", false),
            ("{}", false),
            ("false", false),
            ("NaN", true),
            ("1", true),
            ("\"0\"", true),
            ("[0]", true),
        ] {
            assert_eq!(p(s).is_truthy(), t, "{s}");
        }
    }
}
