//! Resource scopes: what a capability names, and how a request's resource
//! is matched against it.
//!
//! A resource is a path: `/` followed by segments separated by `/`. The
//! rules are deliberately narrow so that two spellings never name one
//! resource and one spelling never names two:
//!
//! * the path starts with `/`; the root `/` alone is allowed;
//! * no empty segment (`//`), no trailing `/` except on the root, no `.`
//!   or `..` segment;
//! * no control character (below U+0020, or U+007F);
//! * at most [`MAX_PATH_BYTES`] bytes of UTF-8;
//! * no normalisation of any kind: comparison is by bytes, so `/Data` and
//!   `/data` are different resources, as are `/a%2Fb` and `/a/b`.
//!
//! A scope is either `Exact` (the request's resource must equal the path
//! byte for byte) or `Prefix` (the request's resource must equal the path,
//! or extend it at a segment boundary). `Prefix(/data/a)` covers `/data/a`
//! and `/data/a/b` and never `/data/ab`. `Prefix(/)` covers every valid
//! path. A request whose resource does not pass the same validation is
//! covered by nothing.

use std::cmp::Ordering;
use std::fmt;

/// Longest accepted resource path, in bytes.
pub const MAX_PATH_BYTES: usize = 1024;

/// Why a path was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// Zero bytes.
    #[error("path is empty")]
    Empty,
    /// Longer than [`MAX_PATH_BYTES`].
    #[error("path exceeds {MAX_PATH_BYTES} bytes")]
    TooLong,
    /// Does not start with `/`.
    #[error("path does not start with '/'")]
    NotAbsolute,
    /// Contains `//` or ends in `/` (other than the root).
    #[error("path has an empty segment")]
    EmptySegment,
    /// Contains a `.` or `..` segment.
    #[error("path has a '.' or '..' segment")]
    DotSegment,
    /// Contains a character below U+0020 or U+007F.
    #[error("path has a control character")]
    ControlCharacter,
}

/// Checks `path` against the rules in the module documentation.
pub fn validate_path(path: &str) -> Result<(), PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    if !path.starts_with('/') {
        return Err(PathError::NotAbsolute);
    }
    if path.chars().any(is_control) {
        return Err(PathError::ControlCharacter);
    }
    if path == "/" {
        return Ok(());
    }
    for segment in path.get(1..).unwrap_or("").split('/') {
        match segment {
            "" => return Err(PathError::EmptySegment),
            "." | ".." => return Err(PathError::DotSegment),
            _ => {}
        }
    }
    Ok(())
}

/// Whether `c` is a character no identifier, operation name, policy
/// reference or path may contain.
pub(crate) fn is_control(c: char) -> bool {
    c < '\u{20}' || c == '\u{7f}'
}

/// How a scope's path is matched. The wire values are fixed and part of
/// the signed encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ScopeKind {
    /// The request's resource must equal the path.
    Exact = 0,
    /// The request's resource must equal the path or extend it at a
    /// segment boundary.
    Prefix = 1,
}

impl ScopeKind {
    /// The wire byte.
    pub const fn to_wire(self) -> u8 {
        self as u8
    }

    /// From the wire byte. Any other value is `None`.
    pub const fn from_wire(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Exact),
            1 => Some(Self::Prefix),
            _ => None,
        }
    }
}

/// One resource scope: a kind and a validated path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceScope {
    kind: ScopeKind,
    path: String,
}

impl ResourceScope {
    /// A scope over `path`, which must pass [`validate_path`].
    pub fn new(kind: ScopeKind, path: &str) -> Result<Self, PathError> {
        validate_path(path)?;
        Ok(Self {
            kind,
            path: path.to_owned(),
        })
    }

    /// An exact scope.
    pub fn exact(path: &str) -> Result<Self, PathError> {
        Self::new(ScopeKind::Exact, path)
    }

    /// A prefix scope.
    pub fn prefix(path: &str) -> Result<Self, PathError> {
        Self::new(ScopeKind::Prefix, path)
    }

    /// The kind.
    pub const fn kind(&self) -> ScopeKind {
        self.kind
    }

    /// The path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether this scope covers `resource`. A resource that fails
    /// [`validate_path`] is covered by nothing.
    pub fn covers(&self, resource: &str) -> bool {
        if validate_path(resource).is_err() {
            return false;
        }
        match self.kind {
            ScopeKind::Exact => resource == self.path,
            ScopeKind::Prefix => {
                if resource == self.path {
                    return true;
                }
                if self.path == "/" {
                    // Every valid path starts with the root.
                    return true;
                }
                resource
                    .strip_prefix(self.path.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
            }
        }
    }
}

/// Scopes order by path bytes, then by kind. This is the order the wire
/// encoding requires, so that one set of scopes has one encoding.
impl Ord for ResourceScope {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path
            .as_bytes()
            .cmp(other.path.as_bytes())
            .then(self.kind.cmp(&other.kind))
    }
}

impl PartialOrd for ResourceScope {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for ResourceScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ScopeKind::Exact => write!(f, "exact:{}", self.path),
            ScopeKind::Prefix => write!(f, "prefix:{}", self.path),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_validated() {
        for ok in ["/", "/a", "/data/a", "/data/a.b/c..d/...", "/Ünïcode/x", "/a%2Fb"] {
            assert_eq!(validate_path(ok), Ok(()), "{ok}");
        }
        assert_eq!(validate_path(""), Err(PathError::Empty));
        assert_eq!(validate_path("a"), Err(PathError::NotAbsolute));
        assert_eq!(validate_path("data/a"), Err(PathError::NotAbsolute));
        assert_eq!(validate_path("//"), Err(PathError::EmptySegment));
        assert_eq!(validate_path("/a/"), Err(PathError::EmptySegment));
        assert_eq!(validate_path("/a//b"), Err(PathError::EmptySegment));
        assert_eq!(validate_path("/."), Err(PathError::DotSegment));
        assert_eq!(validate_path("/a/../b"), Err(PathError::DotSegment));
        assert_eq!(validate_path("/a/./b"), Err(PathError::DotSegment));
        assert_eq!(validate_path("/a\nb"), Err(PathError::ControlCharacter));
        assert_eq!(validate_path("/a\u{7f}"), Err(PathError::ControlCharacter));
        assert_eq!(validate_path("/a\0"), Err(PathError::ControlCharacter));
        let long = format!("/{}", "x".repeat(MAX_PATH_BYTES));
        assert_eq!(validate_path(&long), Err(PathError::TooLong));
        let fits = format!("/{}", "x".repeat(MAX_PATH_BYTES - 1));
        assert_eq!(validate_path(&fits), Ok(()));
    }

    #[test]
    fn scopes_order_by_path_then_kind_and_kinds_round_trip() {
        let a = ResourceScope::exact("/a").unwrap();
        let ap = ResourceScope::prefix("/a").unwrap();
        let b = ResourceScope::exact("/b").unwrap();
        assert!(a < ap && ap < b);
        assert_eq!(ScopeKind::from_wire(0), Some(ScopeKind::Exact));
        assert_eq!(ScopeKind::from_wire(1), Some(ScopeKind::Prefix));
        assert_eq!(ScopeKind::from_wire(2), None);
        assert_eq!(ScopeKind::Prefix.to_wire(), 1);
        assert_eq!(format!("{ap}"), "prefix:/a");
        assert_eq!(ResourceScope::exact("x"), Err(PathError::NotAbsolute));
    }
}
