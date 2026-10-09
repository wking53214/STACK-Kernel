// Governed limits: read the per-agent limits that the governance service may tighten.
//
// The governance service (wking53214/experimental, scripts/adjudication_server.py) keeps one
// boundary per agent and limit, named `stack.agent.<agent>.<suffix>`. It may lower a limit on
// its own; only a named human may raise one. This client reads the current value before the
// kernel starts work for an agent.
//
// Safety rules (all tested):
// - The configured default is a CEILING. A governed value above it is ignored.
//   A broken or hostile service therefore cannot loosen the kernel past its own config.
// - If the service is unreachable, slow, or returns anything that is not a positive whole
//   number, the kernel keeps the last good value (or the default if it has none). It never
//   fails open to "unlimited" and never stops running because the service is down.
// - Reads are cached for `ttl`, so the hot path does not wait on the network.
//
// Plain HTTP only: the service has no TLS (see its THREAT_MODEL T10). Use loopback or a
// trusted network, and a read-only credential.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// Which limit of an agent is being read. The suffix must match the governance side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitKind {
    DeadlineNs,
    TokensCapacity,
    MemoryCapacityBytes,
}

impl LimitKind {
    pub fn suffix(&self) -> &'static str {
        match self {
            LimitKind::DeadlineNs => "deadline_ns",
            LimitKind::TokensCapacity => "tokens_capacity",
            LimitKind::MemoryCapacityBytes => "memory_capacity_bytes",
        }
    }
}

/// The governance side keeps ids that match `^[A-Za-z0-9._-]{1,64}$` as they are and replaces
/// every other id with `h-` + the first 24 hex characters of its SHA-256.
pub fn agent_key(agent_id: &str) -> String {
    let safe = !agent_id.is_empty()
        && agent_id.len() <= 64
        && agent_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
    if safe {
        agent_id.to_string()
    } else {
        let digest = hex::encode(Sha256::digest(agent_id.as_bytes()));
        format!("h-{}", &digest[..24])
    }
}

pub fn boundary_id(agent_id: &str, kind: LimitKind) -> String {
    format!("stack.agent.{}.{}", agent_key(agent_id), kind.suffix())
}

/// Where limits come from. `Ok(None)` means "no such boundary yet" (nothing has been tightened).
pub trait LimitSource: Send + Sync {
    fn fetch(&self, boundary_id: &str) -> Result<Option<serde_json::Value>, String>;
}

/// Reads a JSON file shaped `{"<boundary id>": <limit>}`. Useful where the service writes a
/// snapshot and the kernel has no network path to it.
pub struct FileSource {
    pub path: std::path::PathBuf,
}

impl LimitSource for FileSource {
    fn fetch(&self, boundary_id: &str) -> Result<Option<serde_json::Value>, String> {
        let text = std::fs::read_to_string(&self.path).map_err(|e| e.to_string())?;
        let doc: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        Ok(doc.get(boundary_id).cloned())
    }
}

/// `GET /boundaries/<id>` against the adjudication server, bearer token optional.
pub struct HttpSource {
    pub host: String,
    pub port: u16,
    pub token: Option<String>,
    pub timeout: Duration,
}

const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

impl LimitSource for HttpSource {
    fn fetch(&self, boundary_id: &str) -> Result<Option<serde_json::Value>, String> {
        // The id is built from a sanitized agent key, but refuse anything that could alter
        // the request line regardless of where the caller got it.
        if !boundary_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-') {
            return Err("unsafe boundary id".into());
        }
        let auth = match &self.token {
            Some(t) if t.bytes().all(|b| b.is_ascii_graphic()) => format!("Authorization: Bearer {}\r\n", t),
            Some(_) => return Err("unsafe token".into()),
            None => String::new(),
        };
        let addr = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or("no address")?;
        let mut stream = TcpStream::connect_timeout(&addr, self.timeout).map_err(|e| e.to_string())?;
        stream.set_read_timeout(Some(self.timeout)).map_err(|e| e.to_string())?;
        stream.set_write_timeout(Some(self.timeout)).map_err(|e| e.to_string())?;
        let req = format!(
            "GET /boundaries/{} HTTP/1.1\r\nHost: {}\r\n{}Connection: close\r\n\r\n",
            boundary_id, self.host, auth
        );
        stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        stream.take(MAX_RESPONSE_BYTES).read_to_end(&mut raw).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&raw);
        let (head, body) = text.split_once("\r\n\r\n").ok_or("malformed response")?;
        let status: u16 = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .ok_or("malformed status line")?;
        match status {
            200 => {
                let doc: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
                Ok(doc.get("limit").cloned())
            }
            404 => Ok(None),
            other => Err(format!("http status {}", other)),
        }
    }
}

/// Counters, so an operator can see when the service is failing or returning junk.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LimitStats {
    pub fetched: u64,
    pub source_errors: u64,
    pub invalid_values: u64,
    pub above_ceiling: u64,
}

struct Entry {
    value: Option<u64>, // last good governed value
    checked: Instant,
}

pub struct GovernedLimits<S: LimitSource> {
    source: S,
    ttl: Duration,
    state: Mutex<(HashMap<String, Entry>, LimitStats)>,
}

/// A governed value is usable only if it is a positive whole number.
fn parse_limit(v: &serde_json::Value) -> Option<u64> {
    if let Some(u) = v.as_u64() {
        return if u > 0 { Some(u) } else { None };
    }
    let f = v.as_f64()?;
    if f.is_finite() && f > 0.0 && f.fract() == 0.0 && f < 1.8446744073709552e19 {
        Some(f as u64)
    } else {
        None
    }
}

impl<S: LimitSource> GovernedLimits<S> {
    pub fn new(source: S, ttl: Duration) -> Self {
        Self { source, ttl, state: Mutex::new((HashMap::new(), LimitStats::default())) }
    }

    pub fn stats(&self) -> LimitStats {
        self.state.lock().map(|g| g.1.clone()).unwrap_or_default()
    }

    /// The limit to enforce for this agent right now: never above `default`.
    pub fn effective(&self, agent_id: &str, kind: LimitKind, default: u64) -> u64 {
        let id = boundary_id(agent_id, kind);
        let now = Instant::now();
        // A poisoned lock means another thread panicked; stay on the safe default.
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(_) => return default,
        };
        let fresh = guard.0.get(&id).map_or(false, |e| now.duration_since(e.checked) < self.ttl);
        if !fresh {
            // Network I/O happens under the lock, bounded by the source timeout. A kernel that
            // cannot afford that should call this from a refresher thread and read the cache.
            let result = self.source.fetch(&id);
            let (map, stats) = &mut *guard;
            let entry = map.entry(id.clone()).or_insert(Entry { value: None, checked: now });
            entry.checked = now; // also on failure: do not hammer a down service
            match result {
                Err(_) => stats.source_errors += 1,
                Ok(None) => {
                    stats.fetched += 1;
                }
                Ok(Some(v)) => match parse_limit(&v) {
                    Some(n) => {
                        stats.fetched += 1;
                        entry.value = Some(n);
                    }
                    None => stats.invalid_values += 1,
                },
            }
        }
        let (map, stats) = &mut *guard;
        match map.get(&id).and_then(|e| e.value) {
            Some(v) if v > default => {
                stats.above_ceiling += 1;
                default
            }
            Some(v) => v,
            None => default,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::thread;

    struct Scripted {
        replies: StdMutex<Vec<Result<Option<serde_json::Value>, String>>>,
        calls: StdMutex<u32>,
    }
    impl Scripted {
        fn new(r: Vec<Result<Option<serde_json::Value>, String>>) -> Arc<Self> {
            Arc::new(Self { replies: StdMutex::new(r), calls: StdMutex::new(0) })
        }
    }
    impl LimitSource for Arc<Scripted> {
        fn fetch(&self, _id: &str) -> Result<Option<serde_json::Value>, String> {
            *self.calls.lock().unwrap() += 1;
            let mut r = self.replies.lock().unwrap();
            if r.is_empty() { Ok(None) } else { r.remove(0) }
        }
    }

    fn j(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn ids_match_the_governance_side() {
        assert_eq!(boundary_id("agent-1", LimitKind::TokensCapacity), "stack.agent.agent-1.tokens_capacity");
        // Reference value computed with Python: hashlib.sha256(b"a b").hexdigest()[:24]
        assert_eq!(agent_key("a b"), format!("h-{}", &hex::encode(Sha256::digest(b"a b"))[..24]));
        assert!(agent_key("a/b").starts_with("h-"));
        assert!(agent_key("").starts_with("h-"));
        assert!(agent_key(&"x".repeat(65)).starts_with("h-"));
        assert_eq!(agent_key(&"x".repeat(64)), "x".repeat(64));
    }

    #[test]
    fn uses_default_when_nothing_governed() {
        let g = GovernedLimits::new(Scripted::new(vec![Ok(None)]), Duration::from_secs(60));
        assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 1000);
    }

    #[test]
    fn applies_a_tightened_limit() {
        let g = GovernedLimits::new(Scripted::new(vec![Ok(Some(j("729")))]), Duration::from_secs(60));
        assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 729);
    }

    #[test]
    fn accepts_whole_floats_the_service_may_send() {
        let g = GovernedLimits::new(Scripted::new(vec![Ok(Some(j("729.0")))]), Duration::from_secs(60));
        assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 729);
    }

    #[test]
    fn a_value_above_the_ceiling_is_ignored() {
        let g = GovernedLimits::new(Scripted::new(vec![Ok(Some(j("5000")))]), Duration::from_secs(60));
        assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 1000);
        assert_eq!(g.stats().above_ceiling, 1);
    }

    #[test]
    fn junk_values_never_loosen_and_keep_the_last_good_value() {
        for bad in ["0", "-5", "1.5", "\"900\"", "null", "true", "[900]"] {
            let g = GovernedLimits::new(Scripted::new(vec![Ok(Some(j("700"))), Ok(Some(j(bad)))]), Duration::ZERO);
            assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 700);
            assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 700, "bad value {bad}");
            assert_eq!(g.stats().invalid_values, 1, "bad value {bad}");
        }
    }

    #[test]
    fn source_failure_keeps_last_good_or_default() {
        let g = GovernedLimits::new(Scripted::new(vec![Err("down".into())]), Duration::ZERO);
        assert_eq!(g.effective("a", LimitKind::DeadlineNs, 1000), 1000);
        let g = GovernedLimits::new(Scripted::new(vec![Ok(Some(j("800"))), Err("down".into())]), Duration::ZERO);
        assert_eq!(g.effective("a", LimitKind::DeadlineNs, 1000), 800);
        assert_eq!(g.effective("a", LimitKind::DeadlineNs, 1000), 800);
        assert_eq!(g.stats().source_errors, 1);
    }

    #[test]
    fn a_later_larger_value_below_the_ceiling_is_accepted() {
        // The service only raises a limit after a named operator approves it, so the client
        // follows it up to the configured ceiling.
        let g = GovernedLimits::new(Scripted::new(vec![Ok(Some(j("500"))), Ok(Some(j("900")))]), Duration::ZERO);
        assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 500);
        assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 900);
    }

    #[test]
    fn caches_within_ttl() {
        let s = Scripted::new(vec![Ok(Some(j("500")))]);
        let g = GovernedLimits::new(s.clone(), Duration::from_secs(60));
        for _ in 0..5 {
            assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 500);
        }
        assert_eq!(*s.calls.lock().unwrap(), 1);
    }

    #[test]
    fn limits_are_per_agent_and_per_kind() {
        let s = Scripted::new(vec![Ok(Some(j("500"))), Ok(None), Ok(None)]);
        let g = GovernedLimits::new(s, Duration::from_secs(60));
        assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 500);
        assert_eq!(g.effective("b", LimitKind::TokensCapacity, 1000), 1000);
        assert_eq!(g.effective("a", LimitKind::DeadlineNs, 2000), 2000);
    }

    #[test]
    fn file_source_reads_a_snapshot() {
        let dir = std::env::temp_dir().join(format!("gl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("limits.json");
        std::fs::write(&p, r#"{"stack.agent.a.tokens_capacity": 640}"#).unwrap();
        let g = GovernedLimits::new(FileSource { path: p.clone() }, Duration::ZERO);
        assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 640);
        std::fs::write(&p, "not json").unwrap();
        assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 640); // keeps last good
        assert_eq!(g.stats().source_errors, 1);
        let missing = GovernedLimits::new(FileSource { path: dir.join("nope.json") }, Duration::ZERO);
        assert_eq!(missing.effective("a", LimitKind::TokensCapacity, 1000), 1000);
    }

    /// A one-shot fake server returning `response`; yields the request it saw.
    fn serve_once(response: String) -> (u16, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).unwrap();
            s.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        (port, h)
    }

    fn http(port: u16, token: Option<&str>) -> HttpSource {
        HttpSource { host: "127.0.0.1".into(), port, token: token.map(String::from), timeout: Duration::from_secs(2) }
    }

    fn ok_body(body: &str) -> String {
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body)
    }

    #[test]
    fn http_source_reads_limit_and_sends_token() {
        let (port, h) = serve_once(ok_body(r#"{"boundary_id":"x","limit":729.0,"version":4}"#));
        let g = GovernedLimits::new(http(port, Some("tok")), Duration::ZERO);
        assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 729);
        let req = h.join().unwrap();
        assert!(req.starts_with("GET /boundaries/stack.agent.a.tokens_capacity HTTP/1.1"));
        assert!(req.contains("Authorization: Bearer tok"));
    }

    #[test]
    fn http_404_means_nothing_governed_yet() {
        let (port, _h) = serve_once("HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}".into());
        let g = GovernedLimits::new(http(port, None), Duration::ZERO);
        assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 1000);
        assert_eq!(g.stats().source_errors, 0);
    }

    #[test]
    fn http_errors_and_garbage_fall_back_safely() {
        for resp in [
            "HTTP/1.1 500 Oops\r\n\r\n{}".to_string(),
            "HTTP/1.1 401 Unauthorized\r\n\r\n{}".to_string(),
            "garbage".to_string(),
            ok_body("not json"),
            ok_body(r#"{"limit":"huge"}"#),
            ok_body(r#"{"limit":-1}"#),
        ] {
            let (port, _h) = serve_once(resp.clone());
            let g = GovernedLimits::new(http(port, None), Duration::ZERO);
            assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 1000, "{resp}");
        }
    }

    #[test]
    fn http_unreachable_falls_back_to_default() {
        // Bind then drop to get a port that refuses connections.
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let g = GovernedLimits::new(http(port, None), Duration::ZERO);
        assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 1000);
        assert_eq!(g.stats().source_errors, 1);
    }

    #[test]
    fn http_refuses_header_injection() {
        let src = http(1, Some("a\r\nX-Evil: 1"));
        assert!(src.fetch("stack.agent.a.tokens_capacity").is_err());
        let src = http(1, None);
        assert!(src.fetch("x HTTP/1.1\r\nHost: evil").is_err());
    }

    #[test]
    fn a_silent_server_times_out_instead_of_hanging() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let _h = thread::spawn(move || {
            let (_s, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_secs(3));
        });
        let src = HttpSource { host: "127.0.0.1".into(), port, token: None, timeout: Duration::from_millis(300) };
        let g = GovernedLimits::new(src, Duration::ZERO);
        let t = Instant::now();
        assert_eq!(g.effective("a", LimitKind::TokensCapacity, 1000), 1000);
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    /// Cross-language contract check against a live adjudication server. Run by hand or by CI:
    /// GOVERNED_E2E_PORT=8765 GOVERNED_E2E_TOKEN=... cargo test -p stack-p3-2 -- --ignored e2e
    /// The server must hold agent-7 (tokens_capacity 729 of 1000) and "weird agent/1" (deadline_ns 81).
    #[test]
    #[ignore]
    fn e2e_reads_limits_from_the_python_service() {
        let port: u16 = std::env::var("GOVERNED_E2E_PORT").unwrap().parse().unwrap();
        let token = std::env::var("GOVERNED_E2E_TOKEN").ok();
        let g = GovernedLimits::new(http(port, token.as_deref()), Duration::ZERO);
        assert_eq!(g.effective("agent-7", LimitKind::TokensCapacity, 1000), 729);
        assert_eq!(g.effective("weird agent/1", LimitKind::DeadlineNs, 100), 81);
        assert_eq!(g.effective("unknown-agent", LimitKind::TokensCapacity, 1000), 1000);
        assert_eq!(g.stats().source_errors, 0);
    }
}
