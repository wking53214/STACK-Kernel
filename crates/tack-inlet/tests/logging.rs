//! Log events carry length and, with a deployment key, the full keyed digest;
//! never raw input and never the plain SHA-256.
//!
//! Kept in its own test binary with a single test: `tracing` caches per
//! callsite whether anyone is listening, and a parallel test that hits the
//! same callsite with no subscriber can race that cache and hide events from
//! a thread-local subscriber installed here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::sync::{Arc, Mutex};

use tack_inlet::telemetry::LogKey;
use tack_inlet::{Inlet, InletConfig};

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
    type Writer = Buf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn logs_carry_length_and_keyed_digest_never_raw_input_or_plain_digest() {
    let buf = Buf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .finish();
    let secret = "SECRET-PAYLOAD-\u{202E}-DO-NOT-LOG";
    // TEST FIXTURE KEY: a fixed byte pattern, labelled as such, never a
    // deployment key.
    let fixture: Vec<u8> = (0u8..32).map(|b| b.wrapping_mul(37) ^ 0x5A).collect();
    let key = LogKey::new(&fixture).unwrap();
    let (refused, passed, unkeyed) = tracing::subscriber::with_default(subscriber, || {
        let inlet = Inlet::new(InletConfig::default())
            .unwrap()
            .with_log_key(key.clone());
        let plain = Inlet::new(InletConfig::default()).unwrap();
        (
            inlet.winnow(secret.as_bytes()),
            inlet.winnow(b"CLEAN-PAYLOAD-DO-NOT-LOG"),
            plain.winnow(b"UNKEYED-PAYLOAD"),
        )
    });
    let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(!out.contains("SECRET-PAYLOAD"), "{out}");
    assert!(!out.contains("CLEAN-PAYLOAD"), "{out}");
    assert!(!out.contains("UNKEYED-PAYLOAD"), "{out}");
    let hex = |t: [u8; 32]| t.iter().map(|b| format!("{b:02x}")).collect::<String>();
    for v in [&refused, &passed, &unkeyed] {
        assert!(
            !out.contains(&v.sha256_hex().unwrap()),
            "plain digest must not be logged: {out}"
        );
    }
    for v in [&refused, &passed] {
        let tag = hex(key.log_tag(v.sha256().unwrap()));
        assert_eq!(tag.len(), 64);
        assert!(
            out.contains(&format!("input_hmac={tag}")),
            "full keyed digest logged: {out}"
        );
    }
    assert!(out.contains("input_hmac=unkeyed"), "{out}");
    assert!(
        out.contains("tack.inlet.winnow"),
        "span name present: {out}"
    );
    assert!(
        out.contains("reason=\"bidi_control\"") || out.contains("reason=bidi_control"),
        "{out}"
    );
    assert!(out.contains(&format!("len={}", secret.len())), "{out}");
}
