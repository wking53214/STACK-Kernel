//! Logs never carry raw input: only its length and full SHA-256 digest.
//!
//! This file holds exactly one test on purpose. tracing caches per-callsite
//! interest globally, and a concurrent test that hits the same callsites
//! with no subscriber can race the cache. One test per binary avoids that.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::{fixture, num, req, text};
use stack_bumpers::telemetry;

/// A `MakeWriter` that appends formatted log lines to a shared buffer.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn logs_carry_digest_and_length_never_raw_input() {
    let cap = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_writer(cap.clone())
        .finish();
    let secret_key = "SECRET-KEY-6f1d";
    let secret_val = "SECRET-VALUE-a9c2";
    tracing::subscriber::with_default(subscriber, || {
        let b = fixture();
        let _ = b.normalize(&req(&[(secret_key, num(1.0))]));
        let _ = b.normalize(&req(&[("priority", text(secret_val))]));
        let _ = b.normalize(&req(&[("timeout", num(f64::NAN))]));
        let _ = b.normalize(&req(&[("priority", text("High"))]));
    });
    let logs = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
    assert!(!logs.contains(secret_key), "raw key leaked");
    assert!(!logs.contains(secret_val), "raw value leaked");
    assert!(logs.contains(&telemetry::sha256_hex(secret_key.as_bytes())));
    assert!(logs.contains(&telemetry::sha256_hex(secret_val.as_bytes())));
    assert!(logs.contains(&format!("input_len={}", secret_val.len())));
    assert!(logs.contains("tack.bumpers.normalize"));
    assert!(logs.contains("reason=\"unknown_param\"") || logs.contains("reason=unknown_param"));
    assert!(logs.contains("WARN"), "terminal breach logs at warn");
    assert!(logs.contains("bumper correction"));
    assert!(logs.contains("tack.bumpers.build"));
}
