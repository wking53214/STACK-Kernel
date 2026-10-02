//! Logs carry input length and the full SHA-256 hex digest, never raw
//! input. Its own test binary: `tracing` caches per-callsite interest
//! process-wide, and a scoped subscriber in one test races with tests on
//! other threads that run with no subscriber.

#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

use std::io::Write;
use std::sync::{Arc, Mutex};
use sstack_anc_pipeline::telemetry::sha256_hex;
use sstack_anc_pipeline::{PipelineConfig, PipelineGate, TokenSecret, Validator, TOKEN_LEN};

// Test fixture, not a key. Printable so a raw leak into a log is easy to spot.
const FIXTURE: &[u8; TOKEN_LEN] = b"FIXTURE-not-a-key-0123456789abcd";

fn gate(validator: Validator, record_response_time: bool) -> PipelineGate {
    let cfg = PipelineConfig {
        validator,
        allow_leaky_validators: true,
        record_response_time,
        ..PipelineConfig::default()
    };
    PipelineGate::new(TokenSecret::from_bytes(FIXTURE).unwrap(), cfg).unwrap()
}

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

#[test]
fn logs_carry_length_and_full_digest_never_raw_input() {
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let oversized = [b'Q'; 100];
    tracing::subscriber::with_default(subscriber, || {
        let g = gate(Validator::ConstantTime, true);
        let _ = g.check(FIXTURE);
        let _ = g.check(&oversized);
    });
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    let digest = sha256_hex(FIXTURE);
    assert_eq!(digest.len(), 64);
    assert!(text.contains(&digest), "full digest logged: {text}");
    assert!(text.contains("input_len=32"), "{text}");
    assert!(text.contains("input_len=100"), "{text}");
    assert!(
        text.contains("tack.anc.pipeline_check"),
        "span name: {text}"
    );
    assert!(
        !text.contains("FIXTURE-not-a-key"),
        "raw input leaked: {text}"
    );
    assert!(!text.contains("QQQQ"), "raw oversized input leaked: {text}");
    assert!(
        !text.contains(&sha256_hex(&oversized)),
        "oversized input must not be hashed"
    );
}
