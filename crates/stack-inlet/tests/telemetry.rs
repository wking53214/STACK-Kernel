//! The metrics and log events fire, carry only closed-enum labels, and never
//! carry raw input.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use metrics_util::MetricKind;
use stack_inlet::telemetry::{
    INPUT_BYTES, QUARANTINED_TOTAL, REASON_SEEN_TOTAL, SCAN_DURATION_SECONDS,
    STREAMS_ABANDONED_TOTAL, VERDICTS_TOTAL, VIOLATIONS_TOTAL,
};
use stack_inlet::{Feed, Inlet, InletConfig, StreamConfig};

type Row = (MetricKind, String, Vec<(String, String)>, DebugValue);

fn capture(f: impl FnOnce()) -> Vec<Row> {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, f);
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(ck, _, _, v)| {
            let (kind, key) = ck.into_parts();
            let mut labels: Vec<(String, String)> = key
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            labels.sort();
            (kind, key.name().to_string(), labels, v)
        })
        .collect()
}

fn counter(rows: &[Row], name: &str, labels: &[(&str, &str)]) -> u64 {
    let mut want: Vec<(String, String)> = labels
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    want.sort();
    rows.iter()
        .filter(|r| r.0 == MetricKind::Counter && r.1 == name && r.2 == want)
        .map(|r| match r.3 {
            DebugValue::Counter(n) => n,
            _ => 0,
        })
        .sum()
}

fn histogram_len(rows: &[Row], name: &str) -> usize {
    rows.iter()
        .filter(|r| r.0 == MetricKind::Histogram && r.1 == name)
        .map(|r| match &r.3 {
            DebugValue::Histogram(v) => v.len(),
            _ => 0,
        })
        .sum()
}

#[test]
fn metrics_fire_for_every_outcome() {
    let rows = capture(|| {
        let inlet = Inlet::new(InletConfig { max_len: 32 }).unwrap();
        let _ = inlet.winnow(b"fine");
        let _ = inlet.winnow(b"a\x00b\x01");
        let _ = inlet.winnow("x\u{202E}y\u{FEFF}".as_bytes());
        let _ = inlet.winnow(&[b'a'; 33]);
        let _ = inlet.precheck(1 << 40);
        assert!(
            inlet.precheck(3).is_ok(),
            "a passing precheck emits nothing"
        );
        let mut sc = inlet.scanner();
        assert_eq!(sc.feed(b"\xC0"), Feed::Continue);
        assert_eq!(sc.feed(b"\xAF"), Feed::Continue);
        let _ = sc.finish();
    });

    assert_eq!(
        counter(
            &rows,
            VERDICTS_TOTAL,
            &[("outcome", "pass"), ("reason", "none")]
        ),
        1
    );
    assert_eq!(
        counter(
            &rows,
            VERDICTS_TOTAL,
            &[("outcome", "retry"), ("reason", "c0_control")]
        ),
        1
    );
    assert_eq!(
        counter(
            &rows,
            VERDICTS_TOTAL,
            &[("outcome", "terminal_breach"), ("reason", "bidi_control")]
        ),
        1
    );
    assert_eq!(
        counter(
            &rows,
            VERDICTS_TOTAL,
            &[("outcome", "retry"), ("reason", "oversize")]
        ),
        2
    );
    assert_eq!(
        counter(
            &rows,
            VERDICTS_TOTAL,
            &[("outcome", "terminal_breach"), ("reason", "overlong")]
        ),
        1
    );
    // 2 controls + (bidi + BOM) + 2 oversize + (overlong + stray continuation).
    assert_eq!(counter(&rows, VIOLATIONS_TOTAL, &[]), 8);
    assert_eq!(
        counter(&rows, REASON_SEEN_TOTAL, &[("reason", "c0_control")]),
        1
    );
    assert_eq!(
        counter(&rows, REASON_SEEN_TOTAL, &[("reason", "bidi_control")]),
        1
    );
    assert_eq!(
        counter(&rows, REASON_SEEN_TOTAL, &[("reason", "zero_width")]),
        1
    );
    assert_eq!(
        counter(&rows, REASON_SEEN_TOTAL, &[("reason", "oversize")]),
        2
    );
    assert_eq!(
        counter(&rows, REASON_SEEN_TOTAL, &[("reason", "overlong")]),
        1
    );
    assert_eq!(
        counter(
            &rows,
            REASON_SEEN_TOTAL,
            &[("reason", "unexpected_continuation")]
        ),
        1
    );
    assert_eq!(counter(&rows, QUARANTINED_TOTAL, &[]), 2);
    assert_eq!(histogram_len(&rows, INPUT_BYTES), 6);
    assert_eq!(histogram_len(&rows, SCAN_DURATION_SECONDS), 6);
}

#[test]
fn labels_are_closed_enums_and_names_follow_convention() {
    let rows = capture(|| {
        let inlet = Inlet::new(InletConfig::default()).unwrap();
        for b in 0..=255u8 {
            let _ = inlet.winnow(&[b, b'z', b]);
        }
    });
    let outcomes = ["pass", "retry", "terminal_breach"];
    let reasons: Vec<&str> = tack_inlet::Reason::ALL
        .iter()
        .map(|r| r.as_str())
        .chain(std::iter::once("none"))
        .collect();
    for (kind, name, labels, _) in &rows {
        assert!(name.starts_with("tack_inlet_"), "{name}");
        if *kind == MetricKind::Counter {
            assert!(name.ends_with("_total"), "{name}");
        }
        for (k, v) in labels {
            match k.as_str() {
                "outcome" => assert!(outcomes.contains(&v.as_str()), "{v}"),
                "reason" => assert!(reasons.contains(&v.as_str()), "{v}"),
                other => panic!("unexpected label {other}"),
            }
        }
    }
}

#[test]
fn abandoned_streams_and_chunk_limit_are_recorded() {
    let rows = capture(|| {
        let inlet = Inlet::with_stream_config(
            InletConfig { max_len: 64 },
            StreamConfig { max_chunks: 2 },
        )
        .unwrap();
        // Abandoned with a Trojan Source character pending.
        let mut sc = inlet.scanner();
        assert_eq!(sc.feed("a\u{202E}b".as_bytes()), Feed::Continue);
        drop(sc);
        // Abandoned while clean: counted, but no verdict is issued.
        let mut sc = inlet.scanner();
        assert_eq!(sc.feed(b"clean"), Feed::Continue);
        drop(sc);
        // Finished normally: not counted as abandoned.
        let mut sc = inlet.scanner();
        assert_eq!(sc.feed(b"ok"), Feed::Continue);
        let _ = sc.finish();
        // Chunk cap.
        let mut sc = inlet.scanner();
        assert_eq!(sc.feed(b""), Feed::Continue);
        assert_eq!(sc.feed(b""), Feed::Continue);
        assert_eq!(sc.feed(b""), Feed::OverLimit);
        let _ = sc.finish();
    });
    assert_eq!(
        counter(
            &rows,
            STREAMS_ABANDONED_TOTAL,
            &[("outcome", "terminal_breach")]
        ),
        1
    );
    assert_eq!(
        counter(&rows, STREAMS_ABANDONED_TOTAL, &[("outcome", "pass")]),
        1
    );
    assert_eq!(counter(&rows, QUARANTINED_TOTAL, &[]), 1);
    assert_eq!(
        counter(
            &rows,
            VERDICTS_TOTAL,
            &[("outcome", "pass"), ("reason", "none")]
        ),
        1,
        "only the finished clean stream issues a pass verdict"
    );
    assert_eq!(
        counter(
            &rows,
            VERDICTS_TOTAL,
            &[("outcome", "retry"), ("reason", "chunk_limit")]
        ),
        1
    );
}
