//! The durable file log: creation, reopen, locking, torn tails, every
//! corruption, and a real crash between Attempted and the terminal event.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::*;
use stack_receipt::{
    parse_log, FileReceiptLog, Head, LogError, ManualClock, MemoryReceiptLog, ReceiptLog, Recorder, Stage,
    HEADER_LEN, MAGIC, SLOT_LEN,
};

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stack-receipt-log-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipts.log");
    let _ = std::fs::remove_file(&path);
    path
}

fn open(path: &PathBuf) -> Result<FileReceiptLog, LogError> {
    FileReceiptLog::open(path, "kernel-1", &[fixture_public_key("kernel-1")])
}

/// Writes the four honest events through a fresh log and returns the
/// file's bytes.
fn honest_log(path: &PathBuf) -> Vec<u8> {
    let mut log = open(path).unwrap();
    for s in sign_chain(honest_events()) {
        log.append(&s).unwrap();
    }
    drop(log);
    std::fs::read(path).unwrap()
}

#[test]
fn open_creates_the_header_and_records_survive_reopen() {
    let path = temp("roundtrip");
    let log = open(&path).unwrap();
    assert!(log.is_durable());
    assert_eq!(log.head().unwrap(), Head::genesis());
    assert_eq!(log.committed_len(), HEADER_LEN);
    assert_eq!(log.records(), 0);
    drop(log);
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len() as u64, HEADER_LEN);
    assert_eq!(&bytes[..32], MAGIC);

    let chain = sign_chain(honest_events());
    let mut log = open(&path).unwrap();
    for s in &chain {
        log.append(s).unwrap();
    }
    let head = log.head().unwrap();
    assert_eq!(head.sequence, 4);
    assert_eq!(head.hash, *chain[3].hash());
    drop(log);

    let log = open(&path).unwrap();
    assert_eq!(log.head().unwrap(), head);
    assert_eq!(log.records(), 4);
    let parsed = FileReceiptLog::read_file(&path).unwrap();
    assert_eq!(parsed.records, chain);
    assert!(!parsed.adopted_tail);
    assert_eq!(parsed.discarded_tail_bytes, 0);
    assert_eq!(parsed.generation, 4);
}

#[test]
fn the_lock_is_exclusive_while_held() {
    let path = temp("lock");
    let log = open(&path).unwrap();
    assert!(matches!(open(&path), Err(LogError::Locked { .. })));
    drop(log);
    assert!(open(&path).is_ok());
}

#[test]
fn a_record_that_does_not_chain_or_names_another_kernel_or_key_is_refused() {
    let path = temp("chain");
    let mut log = open(&path).unwrap();
    let chain = sign_chain(honest_events());
    assert!(matches!(log.append(&chain[1]), Err(LogError::DoesNotChain { .. })));
    log.append(&chain[0]).unwrap();
    assert!(matches!(log.append(&chain[0]), Err(LogError::DoesNotChain { .. })), "replayed");
    assert!(matches!(log.append(&chain[2]), Err(LogError::DoesNotChain { .. })), "skipped");
    let other_key = sign_chain_with(&fixture_signer("kernel-2"), honest_events());
    let mut second = other_key[1].clone();
    // Same chain position, different signer: the prev hash does not match
    // because the first record differs; build one that chains but is
    // signed under the wrong key.
    let mut r = second.record().clone();
    r.prev_hash = *chain[0].hash();
    second = fixture_signer("kernel-2").sign(r).unwrap();
    assert_eq!(log.append(&second), Err(LogError::BadSignature));
    assert!(log.append(&chain[1]).is_ok(), "the log is not poisoned by a refused record");
    drop(log);
    assert!(matches!(
        FileReceiptLog::open(&path, "kernel-2", &[fixture_public_key("kernel-1")]),
        Err(LogError::Corrupt { .. })
    ));
    assert!(matches!(
        FileReceiptLog::open(&path, "kernel-1", &[fixture_public_key("kernel-2")]),
        Err(LogError::Corrupt { .. })
    ));
    assert!(matches!(
        FileReceiptLog::open(&path, "kernel-1", &[]),
        Err(LogError::BadConfig(_))
    ));
}

#[test]
fn a_torn_frame_write_at_every_cut_point_is_discarded_and_cut_off_at_the_next_write() {
    let path = temp("torn");
    let full = honest_log(&path);
    let chain = sign_chain(honest_events());
    // Rebuild a log holding three records and a committed length, then
    // append the bytes of the fourth frame cut at every length.
    let three = {
        let p = temp("torn-three");
        let mut l = open(&p).unwrap();
        for s in &chain[..3] {
            l.append(s).unwrap();
        }
        let committed = l.committed_len();
        drop(l);
        let bytes = std::fs::read(&p).unwrap();
        assert_eq!(bytes.len() as u64, committed);
        bytes
    };
    let frame = chain[3].to_frame();
    assert!(full.ends_with(&frame));
    for cut in 0..frame.len() {
        let mut bytes = three.clone();
        bytes.extend_from_slice(&frame[..cut]);
        std::fs::write(&path, &bytes).unwrap();
        let parsed = parse_log(&bytes).unwrap_or_else(|e| panic!("cut {cut}: {e}"));
        assert_eq!(parsed.records.len(), 3, "cut {cut}");
        assert_eq!(parsed.discarded_tail_bytes, cut as u64, "cut {cut}");
        assert!(!parsed.adopted_tail);
        let mut log = open(&path).unwrap_or_else(|e| panic!("cut {cut}: {e}"));
        assert_eq!(log.records(), 3);
        log.append(&chain[3]).unwrap();
        drop(log);
        assert_eq!(std::fs::read(&path).unwrap().len(), full.len(), "cut {cut}: tail cut off");
        let log = open(&path).unwrap();
        assert_eq!(log.records(), 4);
    }
}

#[test]
fn a_complete_frame_past_the_committed_length_is_adopted_and_committed() {
    // A crash between the frame sync and the slot write.
    let path = temp("adopt");
    let full = honest_log(&path);
    let chain = sign_chain(honest_events());
    let p3 = temp("adopt-three");
    let mut l = open(&p3).unwrap();
    for s in &chain[..3] {
        l.append(s).unwrap();
    }
    drop(l);
    let mut bytes = std::fs::read(&p3).unwrap();
    bytes.extend_from_slice(&chain[3].to_frame());
    assert_eq!(bytes.len(), full.len());
    let parsed = parse_log(&bytes).unwrap();
    assert!(parsed.adopted_tail);
    assert_eq!(parsed.records.len(), 4);
    assert_eq!(parsed.committed_len, full.len() as u64);
    std::fs::write(&path, &bytes).unwrap();
    let log = open(&path).unwrap();
    assert_eq!(log.records(), 4);
    assert_eq!(log.committed_len(), full.len() as u64);
    drop(log);
    let parsed = FileReceiptLog::read_file(&path).unwrap();
    assert!(!parsed.adopted_tail, "the reopen finished the commit");
    assert_eq!(parsed.generation, 4);
}

/// Every flipped byte either fails open, or (only inside the newest
/// header slot) makes the older slot win and the last frame be adopted
/// as a torn slot write, which yields exactly the same records. No flip
/// anywhere makes the log present different content as valid.
#[test]
fn every_single_byte_flip_of_a_clean_log_fails_closed_or_yields_identical_records() {
    let path = temp("flip");
    let clean = honest_log(&path);
    let clean_records = parse_log(&clean).unwrap().records;
    let (mut refused, mut identical) = (0, 0);
    let newest_slot = 32..(32 + SLOT_LEN) as usize; // generation 4 is even: slot A
    for i in 0..clean.len() {
        let mut bytes = clean.clone();
        bytes[i] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();
        match open(&path) {
            Ok(log) => {
                assert!(newest_slot.contains(&i), "byte {i}: accepted outside the newest slot");
                assert_eq!(log.records(), 4);
                drop(log);
                let reread = FileReceiptLog::read_file(&path).unwrap();
                assert_eq!(reread.records, clean_records, "byte {i}: content differs");
                identical += 1;
            }
            Err(LogError::Corrupt { .. } | LogError::Truncated { .. }) => refused += 1,
            Err(e) => panic!("byte {i}: {e}"),
        }
    }
    assert_eq!(refused + identical, clean.len());
    assert!(identical <= SLOT_LEN as usize);
    assert!(identical > 0, "a damaged newest slot with an intact last frame is a torn slot write");
}

#[test]
fn other_damage_fails_closed_on_open() {
    let path = temp("damage");
    let clean = honest_log(&path);
    let chain = sign_chain(honest_events());
    // Whole file zeroed.
    std::fs::write(&path, vec![0u8; clean.len()]).unwrap();
    assert!(matches!(open(&path), Err(LogError::Corrupt { .. })));
    // Shorter than the header.
    std::fs::write(&path, &clean[..10]).unwrap();
    assert!(matches!(open(&path), Err(LogError::Corrupt { .. })));
    // Committed region truncated: records that were acknowledged are gone.
    std::fs::write(&path, &clean[..clean.len() - 1]).unwrap();
    assert!(matches!(open(&path), Err(LogError::Truncated { .. })));
    // Two records swapped.
    let f: Vec<Vec<u8>> = chain.iter().map(|s| s.to_frame()).collect();
    let mut swapped = clean[..HEADER_LEN as usize].to_vec();
    for i in [0, 2, 1, 3] {
        swapped.extend_from_slice(&f[i]);
    }
    std::fs::write(&path, &swapped).unwrap();
    assert!(matches!(open(&path), Err(LogError::Corrupt { .. })));
    // A record removed from the middle.
    let mut removed = clean[..HEADER_LEN as usize].to_vec();
    for i in [0, 2, 3] {
        removed.extend_from_slice(&f[i]);
    }
    std::fs::write(&path, &removed).unwrap();
    assert!(matches!(
        open(&path),
        Err(LogError::Corrupt { .. } | LogError::Truncated { .. })
    ));
    // A record duplicated.
    let mut dup = clean.clone();
    dup.extend_from_slice(&f[3]);
    std::fs::write(&path, &dup).unwrap();
    assert!(matches!(open(&path), Err(LogError::Corrupt { .. })), "a duplicate past the commit is not a torn frame");
    // Junk appended that is not a frame prefix.
    let mut junk = clean.clone();
    junk.extend_from_slice(b"junk");
    std::fs::write(&path, &junk).unwrap();
    assert!(matches!(open(&path), Err(LogError::Corrupt { .. })));
    // A plausible but too long tail.
    let mut long = clean.clone();
    long.extend_from_slice(&vec![0u8; (stack_receipt::MAX_FRAME_BYTES + 1) as usize]);
    std::fs::write(&path, &long).unwrap();
    assert!(matches!(open(&path), Err(LogError::Corrupt { .. })));
    // The unused slot zeroed on a non-genesis log: not a clean pair.
    let mut zeroed = clean.clone();
    let slot_b = (32 + SLOT_LEN) as usize..HEADER_LEN as usize;
    let slot_a = 32..(32 + SLOT_LEN) as usize;
    // Generation 4 lives in slot A (even); slot B holds generation 3.
    zeroed[slot_b.clone()].fill(0);
    std::fs::write(&path, &zeroed).unwrap();
    assert!(matches!(open(&path), Err(LogError::Corrupt { .. })));
    // The newest slot zeroed with the last frame intact is exactly what a
    // crash during the slot write leaves: the frame is adopted and the
    // same four records come back.
    let mut zeroed = clean.clone();
    zeroed[slot_a].fill(0);
    std::fs::write(&path, &zeroed).unwrap();
    let log = open(&path).unwrap();
    assert_eq!(log.records(), 4);
    drop(log);
    assert_eq!(FileReceiptLog::read_file(&path).unwrap().records, chain);
    // But the newest slot zeroed AND the last frame gone is a loss the
    // older slot would hide: the file is then shorter than nothing
    // commits, and the older slot is the only one left; this is the
    // rollback case pinned below, which the file alone cannot detect.
}

#[test]
fn rollback_to_an_earlier_committed_state_is_not_detected_by_the_file_alone() {
    // Pinned as a limitation: an attacker who rewrites both slots
    // consistently can present an older log. head() is the anchor.
    let path = temp("rollback");
    let chain = sign_chain(honest_events());
    let mut log = open(&path).unwrap();
    for s in &chain[..3] {
        log.append(s).unwrap();
    }
    drop(log);
    let three = std::fs::read(&path).unwrap();
    let mut log = open(&path).unwrap();
    log.append(&chain[3]).unwrap();
    let anchored = log.head().unwrap();
    drop(log);
    std::fs::write(&path, &three).unwrap();
    let log = open(&path).unwrap();
    assert_eq!(log.records(), 3, "the rolled-back log opens");
    assert_ne!(log.head().unwrap(), anchored, "only the external anchor tells");
}

#[test]
fn a_memory_log_is_not_durable_and_still_enforces_the_chain() {
    let mut m = MemoryReceiptLog::new("kernel-1").unwrap();
    assert!(!m.is_durable());
    let chain = sign_chain(honest_events());
    assert!(matches!(m.append(&chain[1]), Err(LogError::DoesNotChain { .. })));
    m.append(&chain[0]).unwrap();
    m.append(&chain[1]).unwrap();
    assert_eq!(m.records().len(), 2);
    assert_eq!(m.head().unwrap().sequence, 2);
    assert!(MemoryReceiptLog::new("").is_err());
}

/// The kernel dies between Attempted and the terminal event. A child copy
/// of this test binary writes Proposed, Authorized and Attempted, signals
/// that it is "executing", and is SIGKILLed by the parent. The reopened
/// log must hold exactly those three records with the attempt open.
#[test]
fn a_process_killed_between_attempted_and_terminal_leaves_the_attempt_open() {
    const CHILD_ENV: &str = "STACK_RECEIPT_KILL_CHILD_LOG";
    if let Some(path) = std::env::var_os(CHILD_ENV) {
        let path = PathBuf::from(path);
        let log = open(&path).unwrap();
        let recorder = Recorder::new(
            Box::new(log),
            fixture_signer("kernel-1"),
            provenance(),
            Box::new(ManualClock::new(T0)),
        )
        .unwrap();
        let stack_receipt::Event::Proposed(p) = proposed() else { panic!() };
        let stack_receipt::Event::Authorized(a) = authorized() else { panic!() };
        let stack_receipt::Event::Attempted(at) = attempted() else { panic!() };
        let exec = recorder.propose(exec_id(), p).unwrap();
        let exec = exec.authorize_with(a).unwrap();
        let _running = exec.attempt(at.action, at.started_at_ms).unwrap();
        // "Executing": tell the parent, then wait to be killed.
        std::fs::write(path.with_extension("attempted"), b"1").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(120));
        panic!("the parent did not kill this child");
    }
    let path = temp("kill");
    let marker = path.with_extension("attempted");
    let _ = std::fs::remove_file(&marker);
    let exe = std::env::current_exe().unwrap();
    let mut child = std::process::Command::new(exe)
        .args([
            "--exact",
            "a_process_killed_between_attempted_and_terminal_leaves_the_attempt_open",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, &path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !marker.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("child exited before attempting: {status}");
        }
        assert!(std::time::Instant::now() < deadline, "child never reached Attempted");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    child.kill().unwrap(); // SIGKILL on Unix
    let status = child.wait().unwrap();
    assert!(!status.success());
    // The kernel's lock died with it; the log reopens and shows the
    // attempt with no terminal event.
    let log = open(&path).unwrap();
    assert_eq!(log.records(), 3);
    let parsed = FileReceiptLog::read_file(&path).unwrap();
    let stages: Vec<Stage> = parsed.records.iter().map(|r| r.record().stage()).collect();
    assert_eq!(stages, [Stage::Proposed, Stage::Authorized, Stage::Attempted]);
    assert!(!parsed.adopted_tail);
    assert_eq!(parsed.discarded_tail_bytes, 0);
    // The verifier: INCOMPLETE with an unknown outcome, never success.
    let v = stack_receipt::verify_log_bytes(
        &std::fs::read(&path).unwrap(),
        &baseline_trust(),
        &stack_receipt::Expectations::default(),
    );
    assert_eq!(v.state, stack_receipt::State::Incomplete);
    assert_eq!(v.executions.len(), 1);
    assert_eq!(v.executions[0].execution.outcome, Some(stack_receipt::OutcomeKind::Unknown));
    assert_eq!(v.executions[0].findings[0].code, stack_receipt::FindingCode::TerminalMissing);
}
