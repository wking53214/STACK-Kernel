//! Shared fixtures for the admission tests. Every key here is a TEST
//! FIXTURE derived from a public label and must never be used outside
//! tests. This module holds the only capability-signing path in the
//! crate: the translating issuer of decision E lives outside the kernel
//! and outside CNS, and these tests stand in for it.

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stack_admission::{
    Admission, AdmissionResult, BuildError, ExecutionLimits, Executor, ExecutorError, KernelPolicy, Parts, Refused, RunReport,
    SupervisedExecutor, WorkerConfig, WorkerKind,
};
use stack_authority::{
    Capability, Digest32, FileUseStore, ManualClock, PublicKey, Purpose, ResourceScope, RevocationList, TrustAnchor,
    TrustSet, NONCE_BYTES,
};
use stack_receipt::{
    Expectations, FileReceiptLog, LogVerification, Provenance, ReceiptKeyAnchor, ReceiptLog, ReceiptPublicKey,
    ReceiptSigner, Stage as ReceiptStage, State, TrustedReceiptKeys,
};
use stack_trident::{
    seal_for, EnvelopeDraft, FileStore, GateOutcome, GatePosition, KeyMeta, KeyPurpose, KeyRing, Nonce, SecretKey,
    StartError, StoreError, TridentConfig,
};

/// The real executor for tests: the worker program this build compiled, the
/// capability bit granted once for the whole test process (a second change
/// would make the first one's in-flight runs wait), one token per run.
pub fn test_executor() -> SupervisedExecutor {
    static GRANT: std::sync::Once = std::sync::Once::new();
    let executor = SupervisedExecutor::new(WorkerConfig {
        worker_path: PathBuf::from(stack_ffi::WORKER_BUILD_PATH),
        worker_sha256: Some(
            stack_ffi::worker_image_sha256(&std::ffi::CString::new(stack_ffi::WORKER_BUILD_PATH).expect("no NUL"))
                .expect("hash the worker build"),
        ),
        context_id: 0,
        required_capabilities: 0x01,
        tokens_per_run: 1,
        reap_timeout_ns: 0,
    })
    .expect("the test worker is usable");
    GRANT.call_once(|| stack_ffi::host_set_capabilities(0x01, 0, 0, 0).expect("grant the test capability"));
    executor
}

/// Start of test time (a fixed Unix ms value).
pub const T0: u64 = 1_800_000_000_000;
/// One hour in milliseconds.
pub const HOUR: u64 = 3_600_000;
/// One day in milliseconds.
pub const DAY: u64 = 24 * HOUR;
/// The kernel under test: its receipt kernel id and its audience.
pub const KERNEL: &str = "kernel-a";
/// The trusted capability issuer's id.
pub const ISSUER: &str = "issuer-1";
/// The Trident sender's key label.
pub const SENDER: &str = "sender-a";
/// The execution deadline every harness uses.
pub const DEADLINE_NS: u64 = 300_000_000;
/// The CNS commit the fixtures were produced at.
pub const CNS_COMMIT: &str = "4acd8f958a091900d43f553eba7fe83f7d33c4d6";

// ---------------------------------------------------------------------------
// TEST FIXTURE keys
// ---------------------------------------------------------------------------

/// A deterministic 32-byte value from a public label.
pub fn fixture_bytes32(label: &str) -> [u8; 32] {
    Sha256::digest(format!("stack-admission TEST FIXTURE: {label}").as_bytes()).into()
}

/// TEST FIXTURE Trident sender key.
pub fn trident_key(label: &str) -> SecretKey {
    SecretKey::from_bytes(fixture_bytes32(&format!("trident {label}")).to_vec()).unwrap()
}

/// TEST FIXTURE capability issuer signing key. Not a key anyone deploys.
pub fn issuer_signing_key(label: &str) -> SigningKey {
    SigningKey::from_bytes(&fixture_bytes32(&format!("issuer {label}")))
}

/// The public half of the fixture issuer key.
pub fn issuer_public_key(label: &str) -> PublicKey {
    PublicKey::from_bytes(issuer_signing_key(label).verifying_key().to_bytes()).unwrap()
}

/// TEST FIXTURE receipt signing key for the kernel.
pub fn receipt_signer(label: &str) -> ReceiptSigner {
    ReceiptSigner::from_secret_bytes(&fixture_bytes32(&format!("receipt {label}"))).unwrap()
}

/// The public half of the fixture receipt key.
pub fn receipt_public_key(label: &str) -> ReceiptPublicKey {
    *receipt_signer(label).public_key()
}

/// The receipt keys an auditor trusts for `KERNEL`: the fixture key
/// `KERNEL`, valid from `T0 - DAY` to `T0 + DAY`. Built fresh by the
/// auditor; nothing the producer said goes into it.
pub fn receipt_trust() -> TrustedReceiptKeys {
    let mut t = TrustedReceiptKeys::new(16);
    t.insert(ReceiptKeyAnchor::new(KERNEL, receipt_public_key(KERNEL), T0 - DAY, T0 + DAY).unwrap())
        .unwrap();
    t
}

/// A trust set holding `ISSUER` under the fixture key `ISSUER`.
pub fn issuer_trust() -> TrustSet {
    let mut ts = TrustSet::new(16);
    ts.insert(TrustAnchor::new(ISSUER, issuer_public_key(ISSUER), Purpose::CapabilityIssuer, T0 - DAY, T0 + DAY).unwrap())
        .unwrap();
    ts
}

/// A key ring holding the fixture sender key with issuer metadata, as
/// the Production profile requires.
pub fn sender_ring() -> KeyRing {
    let mut ring = KeyRing::new(16);
    ring.insert_with_meta(
        trident_key(SENDER),
        KeyMeta::new("issuer:test-fixture", KeyPurpose::Handoff, 0, None).unwrap(),
    )
    .unwrap();
    ring
}

// ---------------------------------------------------------------------------
// CNS fixtures
// ---------------------------------------------------------------------------

/// Every case of `tests/fixtures/cns-governed-decisions.json`.
pub fn load_cases() -> Vec<Value> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cns-governed-decisions.json");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(file["schema"].as_str(), Some("stack-admission-cns-governed-decisions/1"));
    assert_eq!(file["cns_commit"].as_str(), Some(CNS_COMMIT));
    file["cases"].as_array().unwrap().clone()
}

/// One case by name.
pub fn case(name: &str) -> Value {
    load_cases()
        .into_iter()
        .find(|c| c["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("no fixture case {name}"))
}

/// The CNS subject digest the fixture records for a case.
pub fn case_subject_digest(case: &Value) -> Digest32 {
    Digest32::from_hex(case["subject_digest"].as_str().unwrap()).unwrap()
}

/// The decision root the real SuperGate produced for a case.
pub fn case_root(case: &Value) -> Digest32 {
    Digest32::from_hex(case["root"].as_str().unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// Policy and executor
// ---------------------------------------------------------------------------

/// The kernel policy under test: `kernel-a`, requiring the door and the
/// judge, mapping one name per worker kind.
pub fn policy() -> KernelPolicy {
    KernelPolicy {
        kernel_id: KERNEL.into(),
        audience: KERNEL.into(),
        required_seats: vec!["Governance_Gateway:door".into(), "DIT:judge".into()],
        seat_positions: BTreeMap::from([
            ("Governance_Gateway:door".to_owned(), stack_receipt::GatePosition::Alpha),
            ("DIT:judge".to_owned(), stack_receipt::GatePosition::Omega),
        ]),
        operations: BTreeMap::from([
            ("echo".to_owned(), WorkerKind::ReturnBytes),
            ("spin".to_owned(), WorkerKind::SpinForever),
            ("block".to_owned(), WorkerKind::BlockForever),
            ("crash".to_owned(), WorkerKind::Crash),
            ("abort".to_owned(), WorkerKind::Abort),
            ("exit".to_owned(), WorkerKind::ExitNonZero),
            ("forbidden".to_owned(), WorkerKind::ForbiddenSyscall),
        ]),
        limits: ExecutionLimits::with_deadline_ns(DEADLINE_NS),
        provenance: Provenance {
            component: "stack-admission".into(),
            version: "0.1.0-test".into(),
            host_id: "test-host".into(),
        },
    }
}

/// The side-effect witness: counts every run the executor is asked for and
/// records which receipt stages were already durable in the log FILE at
/// the instant the run began. A refusal test asserts the count is
/// untouched; the ordering test asserts `attempted` was on disk first.
///
/// The built-in workers cannot write a counter file themselves: they run
/// under a seccomp filter that kills any `open(2)`. This wrapper sits at
/// the executor seam, which is the only place a run can be observed from
/// outside the worker.
#[derive(Debug)]
pub struct CountingExecutor {
    pub inner: Box<dyn Executor>,
    pub runs: Arc<AtomicUsize>,
    pub receipts: PathBuf,
    pub seen: Arc<Mutex<Vec<Vec<ReceiptStage>>>>,
}

impl Executor for CountingExecutor {
    fn run(&self, kind: WorkerKind, limits: &ExecutionLimits, args: &[u8]) -> Result<RunReport, ExecutorError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        let stages = std::fs::read(&self.receipts)
            .ok()
            .and_then(|b| stack_receipt::parse_log(&b).ok())
            .map(|p| p.records.iter().map(|r| r.record().stage()).collect())
            .unwrap_or_default();
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(stages);
        }
        self.inner.run(kind, limits, args)
    }
}

/// An executor that returns a fixed answer, for the contradictory and
/// failing reports a real supervisor should never produce.
#[derive(Debug)]
pub struct ScriptedExecutor(pub Result<RunReport, ExecutorError>);

impl Executor for ScriptedExecutor {
    fn run(&self, _: WorkerKind, _: &ExecutionLimits, _: &[u8]) -> Result<RunReport, ExecutorError> {
        self.0.clone()
    }
}

/// A durable log whose `append` fails on chosen calls (1-based), without
/// touching the file: receipt generation breaks at a chosen point.
#[derive(Debug)]
pub struct FailingFileLog {
    pub inner: FileReceiptLog,
    pub fail_on: Vec<usize>,
    pub calls: usize,
}

impl FailingFileLog {
    pub fn open(dir: &Path, fail_on: &[usize]) -> Self {
        let inner = FileReceiptLog::open(receipts_path(dir), KERNEL, &[receipt_public_key(KERNEL)]).unwrap();
        Self {
            inner,
            fail_on: fail_on.to_vec(),
            calls: 0,
        }
    }
}

impl ReceiptLog for FailingFileLog {
    fn kernel_id(&self) -> &str {
        self.inner.kernel_id()
    }
    fn head(&self) -> Result<stack_receipt::Head, stack_receipt::LogError> {
        self.inner.head()
    }
    fn append(&mut self, record: &stack_receipt::SignedRecord) -> Result<(), stack_receipt::LogError> {
        self.calls += 1;
        if self.fail_on.contains(&self.calls) {
            return Err(stack_receipt::LogError::Poisoned);
        }
        self.inner.append(record)
    }
    fn is_durable(&self) -> bool {
        self.inner.is_durable()
    }
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// A directory under the system temp dir, unique to this process and
/// call, removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("stack-admission-test-{}-{n}-{label}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn replay_path(dir: &Path) -> PathBuf {
    dir.join("replay.log")
}
pub fn uses_path(dir: &Path) -> PathBuf {
    dir.join("uses.log")
}
pub fn receipts_path(dir: &Path) -> PathBuf {
    dir.join("receipts.log")
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

/// Builds an [`Admission`] over the files in one directory.
pub struct Builder {
    dir: PathBuf,
    clock: Arc<ManualClock>,
    policy: KernelPolicy,
    trident: TridentConfig,
    trust: TrustSet,
    executor: Option<Box<dyn Executor>>,
    receipt_log: Option<Box<dyn ReceiptLog>>,
    replay: Option<PathBuf>,
    uses: Option<PathBuf>,
}

impl Builder {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            clock: Arc::new(ManualClock::new(T0)),
            policy: policy(),
            trident: TridentConfig::production(KERNEL),
            trust: issuer_trust(),
            executor: None,
            receipt_log: None,
            replay: None,
            uses: None,
        }
    }

    /// A kernel restarting after another one that last read `previous_now`:
    /// the same wall clock carries on (the Trident refuses to start behind
    /// its own store's high-water mark).
    pub fn restarting(dir: &Path, previous_now: u64) -> Self {
        Self::new(dir).clock(Arc::new(ManualClock::new(previous_now)))
    }

    /// Uses this replay store file instead of the one in the directory,
    /// to share a store between two kernels.
    pub fn replay_file(mut self, path: PathBuf) -> Self {
        self.replay = Some(path);
        self
    }

    /// Uses this one-time-use store file instead of the one in the directory.
    pub fn uses_file(mut self, path: PathBuf) -> Self {
        self.uses = Some(path);
        self
    }

    pub fn clock(mut self, clock: Arc<ManualClock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn policy(mut self, policy: KernelPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn trident(mut self, cfg: TridentConfig) -> Self {
        self.trident = cfg;
        self
    }

    pub fn trust(mut self, trust: TrustSet) -> Self {
        self.trust = trust;
        self
    }

    pub fn executor(mut self, executor: Box<dyn Executor>) -> Self {
        self.executor = Some(executor);
        self
    }

    pub fn receipt_log(mut self, log: Box<dyn ReceiptLog>) -> Self {
        self.receipt_log = Some(log);
        self
    }

    /// Builds the kernel without stepping the clock.
    pub fn build(self) -> Result<Harness, BuildError> {
        let runs = Arc::new(AtomicUsize::new(0));
        let inner = self.executor.unwrap_or_else(|| Box::new(test_executor()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let executor = Box::new(CountingExecutor {
            inner,
            runs: Arc::clone(&runs),
            receipts: receipts_path(&self.dir),
            seen: Arc::clone(&seen),
        });
        let receipt_log: Box<dyn ReceiptLog> = match self.receipt_log {
            Some(l) => l,
            None => Box::new(
                FileReceiptLog::open(receipts_path(&self.dir), &self.policy.kernel_id, &[receipt_public_key(KERNEL)])
                    .map_err(|e| BuildError::Recorder(e.into()))?,
            ),
        };
        let replay_store = Box::new(
            FileStore::open(self.replay.clone().unwrap_or_else(|| replay_path(&self.dir)))
                .map_err(stack_trident::StartError::from)?,
        );
        let use_store = Box::new(
            FileUseStore::open(self.uses.clone().unwrap_or_else(|| uses_path(&self.dir)), 1024).map_err(|_| BuildError::UseStoreNotDurable)?,
        );
        let parts = Parts {
            trident: self.trident,
            keyring: sender_ring(),
            replay_store,
            trust: self.trust,
            revocations: RevocationList::new(1024),
            use_store,
            receipt_log,
            receipt_signer: receipt_signer(KERNEL),
            executor,
            clock: self.clock.clone(),
        };
        let admission = Admission::new(self.policy.clone(), parts)?;
        Ok(Harness {
            dir: self.dir,
            clock: self.clock,
            admission,
            runs,
            seen,
            policy: self.policy,
            next_seq: AtomicU64::new(1),
        })
    }

    /// As [`Builder::start`], for a kernel that starts right after another
    /// one released its stores. The stores are advisory file locks, held by
    /// the open file description; a supervised worker forked by ANY thread
    /// of the old process (here, another test running a worker at that
    /// instant) holds a copy of the descriptor until it closes its
    /// descriptors or dies. So the lock can outlive the old kernel by
    /// milliseconds. The new kernel fails closed ("locked") and this
    /// retries, printing how long it waited whenever it had to.
    pub fn start_after_release(self) -> Harness {
        let skew = self.trident.max_future_skew_ms;
        let (dir, clock, policy, trident, trust) =
            (self.dir.clone(), Arc::clone(&self.clock), self.policy.clone(), self.trident.clone(), self.trust.clone());
        let first = self.build();
        let h = match first {
            Ok(h) => h,
            Err(e) => {
                let begun = std::time::Instant::now();
                let mut last = e;
                loop {
                    assert!(
                        matches!(last, BuildError::Trident(StartError::Store(StoreError::Locked { .. })) | BuildError::Recorder(_) | BuildError::UseStoreNotDurable),
                        "the restart failed for a reason other than a lock: {last}"
                    );
                    assert!(begun.elapsed() < std::time::Duration::from_secs(10), "stores still locked after 10 s: {last}");
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    let retry = Builder::new(&dir).clock(Arc::clone(&clock)).policy(policy.clone()).trident(trident.clone()).trust(trust.clone());
                    match retry.build() {
                        Ok(h) => {
                            println!("observed: stores were locked for {:?} after the previous kernel was dropped", begun.elapsed());
                            break h;
                        }
                        Err(e) => last = e,
                    }
                }
            }
        };
        h.clock.advance(skew + 1);
        h
    }

    /// Builds the kernel and steps the clock past the Trident's start-up
    /// epoch floor so fresh envelopes are accepted.
    pub fn start(self) -> Harness {
        let skew = self.trident.max_future_skew_ms;
        let h = self.build().unwrap_or_else(|e| panic!("harness failed to start: {e}"));
        h.clock.advance(skew + 1);
        h
    }
}

/// A running kernel and the fixture sender that feeds it.
#[derive(Debug)]
pub struct Harness {
    pub dir: PathBuf,
    pub clock: Arc<ManualClock>,
    pub admission: Admission,
    pub runs: Arc<AtomicUsize>,
    pub seen: Arc<Mutex<Vec<Vec<ReceiptStage>>>>,
    pub policy: KernelPolicy,
    next_seq: AtomicU64,
}

impl Harness {
    /// The clock reading.
    pub fn now(&self) -> u64 {
        stack_authority::Clock::now_unix_ms(self.clock.as_ref())
    }

    /// How many runs the executor was asked for.
    pub fn runs(&self) -> usize {
        self.runs.load(Ordering::SeqCst)
    }

    /// The next sender sequence, and the one after that next time.
    pub fn next_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::SeqCst)
    }

    /// Sets the sequence the next envelope carries (for a restarted
    /// harness continuing a sender's counter).
    pub fn set_next_seq(&self, seq: u64) {
        self.next_seq.store(seq, Ordering::SeqCst);
    }

    /// A fresh envelope from `SENDER` sealed for `KERNEL`, PASS at alpha.
    pub fn envelope(&self, payload: Value) -> Vec<u8> {
        self.envelope_for(payload, KERNEL, GateOutcome::Pass)
    }

    /// A fresh envelope sealed for `audience` with the sender gate claim
    /// `outcome`.
    pub fn envelope_for(&self, payload: Value, audience: &str, outcome: GateOutcome) -> Vec<u8> {
        let seq = self.next_seq();
        self.envelope_with(payload, audience, outcome, seq)
    }

    /// An envelope carrying exactly sender sequence `seq` (and its nonce).
    pub fn envelope_for_seq(&self, payload: Value, seq: u64) -> Vec<u8> {
        self.envelope_with(payload, KERNEL, GateOutcome::Pass, seq)
    }

    fn envelope_with(&self, payload: Value, audience: &str, outcome: GateOutcome, seq: u64) -> Vec<u8> {
        let env = seal_for(
            EnvelopeDraft {
                sequence: seq,
                issued_at_unix_ms: self.now(),
                nonce: nonce_for(seq),
                gate_position: GatePosition::Alpha,
                gate_outcome: outcome,
                payload,
            },
            &trident_key(SENDER),
            audience,
            &self.policy_limits(),
        )
        .unwrap();
        env.to_wire_bytes(&self.policy_limits()).unwrap()
    }

    fn policy_limits(&self) -> stack_trident::Limits {
        TridentConfig::production(KERNEL).limits()
    }

    /// Admits `payload` and expects a refusal.
    pub fn refusal(&self, payload: Value) -> Refused {
        match self.admission.admit(&self.envelope(payload)) {
            Ok(a) => panic!("expected a refusal, got {a:?}"),
            Err(r) => r,
        }
    }

    /// Runs `payload` through the whole pipeline in a fresh envelope.
    pub fn process(&self, payload: Value) -> AdmissionResult {
        self.admission.process(&self.envelope(payload))
    }

    /// Verifies the receipt log as an auditor who supplies everything it
    /// can: the case's subject content, the kernel's required roster, the
    /// audience, and (when given) the result bytes.
    pub fn verify_full(&self, case: &Value, result: Option<&[u8]>) -> LogVerification {
        verify_bytes_full(&self.receipt_bytes(), case, result)
    }

    /// The receipt log file's bytes (read without the lock).
    pub fn receipt_bytes(&self) -> Vec<u8> {
        std::fs::read(receipts_path(&self.dir)).unwrap()
    }

    /// Verifies the receipt log as an auditor: fresh trusted keys, the
    /// kernel id and audience the auditor expects, plus `expectations`.
    pub fn verify_log(&self, expectations: Expectations<'_>) -> LogVerification {
        let exp = Expectations {
            kernel_id: Some(KERNEL),
            audience: Some(KERNEL),
            ..expectations
        };
        stack_receipt::verify_log_bytes(&self.receipt_bytes(), &receipt_trust(), &exp)
    }

    /// Asserts that `refused` closed its execution with a `rejected`
    /// record the auditor can verify, and that the refusal names the stage.
    pub fn assert_rejected_recorded(&self, refused: &Refused) {
        assert!(refused.recorded, "refusal was not recorded: {refused:?}");
        assert_eq!(refused.record_error, None);
        let id = refused.execution_id.expect("a recorded refusal has an execution id");
        let v = self.verify_log(Expectations::default());
        let e = v
            .executions
            .iter()
            .find(|e| e.execution.execution_id == id)
            .unwrap_or_else(|| panic!("execution {id} not in the log"));
        assert_eq!(e.state, State::VerifiedWithLimitations, "{}", e.to_json());
        assert_eq!(e.execution.stage_reached, Some(ReceiptStage::Rejected));
        assert_eq!(e.execution.outcome, None, "a rejection has no outcome");
    }

    /// Asserts that nothing was recorded for the refusal and no run happened.
    pub fn assert_unrecorded(&self, refused: &Refused) {
        assert!(!refused.recorded);
        assert_eq!(refused.execution_id, None);
    }
}

/// The clock reading of a kernel started with [`Builder::start`] and not
/// stepped since: what a restarted kernel's clock must at least show.
pub fn started_now() -> u64 {
    T0 + TridentConfig::production(KERNEL).max_future_skew_ms + 1
}

/// A nonce from a sequence number.
pub fn nonce_for(seq: u64) -> Nonce {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&seq.to_be_bytes());
    b[8] = 0xa5;
    Nonce::from_bytes(b)
}

// ---------------------------------------------------------------------------
// TEST FIXTURE issuer: the translating issuer of decision E, as a test helper
// ---------------------------------------------------------------------------

/// What the fixture issuer signs.
#[derive(Debug, Clone)]
pub struct CapSpec {
    pub cap_id: String,
    pub issuer_id: String,
    pub key_label: String,
    pub audience: String,
    pub subject_digest: Digest32,
    pub decision_root: Digest32,
    pub operations: Vec<String>,
    pub resources: Vec<ResourceScope>,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    pub one_time: bool,
    pub policy_ref: String,
}

static CAP_COUNTER: AtomicU64 = AtomicU64::new(1);

impl CapSpec {
    /// A one-time capability from `ISSUER` for `KERNEL`, about the case's
    /// subject under the case's root, for `operation` on exactly
    /// `resource`, valid from `T0` for one hour.
    pub fn for_case(case: &Value, operation: &str, resource: &str) -> Self {
        Self::for_digests(case_subject_digest(case), case_root(case), operation, resource)
    }

    /// As [`CapSpec::for_case`] with explicit digests.
    pub fn for_digests(subject_digest: Digest32, decision_root: Digest32, operation: &str, resource: &str) -> Self {
        let n = CAP_COUNTER.fetch_add(1, Ordering::SeqCst);
        Self {
            cap_id: format!("cap-{n:04}"),
            issuer_id: ISSUER.into(),
            key_label: ISSUER.into(),
            audience: KERNEL.into(),
            subject_digest,
            decision_root,
            operations: vec![operation.to_owned()],
            resources: vec![ResourceScope::exact(resource).unwrap()],
            not_before_ms: T0,
            expires_at_ms: T0 + HOUR,
            one_time: true,
            policy_ref: "policy/test-fixture".into(),
        }
    }

    /// The fixture issuer checks nothing here: a test that wants a
    /// capability for a refused decision gets one, because the kernel, not
    /// the issuer, is what these tests prove.
    pub fn issue(&self) -> Vec<u8> {
        let mut cap = Capability {
            cap_id: self.cap_id.clone(),
            issuer_id: self.issuer_id.clone(),
            audience: self.audience.clone(),
            subject_digest: self.subject_digest,
            decision_root: self.decision_root,
            operations: self.operations.clone(),
            resources: self.resources.clone(),
            not_before_ms: self.not_before_ms,
            expires_at_ms: self.expires_at_ms,
            one_time: self.one_time,
            policy_ref: self.policy_ref.clone(),
            nonce: nonce_bytes(&self.cap_id),
        };
        cap.normalise();
        let key = issuer_signing_key(&self.key_label);
        let key_id = issuer_public_key(&self.key_label).key_id();
        let region = cap.encode_signed_region(key_id.as_bytes()).unwrap();
        let sig = key.sign(&region);
        let mut wire = region;
        wire.extend_from_slice(&sig.to_bytes());
        wire
    }
}

fn nonce_bytes(label: &str) -> [u8; NONCE_BYTES] {
    let mut n = [0u8; NONCE_BYTES];
    n.copy_from_slice(&fixture_bytes32(&format!("nonce {label}"))[..NONCE_BYTES]);
    n
}

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

/// The resource every baseline request names.
pub const RESOURCE: &str = "/data/a";

/// The baseline arguments.
pub fn args() -> Value {
    json!({"k": 1, "items": ["x", null, true]})
}

/// A payload carrying the case's subject and decision, `capability`, and
/// the requested action.
pub fn payload_with(case: &Value, capability: &[u8], operation: &str, resource: &str) -> Value {
    json!({
        "subject": case["subject"],
        "decision": {"seats": case["seats"], "verdicts": case["verdicts"], "root": case["root"]},
        "capability": hex::encode(capability),
        "operation": operation,
        "resource": resource,
        "args": args(),
    })
}

/// A complete, honest payload for `case` and `operation`: a capability
/// from the trusted issuer for exactly this subject, root, operation and
/// `RESOURCE`.
pub fn honest_payload(case: &Value, operation: &str) -> Value {
    let cap = CapSpec::for_case(case, operation, RESOURCE).issue();
    payload_with(case, &cap, operation, RESOURCE)
}

/// The all-PASS fixture case.
pub fn all_pass() -> Value {
    case("all_pass")
}

// ---------------------------------------------------------------------------
// Independent verification
// ---------------------------------------------------------------------------

/// The auditor's expectations, built from nothing the producer wrote
/// except the case's public subject content: fresh trusted keys, the
/// kernel's required roster, the expected kernel and audience.
pub fn verify_bytes_full(bytes: &[u8], case: &Value, result: Option<&[u8]>) -> LogVerification {
    let content = stack_admission::cns_value(&case["subject"]).unwrap();
    let roster = policy().roster_policy();
    let exp = Expectations {
        subject_content: Some(&content),
        roster_policy: Some(&roster),
        audience: Some(KERNEL),
        kernel_id: Some(KERNEL),
        result_bytes: result,
    };
    stack_receipt::verify_log_bytes(bytes, &receipt_trust(), &exp)
}

/// The spellings of a scope's unchecked items.
pub fn not_checked(v: &LogVerification) -> Vec<&'static str> {
    v.scope.not_checked.iter().map(|l| l.as_str()).collect()
}
