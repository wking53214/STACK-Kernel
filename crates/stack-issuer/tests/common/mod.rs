//! Shared fixtures for the issuer tests. Every key here is a TEST FIXTURE
//! derived from a public label. Nothing in `src/` holds or derives a key:
//! the production signer is a deployment decision this crate does not make.
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use stack_admission::{DecisionClaim, ExecutionLimits, KernelPolicy, WorkerKind};
use stack_authority::{
    Authority, AuthorityConfig, ManualClock, MemoryUseStore, PublicKey, Purpose, RevocationList, TrustAnchor, TrustSet,
    SIGNATURE_BYTES,
};
use stack_issuer::{
    AuthorizationRequest, Authorizer, ConfigError, DecisionVerifier, Entropy, EntropyError, IssuanceLog, IssuanceRecord, Issuer,
    IssuerConfig, LogError, Refusal, SignError, Signer,
};
use stack_receipt::Provenance;
use stack_trident::canonical::Limits;

pub const T0: u64 = 1_800_000_000_000;
pub const HOUR: u64 = 3_600_000;
pub const DAY: u64 = 24 * HOUR;
pub const KERNEL: &str = "kernel-a";
pub const ISSUER: &str = "issuer-1";
pub const POLICY_REF: &str = "policy/test/1";
pub const MAX_LIFETIME_MS: u64 = 10 * 60 * 1000;

/// The kernel policy the issuer's own policy is derived from.
pub fn kernel_policy() -> KernelPolicy {
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
        ]),
        limits: ExecutionLimits::with_deadline_ns(300_000_000),
        require_one_time_capabilities: true,
        refuse_arguments: false,
        require_execution_binding: true,
        provenance: Provenance {
            component: "stack-issuer-test".into(),
            version: "0.1.0-test".into(),
            host_id: "test-host".into(),
        },
    }
}

pub fn canonical_limits() -> Limits {
    stack_trident::TridentConfig::production(KERNEL).limits()
}

pub const ROOTS: &[&str] = &["/data"];
/// High, so the tests that issue many capabilities for one decision are not limited.
pub const MAX_PER_DECISION: u32 = 1000;

pub fn issuer_config() -> IssuerConfig {
    config_with_limit(MAX_PER_DECISION)
}

pub fn config_with_limit(max_per_decision: u32) -> IssuerConfig {
    IssuerConfig::from_kernel_policy(
        &kernel_policy(),
        ISSUER,
        POLICY_REF,
        canonical_limits(),
        MAX_LIFETIME_MS,
        ROOTS,
        max_per_decision,
    )
    .unwrap()
}

// ---- fixture signer -------------------------------------------------------

pub fn signing_key(label: &str) -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(format!("stack-issuer TEST FIXTURE key: {label}").as_bytes()).into();
    SigningKey::from_bytes(&seed)
}

pub fn public_key(label: &str) -> PublicKey {
    PublicKey::from_bytes(signing_key(label).verifying_key().to_bytes()).unwrap()
}

/// A signer that holds a fixture key in memory. `pretend` makes it advertise
/// one key and sign with another, the way a broken or hostile device would.
#[derive(Debug)]
pub struct FixtureSigner {
    advertised: PublicKey,
    key: SigningKey,
    pub fail: bool,
    /// How many times `sign` was called.
    pub signs: Arc<AtomicUsize>,
}

impl FixtureSigner {
    pub fn honest(label: &str) -> Self {
        Self { advertised: public_key(label), key: signing_key(label), fail: false, signs: Arc::default() }
    }
    pub fn pretend(advertised: &str, signs_with: &str) -> Self {
        Self { advertised: public_key(advertised), key: signing_key(signs_with), fail: false, signs: Arc::default() }
    }
    pub fn failing(label: &str) -> Self {
        Self { fail: true, ..Self::honest(label) }
    }
}

impl Signer for FixtureSigner {
    fn public_key(&self) -> PublicKey {
        self.advertised
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], SignError> {
        self.signs.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(SignError::Unavailable("fixture device offline".into()));
        }
        Ok(self.key.sign(message).to_bytes())
    }
}

// ---- fixture entropy and log ----------------------------------------------

/// Deterministic, distinct bytes. TEST FIXTURE: never production entropy.
#[derive(Debug, Default)]
pub struct CounterEntropy {
    pub n: AtomicU64,
    pub fail: bool,
}

impl Entropy for CounterEntropy {
    fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError> {
        if self.fail {
            return Err(EntropyError::Unavailable("fixture entropy offline".into()));
        }
        let n = self.n.fetch_add(1, Ordering::SeqCst);
        let block: [u8; 32] = Sha256::digest(n.to_be_bytes()).into();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = block[i % 32];
        }
        Ok(())
    }
}

/// A log that keeps its records and can be told to fail.
#[derive(Debug, Clone, Default)]
pub struct SharedLog {
    pub records: Arc<Mutex<Vec<IssuanceRecord>>>,
    pub fail: Arc<Mutex<bool>>,
    pub not_durable: Arc<Mutex<bool>>,
}

impl SharedLog {
    pub fn count(&self) -> usize {
        self.records.lock().unwrap().len()
    }
    pub fn set_failing(&self, v: bool) {
        *self.fail.lock().unwrap() = v;
    }
}

impl IssuanceLog for SharedLog {
    fn is_durable(&self) -> bool {
        !*self.not_durable.lock().unwrap()
    }
    fn issued_for_decision(&self, decision_root: &str) -> Result<u32, LogError> {
        Ok(self.records.lock().unwrap().iter().filter(|r| r.decision_root == decision_root).count() as u32)
    }
    fn append(&self, record: &IssuanceRecord, max_per_decision: u32) -> Result<(), LogError> {
        if *self.fail.lock().unwrap() {
            return Err(LogError::Unavailable("fixture log offline".into()));
        }
        let mut records = self.records.lock().unwrap();
        let same = records.iter().filter(|r| r.decision_root == record.decision_root).count();
        if same >= max_per_decision as usize {
            return Err(LogError::DecisionLimit);
        }
        records.push(record.clone());
        Ok(())
    }
}

/// The decision claim as a verifier received it: (seats, verdict count, claimed root hex).
pub type SeenDecision = (Vec<String>, usize, String);

/// TEST FIXTURE: a verifier that accepts every decision. The crate ships no such thing;
/// a deployment that wrote this would be choosing to trust any well-formed decision.
#[derive(Debug, Default, Clone)]
pub struct FixtureAllowAllVerifier {
    pub calls: Arc<Mutex<Vec<(String, String)>>>,
    /// The decision claim as the verifier received it: (seats, verdicts, claimed root hex).
    pub decisions: Arc<Mutex<Vec<SeenDecision>>>,
    pub refuse: bool,
}

impl DecisionVerifier for FixtureAllowAllVerifier {
    fn verify(&self, subject_digest: &stack_authority::Digest32, decision: &stack_admission::DecisionClaim, root: &stack_authority::Digest32) -> Result<(), Refusal> {
        self.calls.lock().unwrap().push((subject_digest.to_hex(), root.to_hex()));
        self.decisions.lock().unwrap().push((decision.seats.clone(), decision.verdicts.len(), decision.root.to_hex()));
        if self.refuse {
            return Err(Refusal("fixture verifier refuses".into()));
        }
        Ok(())
    }
}

/// What the authorizer fixture saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub requester: String,
    pub operation: String,
    pub resources: Vec<String>,
    pub lifetime_ms: u64,
    pub args_digest: String,
    pub subject_digest: String,
    pub decision_root: String,
}

/// TEST FIXTURE: an authorizer that records what it saw and allows only the listed
/// (requester, operation) pairs, or everything when `allow` is `None`.
#[derive(Debug, Default, Clone)]
pub struct FixtureAuthorizer {
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub allow: Option<Vec<(String, String)>>,
}

impl Authorizer for FixtureAuthorizer {
    fn authorize(&self, r: &AuthorizationRequest<'_>) -> Result<(), Refusal> {
        self.seen.lock().unwrap().push(Seen {
            requester: r.requester.to_owned(),
            operation: r.operation.to_owned(),
            resources: r.resources.iter().map(|x| x.path().to_owned()).collect(),
            lifetime_ms: r.lifetime_ms,
            args_digest: r.args_digest.to_hex(),
            subject_digest: r.subject_digest.to_hex(),
            decision_root: r.decision_root.to_hex(),
        });
        match &self.allow {
            None => Ok(()),
            Some(list) if list.iter().any(|(q, o)| q == r.requester && o == r.operation) => Ok(()),
            Some(_) => Err(Refusal("fixture authorizer denies".into())),
        }
    }
}

/// An issuer with the allow-all fixture hooks.
pub fn new_issuer(
    config: IssuerConfig,
    signer: FixtureSigner,
    entropy: impl Entropy + 'static,
    log: impl IssuanceLog + 'static,
    clock: impl stack_authority::Clock + 'static,
) -> Result<Issuer, ConfigError> {
    Issuer::new(
        config,
        Box::new(signer),
        Box::new(entropy),
        Box::new(log),
        Box::new(clock),
        Box::new(FixtureAllowAllVerifier::default()),
        Box::new(FixtureAuthorizer::default()),
    )
}

pub fn issuer_with(signer: FixtureSigner, entropy: CounterEntropy, log: &SharedLog, now: u64) -> Issuer {
    new_issuer(issuer_config(), signer, entropy, log.clone(), ManualClock::new(now)).unwrap()
}

pub fn honest_issuer(log: &SharedLog) -> Issuer {
    issuer_with(FixtureSigner::honest(ISSUER), CounterEntropy::default(), log, T0)
}

// ---- CNS fixtures and the verifier ----------------------------------------

/// A case of the admission crate's CNS fixture file, which the real SuperGate
/// produced.
pub fn case(name: &str) -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../stack-admission/tests/fixtures/cns-governed-decisions.json");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    file["cases"].as_array().unwrap().iter().find(|c| c["name"].as_str() == Some(name)).unwrap().clone()
}

pub fn decision_of(case: &Value) -> DecisionClaim {
    // The payload parser is the kernel's own, so the claim is shaped as the kernel reads it.
    let payload = serde_json::json!({
        "subject": case["subject"],
        "decision": {"seats": case["seats"], "verdicts": case["verdicts"], "root": case["root"]},
        "capability": "00",
        "operation": "echo",
        "resource": "/data/a",
        "args": null,
    });
    stack_admission::payload::parse(&payload).unwrap().decision
}

/// A verifier for `KERNEL` that trusts the fixture issuer key and requires one-time use and a binding.
pub fn verifier() -> (Authority, MemoryUseStore) {
    let mut trust = TrustSet::new(16);
    trust
        .insert(TrustAnchor::new(ISSUER, public_key(ISSUER), Purpose::CapabilityIssuer, T0 - DAY, T0 + DAY).unwrap())
        .unwrap();
    let config = AuthorityConfig {
        require_durable_use_store: false,
        require_execution_binding: true,
        require_one_time: true,
        ..AuthorityConfig::new(KERNEL)
    };
    (Authority::new(config, trust, RevocationList::new(1024)).unwrap(), MemoryUseStore::new(1024))
}


/// A scratch directory removed when it goes out of scope.
pub struct TempDir(pub std::path::PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!("stack-issuer-{}-{}-{label}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    pub fn file(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A well-formed issuance record line (with its newline) for a decision root.
pub fn record_line(root_byte: u8) -> String {
    format!("{{\"cap_id\":\"cap-x\",\"decision_root\":\"{}\"}}\n", hex::encode([root_byte; 32]))
}
