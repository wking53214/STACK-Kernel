//! Shared fixtures for the issuer tests. Every key here is a TEST FIXTURE
//! derived from a public label. Nothing in `src/` holds or derives a key:
//! the production signer is a deployment decision this crate does not make.
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
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
    Entropy, EntropyError, IssuanceLog, IssuanceRecord, Issuer, IssuerConfig, LogError, SignError, Signer,
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

pub fn issuer_config() -> IssuerConfig {
    IssuerConfig::from_kernel_policy(&kernel_policy(), ISSUER, POLICY_REF, canonical_limits(), MAX_LIFETIME_MS, ROOTS).unwrap()
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
}

impl FixtureSigner {
    pub fn honest(label: &str) -> Self {
        Self { advertised: public_key(label), key: signing_key(label), fail: false }
    }
    pub fn pretend(advertised: &str, signs_with: &str) -> Self {
        Self { advertised: public_key(advertised), key: signing_key(signs_with), fail: false }
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
    fn append(&self, record: &IssuanceRecord) -> Result<(), LogError> {
        if *self.fail.lock().unwrap() {
            return Err(LogError::Unavailable("fixture log offline".into()));
        }
        self.records.lock().unwrap().push(record.clone());
        Ok(())
    }
}

pub fn issuer_with(signer: FixtureSigner, entropy: CounterEntropy, log: &SharedLog, now: u64) -> Issuer {
    Issuer::new(
        issuer_config(),
        Box::new(signer),
        Box::new(entropy),
        Box::new(log.clone()),
        Box::new(ManualClock::new(now)),
    )
    .unwrap()
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
