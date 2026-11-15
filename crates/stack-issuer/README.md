# stack-issuer

A capability issuer, as a library. It makes the `stack-capability/2` capabilities the kernel verifies. It holds no key, runs no service, and decides nothing about where it is deployed.

Status: library and tests. There is no service wrapper, no production signer, no requester authentication and no issuance authorization policy. See "What this does not do" before relying on it.

## What it does

The requester says: a subject, a claimed CNS decision, one operation, the resource scopes, the arguments and a lifetime. It cannot say a digest, an audience, a worker or a limit; the request type has no such field. The issuer derives them:

| Field | Derived from |
|---|---|
| audience | the kernel policy |
| subject digest | the subject content, recomputed (`stack_admission::binding::subject_digest`) |
| decision root | the claimed seats and verdicts, recomputed |
| worker label | the kernel policy's operation map |
| arguments digest, limits digest | `stack_admission::execution_binding`, the kernel's own function, over the canonical arguments |

The issuer's policy is a copy of one `KernelPolicy`, taken when `IssuerConfig::from_kernel_policy` is called: the same required seats, positions, operations and limits. It does not follow later changes to the kernel's policy. If the two drift, the kernel refuses the capability (worker, limits or roster mismatch); it does not accept something broader.

It refuses:
- a decision the kernel's own `binding::check` refuses (root mismatch, a verdict bound to other content, a missing or misplaced seat), and the shape faults the kernel's payload parser refuses (subject not a map, bad verdict, too many seats);
- arguments, when the kernel policy sets `refuse_arguments` and they are not `null` or `{}`;
- an operation the kernel does not run;
- no scope, more than 16 scopes, a prefix scope on `/`, and any scope that is not at or under one of the configured **resource roots** (R-6). There is no default list and `/` is not a valid root;
- a lifetime of zero or above the configured ceiling (a ceiling over 24 hours is a configuration error);
- a policy that neither refuses arguments nor requires an execution binding;
- an issuer clock that reads zero, runs backwards, or would overflow the window.

Every capability it issues is one-time and version 2.

## Signing, entropy and the log

- `Signer` is the only way it signs. Implementations (an HSM or KMS adapter) live outside this crate and must not expose key bytes through `Debug`. The issuer checks each signature against the signer's own public key before anything leaves. That proves the signature matches the key the signer advertises; whether the kernel trusts that key is the kernel's trust set, and a wrong key fails closed there.
- `Entropy` supplies the capability id and nonce as two separate draws. `OsEntropy` reads `/dev/urandom`.
- `IssuanceLog` takes one record per capability, written before the capability is returned. If the write fails, no capability is returned. A log must say it is durable or `Issuer::new` refuses it. A record means "the issuer produced this", not "it was delivered".
- `FileIssuanceLog` is append-only JSON lines, flushed to stable storage per record, created owner-readable only. It refuses to open a file whose last line is unterminated, and after a failed write it refuses every later append until reopened.

## Tests

41 tests: `tests/issue.rs` (18) and `tests/hardening.rs` (23). The verifier is the real `stack_authority::Authority`, the CNS decision is a case the real SuperGate produced (the admission crate's fixture), and keys are test fixtures.

Mutation checks: the original nine mutations were each caught, but an independent review then found eleven further mutations that survived the 18 tests (required seats ignored, positions ignored, scope limits, requester check, ordering, id from nonce, record fields and others). `tests/hardening.rs` pins those. Of 23 mutations run on the current tests, 22 are caught. The one that survives is removing the parse-after-sign check: the bytes come straight from the encoder, so it is a redundant second guard that no input can reach. The reviewer also ran an end-to-end test through the real `Admission` and worker in a scratch copy and it passed; that test is not in this repository, because it needs a dev-dependency cycle with `stack-admission`.

## What this does not do

- **It cannot show that a real CNS decision exists.** The CNS proof is an HMAC under a key local to CNS. The issuer checks everything the kernel checks and nothing more, so a forged but self-consistent decision of PASS verdicts passes. Until a verification channel to CNS exists, the issuer adds no security beyond who is allowed to call `issue`. Owner decision.
- **It is not an authorization decision.** Any caller of `issue` gets any operation, scope (within the roots) and arguments for any passing decision, and the same decision can be turned into any number of one-time capabilities. `requester` is only a label in the log. The caller must authenticate and authorize the requester and limit issuance per decision. A required authorizer hook is an owner decision.
- **No production signer.** Key custody (R-1, R-2, R-3) is deployment. The kernel's trust set decides which key it believes.
- **The log is not tamper-evident** (no hash chain, no signature), the directory entry is not flushed, and it takes no lock: one issuer process per file.
- **Not done:** revocation and rotation operations (R-12 to R-15), a reconciler between the issuance log, the use store and the receipt log (R-17), clock agreement between issuer and kernel (R-19; the issuer sets `not_before` to now, so a kernel clock behind the issuer's refuses a fresh capability as not yet valid), a shared use store for several kernels (R-20), a size check against the Trident envelope.
- **Coupling.** This crate depends on `stack-admission`, which links the C++ host library, to reuse the kernel's own binding functions. Extracting those into a small shared crate would let an issuer be built without the worker.
- `null` and `{}` bind different digests. The issuer binds the arguments exactly as given.
