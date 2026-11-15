# stack-issuer

A capability issuer, as a library. It makes the `stack-capability/2` capabilities the kernel verifies. It holds no key, runs no service, and decides nothing about where it is deployed.

Status: library and tests. There is no service wrapper, no production signer and no requester authentication. See "What this does not do".

## What it does

The requester says: a subject, a claimed CNS decision, one operation, the resource scopes, the arguments and a lifetime. It cannot say a digest, an audience, a worker or a limit; the request type has no such field. The issuer derives them:

| Field | Derived from |
|---|---|
| audience | the kernel policy |
| subject digest | the subject content, recomputed (`stack_admission::binding::subject_digest`) |
| decision root | the claimed seats and verdicts, recomputed |
| worker label | the kernel policy's operation map |
| arguments digest, limits digest | `stack_admission::execution_binding`, the kernel's own function, over the canonical arguments |

The issuer's policy is built from one `KernelPolicy` (`IssuerConfig::from_kernel_policy`): the same required seats, positions, operations and limits, from one source (R-5, R-11).

It refuses:
- a decision the kernel would refuse (the kernel's own `binding::check`: root mismatch, a verdict bound to other content, a missing or misplaced seat);
- an operation the kernel does not run;
- no scope, more than 16 scopes, or a prefix scope on `/`;
- a lifetime of zero or above the configured ceiling (a ceiling over 24 hours is a configuration error).

Every capability it issues is one-time and version 2.

## Signing, entropy and the log

- `Signer` is the only way it signs. Implementations (an HSM or KMS adapter) live outside this crate. The issuer checks each signature against the signer's own public key before anything leaves, so a broken or hostile device cannot hand out an unverifiable capability.
- `Entropy` supplies the capability id and nonce. `OsEntropy` reads `/dev/urandom`.
- `IssuanceLog` takes one record per capability, written before the capability is returned. If the write fails, no capability is returned. `FileIssuanceLog` is append-only JSON lines, flushed to stable storage per record.

## Tests

`tests/issue.rs`, 18 tests. The verifier is the real `stack_authority::Authority`, the CNS decision is a case the real SuperGate produced (the admission crate's fixture), and keys are test fixtures. Nine mutations of the implementation were each caught by at least one test (decision check off, reusable issued, wildcard allowed, signature check off, log failure ignored, worker not from policy, lifetime ceiling off, arguments not bound, constant nonce).

Not tested: an end-to-end run through `stack_admission::Admission` with a real worker. The authority is exercised directly with the request the kernel would build.

## What this does not do

- **It cannot show that a real CNS decision exists.** The CNS proof is an HMAC under a key local to CNS. The issuer checks everything the kernel checks (structure, roster, positions, subject binding, root) and nothing more. A forged but self-consistent decision of PASS verdicts passes. Closing this needs a verification channel to CNS, which does not exist. Owner decision.
- **It does not authenticate the requester.** `requester` is a label for the log. The caller must authenticate the requester before calling `issue`.
- **No production signer.** Key custody (R-1, R-2, R-3) is deployment. The kernel's trust set decides which key it believes.
- **The log is not tamper-evident.** No hash chain, no signature, no file lock: one issuer process per file.
- **Not done:** revocation and rotation operations (R-12 to R-15), a reconciler between the issuance log, the use store and the receipt log (R-17), clock discipline (R-19), a shared use store for several kernels (R-20).
- **Coupling.** This crate depends on `stack-admission`, which links the C++ host library, to reuse the kernel's own binding functions. Extracting those functions into a small shared crate would let an issuer be built without the worker. Left as is to keep the diff small.
- `null` and `{}` bind different digests. The issuer binds the arguments exactly as given.
