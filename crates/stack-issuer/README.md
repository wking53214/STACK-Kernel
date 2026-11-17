# stack-issuer

A capability issuer, as a library. It makes the `stack-capability/2` capabilities the kernel verifies. It holds no key, runs no service, and decides nothing about where it is deployed.

Status: library and tests. There is no service wrapper, no production signer, no requester authentication, no real authorization policy, and no CNS side that produces decision receipts. A receipt verifier (`CnsReceiptVerifier`) exists and is tested, but it has nothing to verify until CNS signs receipts. Two hooks that a deployment must supply are required by the type system, and only refusing placeholders ship. See "What this does not do" before relying on it.

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

## The two required hooks and the per-decision cap

`Issuer::new` takes a `DecisionVerifier` and an `Authorizer`. Neither has a default. `RefuseAllDecisions` and `DenyAllRequests` refuse everything, so an issuer built with them issues nothing; `CnsReceiptVerifier` allows only a decision with a valid, unexpired receipt signed by a pinned CNS key, and no authorization policy ships that allows anything.

- `Authorizer::authorize(requester, operation, scopes, lifetime, args_digest, subject_digest, decision_root)`: may this requester be issued this? A passing CNS decision is about a subject, not about an operation or a requester. It runs first: it is cheap local policy.
- `DecisionVerifier::verify_with_receipt(subject_digest, decision, decision_root, receipt)` (default: ignore the receipt and call `verify(subject_digest, decision, decision_root)`): is this CNS decision genuine? The issuer cannot tell by itself (the CNS proof is an HMAC local to CNS). It runs second, because it is probably a call to CNS, so a requester the policy refuses costs no lookup.

Both run before the issuer takes entropy, reads the clock or asks the signer for anything, and after the issuer's own structural checks, with the values it recomputed. A refusal from either means no capability, no log record and no cap slot. Hooks are called concurrently, may be called for a request that is refused later, have no timeout, and report only a refusal text (an outage and a forged decision look the same). Do not forward that text to a requester: error text can name roster seats and internal policy. A hook that holds a key must not derive `Debug` over it.

**The three caps.** `IssuerConfig` requires `IssuanceCaps`, all at least 1 and none defaulted, counted in the issuance log so they survive a restart:
- `per_decision`: the most capabilities one decision *root* may produce.
- `per_subject`: the most capabilities one *subject digest* may produce across all of its decision roots. This is what stops a requester who holds one genuine decision from relabelling a verdict, adding a PASS seat, or reordering the seats to get a new root: the subject digest does not change. The price is that one piece of content can never be re-decided and re-issued beyond this number without an operator reset.
- `distinct_decisions`: the most distinct decision roots the log may hold. Past it the issuer refuses a decision it has not seen before. It bounds the log's memory and open time against a requester who mints roots; a decision already in the log is still served, and a reset root still counts.

`IssuanceLog::append` checks all three and records atomically, and the issuer reads the counts first so an exhausted request costs no signature. What the caps do and do not give you:
- They survive a restart (`FileIssuanceLog` rebuilds the counts from the file at open).
- **Rotating the log resets them.** To rotate without re-arming spent decisions, open the new file with `FileIssuanceLog::open_with_history` and list every earlier segment, oldest first.
- **They are not per requester.** An authorized requester can use up a decision's or a subject's allowance (for example with 1 ms lifetimes) and every other user is then refused. The authorizer must rate-limit, or an operator must reset.
- A slot is taken when the record is written. If the write reached the file but the flush failed, no capability is released and the record may still count after the next open.
- With a verifier that accepts exactly the roots CNS produced, the per-decision cap is meaningful by itself. Without one, the per-subject cap is the one a requester cannot dodge by editing a decision.

**Operator reset.** `Issuer::reset_decision(root, operator, reason)` re-allows one decision root: it writes a reset record into the log (so it survives a restart and is auditable), sets the root's count to zero, and takes what it had off its subject's count. It returns the count it had. A reset of an unknown or already-zero root is refused and writes nothing. **Who may call it is the caller's job**: the issuer records `operator` and does not authenticate it. A reset undoes a cap, so treat the ability to call it as you treat the signing key. History segments must be listed oldest first, because a reset applies to the records before it; a reset listed before them is refused.

**`policy_ref`.** The `policy_ref` in every capability is your text, then `@sha256:` and a digest of the kernel policy the issuer was built from (audience, required seats, seat positions, operations and workers, the limits' digest, and three flags; the layout is in `config.rs`, and a test pins it against a value computed independently in Python). If the issuer and the kernel policy drift, the digest in the audit log shows it. Your text may be at most 184 bytes.

## Signing, entropy and the log

- `Signer` is the only way it signs. Implementations (an HSM or KMS adapter) live outside this crate and must not expose key bytes through `Debug`. The issuer checks each signature against the signer's own public key before anything leaves. That proves the signature matches the key the signer advertises; whether the kernel trusts that key is the kernel's trust set, and a wrong key fails closed there.
- `Entropy` supplies the capability id and nonce as two separate draws. `OsEntropy` reads `/dev/urandom`.
- `IssuanceLog` takes one record per capability, written before the capability is returned. If the write fails, no capability is returned. A log must say it is durable or `Issuer::new` refuses it. A record means "the issuer produced this", not "it was delivered".
- `FileIssuanceLog` is append-only JSON lines, flushed to stable storage per record. On Unix a new file is created readable by its owner only; an existing file keeps its mode. It refuses a symlink, a FIFO and a socket, and `is_durable` is true only for a regular file, so `Issuer::new` refuses a log on a device.
  - **Locking.** It takes an exclusive advisory lock for the life of the handle, so a second handle on the same file is refused. The lock belongs to the file, not the path, and to the open file description, not the process. So `append` checks (Unix) that the path still names the file the handle holds, and that the process is the one that opened it, and latches the handle if not: renaming, replacing or removing the log while it runs, or forking with it open, stops the issuer instead of silently splitting the count. The check is not atomic with the write, and it does not help on a network filesystem whose locks are client-local.
  - **Opening** streams the file line by line (no size limit; one line may be at most 1 MiB) and refuses an unterminated last line, an empty line, invalid UTF-8, and any line that is not a record. `append` refuses to write a record that `open` would refuse. After a failed write or flush it refuses every later append, including concurrent ones, until reopened.
  - **Rotation.** `open_with_history` (oldest segment first) reads each earlier segment under a shared lock, so a segment still held by a running issuer makes the open fail: **stop the old issuer first.** A segment must be a regular file, listed once, and not the live file; the segments are checked before the live file is created. Nothing detects an omitted segment.
  - **Growth.** Memory and open time grow with the number of distinct decision roots, which `distinct_decisions` bounds for new roots. Rotate with history before the bound is reached.

## Tests

132 tests: `tests/receipt.rs` (23, see "CNS decision receipts"), `tests/issue.rs` (18), `tests/hardening.rs` (27), `tests/hooks.rs` (21), `tests/review6.rs` (22), `tests/caps.rs` (20) and one unit test in `src/log.rs` (the fork check). The verifier in the end-to-end issue test is the real `stack_authority::Authority`, the CNS decision is a case the real SuperGate produced (the admission crate's fixture), and keys, hooks and the in-memory log are test fixtures, named as such. The cap and file-log behaviour is tested against the real `FileIssuanceLog`.

Mutation checks. Four independent reviews each found that my tests were weaker than I had said, so the figures are given with their history:
- The first nine mutations were caught by the first 18 tests. Review 4 then found eleven more that survived; `hardening.rs` pins them.
- Review 5 found 18 survivors in the hook, cap, log and hardening code; they were pinned and re-run (22 mutations, all caught).
- Review 6 ran 94 mutations against the merged tests and found 31 survivors: the whole on-disk record format (14 of 17 JSON keys never read back), `O_APPEND`, multi-segment history, the order of the hooks against entropy and the clock, seven exact-length boundaries, and the parse-after-sign check. **That check was described here as an equivalent mutant. It is not:** it also enforces the 16 KiB size a default verifier accepts, and without it a 16,709-byte capability was issued and logged. `review6.rs` pins all of these. I then ran 26 mutations against the new behaviour and the survivors, and all are caught (one, the FIFO check, by a test that fails rather than hangs). The pid (fork) check is covered by a unit test that fakes the pid, not by a real fork.
- The per-subject cap, the distinct-decision bound, the reset and the policy digest were each written test first against the behaviour, then run against 33 mutations. Four survived at first and exposed gaps in my tests, not in the code: a reset of an already-zero root wrote a line the reader would then refuse (the test did not look at the file), and the limit errors found at append time were never exercised because the issuer's own look at the counts caught everything first. Both are pinned. These changes have not had an independent review yet.
- Concurrency tests are probabilistic by nature; the latch and the cap are each run for 40 to 50 rounds of 8 threads.

The reviewer also ran an end-to-end test through the real `Admission` and worker in a scratch copy and it passed; that test is not in this repository, because it needs a dev-dependency cycle with `stack-admission`.

## CNS decision receipts

`CnsReceiptVerifier` is a `DecisionVerifier` that requires a receipt: a 193-byte fixed-length statement, signed by a CNS key the deployment pins, that CNS decided this root about this subject between two times. Call `Issuer::issue_with_receipt(request, Some(&receipt))`. `Issuer::issue(request)` passes no receipt, so this verifier refuses it.

The verifier checks, in this order: length, version, that the key id is pinned, the strict Ed25519 signature (the contents are not believed before it verifies), the key's window (it must cover now and the time the receipt was issued; pin the new key before the old one retires, with overlapping windows), that subject and root equal the values the issuer recomputed, that the life is positive and no longer than the verifier allows (at most 24 hours; set it to minutes), that the receipt is not from the future beyond a skew of at most 5 minutes, and that it has not expired. The signature covers a domain label (`stack-issuer/cns-decision-receipt/1`) and every other byte. The full layout is in `src/receipt.rs`; a receipt built independently in Python is a known-answer test.

What it does not do: a compromised CNS key signs anything; the nonce is recorded, not checked, so one receipt can back several requests inside its life (the per-decision and per-subject caps bound that); the receipt is not in the issuance log record (the log records the decision root); and **nothing in CNS produces receipts yet**. That part is a CNS change that needs the owner's go-ahead and a key custody decision. Passing a receipt to a verifier that does not override `verify_with_receipt` checks nothing.

## What this does not do

- **No CNS side produces receipts yet.** The CNS proof is an HMAC under a key local to CNS. The issuer checks everything the kernel checks, and a forged but self-consistent decision of PASS verdicts passes those checks. `CnsReceiptVerifier` closes that gap once CNS signs a receipt for each decision (see "CNS decision receipts"); until CNS does, and a deployment pins its key, the safe configuration is `RefuseAllDecisions`, which issues nothing. A deployment that plugs in an allow-all verifier gets exactly the weakness the hook was added to expose.
- **No real authorization policy exists.** The `Authorizer` hook is where a deployment decides who may be issued what. `requester` is a label the caller supplies; authenticating the requester is the caller's job, and the hook is only as good as that authentication. The per-decision cap limits how many capabilities one decision can ever produce; it does not say who gets them.
- **No production signer.** Key custody (R-1, R-2, R-3) is deployment. The kernel's trust set decides which key it believes.
- **The log is not tamper-evident** (no hash chain, no signature), and the directory entry is not flushed. The lock stops a second issuer, not another program editing the file; truncating or hand-editing the log resets the counts. On non-Unix platforms the owner-only mode and the rename and fork checks do not apply, and `File::try_lock` behaves differently on Windows (not tested).
- **Not done:** revocation and rotation operations (R-12 to R-15), a reconciler between the issuance log, the use store and the receipt log (R-17), clock agreement between issuer and kernel (R-19; the issuer sets `not_before` to now, so a kernel clock behind the issuer's refuses a fresh capability as not yet valid), a shared use store for several kernels (R-20), a size check against the Trident envelope, a release of slots for capabilities that expired unused, an authenticated path for the reset.
- **Coupling.** This crate depends on `stack-admission`, which links the C++ host library, to reuse the kernel's own binding functions. Extracting those into a small shared crate would let an issuer be built without the worker.
- `null` and `{}` bind different digests. The issuer binds the arguments exactly as given.
- **The cap's key.** Besides relabelling a verdict or adding a PASS seat, simply reversing the seat order of a genuine decision gives a new valid root.
- **Issuance accounting.** The log does not enforce a unique `cap_id`, and `Entropy` quality is the deployer's: an entropy source that returns zeros issues capability `cap-000...0` again and again. The kernel's use store would refuse the reuse. `Signer::public_key` is called on every issuance, so an adapter should make it cheap.
- **The clock guard** refuses an issuance whose clock reading is earlier than the last completed issuance. A step forward of N seconds blocks nothing; a step backward of N seconds blocks issuance for N seconds. A refused or failed request does not move the guard.
- **Control characters.** The issuer refuses every Unicode control character in the text it checks; the kernel's rule is narrower (below 0x20 and 0x7f). So a CNS seat name with a character such as U+0085 cannot be issued for, though the kernel would accept it. It fails closed.
- **Error text.** `IssueError`'s `Display` is neutral ("decision refused", "not authorized"). The detail (roster seats, a hook's reason) is in `IssueError::detail()`, for the operator's log. `Debug` of `Issued` and `IssuanceRequest` does not print the capability, the subject or the arguments.
