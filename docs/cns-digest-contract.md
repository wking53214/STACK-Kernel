# CNS subject digest contract (`cns-digest/1`)

This is the contract between CNS (`cns.gate.subject_digest`, Python, the
reference) and the two Rust reproductions in this repository:
`stack-sentinel` (`src/cns.rs`, full domain) and `stack-trident`
(`src/cns_digest.rs`, restricted domain). The machine-readable form is CNS's
`contracts/digest-vectors.json` (schema `cns-digest-vectors/2`), vendored here
as `crates/stack-sentinel/tests/fixtures/cns-digest-vectors.json`. Where this
page and that file disagree, the file is right and this page is a defect.

## Digest

`digest = lowercase_hex(SHA-256(UTF-8(rendering(content))))`, 64 characters,
never truncated. The algorithm name is `digest_version: "cns-digest/1"`.

## Value domain (normative)

Content is a map with text keys. Values are:

| value | rendering |
|---|---|
| null | `n:` |
| boolean | `b:1` or `b:0` (never the integer 1 or 0) |
| integer, any magnitude | `i:<base 10, leading - if negative, no leading zeros>:` |
| float, finite binary64 | `f:<Python repr, shortest round trip>:`; `-0.0` renders as `0.0` |
| text | `s:<number of code points>:<text>` |
| list | `l:<number of items>:` then each item |
| map | `d:<number of members>:` then, for each key in ascending code point order, the key rendered as text and then its value |

In JSON, a number with a fraction or exponent is a float and one without is
an integer; a reader must keep that distinction. Code point order is not
UTF-16 order: keys at U+E000 to U+FFFF sort before astral keys by code point
and after them in UTF-16.

The normative domain sets no depth limit. Container depth is 0 for a scalar
and 1 plus the deepest member for a map or list; a map of scalars has depth 1.

## Refusals

Every implementation refuses these. CNS raises `TypeError` for each
(`cns_composition/tests/test_digest_vectors.py`); JSON cannot carry them, so
the vectors file lists them by name under `refusals`:

| name | input |
|---|---|
| `nan` | float NaN |
| `positive_infinity`, `negative_infinity` | float infinities |
| `lone_high_surrogate`, `lone_low_surrogate` | text holding an unpaired surrogate |
| `non_text_key` | a map key that is not text |
| `bytes` | binary data (`bytes`, `bytearray`, `memoryview`, `array.array` in Python) |

In Rust: `stack-sentinel` refuses NaN and the infinities in the digest and
lone surrogate escapes in its JSON reader; its value type cannot hold a
non-text key or bytes (`every_named_refusal_is_refused` in
`crates/stack-sentinel/tests/cns_vectors.rs`). `stack-trident` refuses NaN,
the infinities and lone surrogate escapes in its strict JSON parser (unit
tests in `src/canonical.rs`), and its `serde_json` value type cannot hold a
lone surrogate, a non-text key or bytes.

## Restricted v1 (what `stack-trident` accepts)

`stack-trident` binds an envelope's `subject_digest` with the CNS digest over
a declared sub-domain, `restricted_v1`:

* no float anywhere;
* every integer within `-(2^53 - 1)` to `2^53 - 1` inclusive;
* container depth of the payload at most 31.

The depth comes from the Trident's limits. At the default `max_depth` of 32
the envelope object is nesting level 1, so the payload may nest 31 levels;
`seal` and `verify` refuse depth 32 with `TooDeep` before any digest is
computed. `cns_digest::subject_digest` called directly accepts depth
`max_depth` (32) and refuses 33. Both numbers are pinned by
`the_depth_boundary_is_the_documented_one` in
`crates/stack-trident/tests/cns_digest.rs`. A deployment that configures a
different `max_depth` moves this boundary; the vectors cover the default only.

Envelope size (65,536 canonical JSON bytes) and node count (`max_nodes`, 16,384) are
transport caps of a deployment, not part of the digest domain; every
`restricted_v1` vector and case seals and verifies within them at the
defaults (tested).

**Decision.** The Trident stays on this declared restricted domain. Inside
it, rendering and digest are identical to CNS. Outside it, the Trident
refuses with a typed error (`NonInteger`, `IntegerOutOfRange`, `TooDeep`,
`NonFinite`). It never computes a different digest and never falls back to
another canonicalization. The canonical JSON in `canonical.rs` is what the
MAC covers; it is not a digest of the subject, and a digest computed from it
does not verify (`a_canonical_json_digest_never_equals_the_cns_digest_and_never_verifies`).
A CNS rendering of content always begins with `d:` and canonical JSON of an
object with `{`, so the two hash different byte strings for every content.

## Vector files and how they stay in sync

| file in CNS | vendored here | contents |
|---|---|---|
| `contracts/digest-vectors.json` | `crates/stack-sentinel/tests/fixtures/cns-digest-vectors.json` | 38 named vectors (27 `restricted_v1`), 7 refusals, the domain |
| `contracts/digest-differential.json` | `crates/stack-sentinel/tests/fixtures/digest-differential.json` | 400 cases from `random.Random(20261104)` in `cns_composition/digest_differential.py` (283 `restricted_v1`). The file's own note says to regenerate with `digest_vectors --write`; the seed and the generator are in `digest_differential.py` |

Each vector and case carries `content`, `rendering`, `digest` and
`restricted_v1`. The flag is computed by CNS's generator, never written by
hand. The copies here are exact copies of CNS's files; CNS's drift check
compares them as parsed JSON, every field included.

What checks what:

* CNS: the files are exactly what `subject_digest` produces now; the first 24
  digests (schema 1) are pinned literally; `python -m
  cns_composition.digest_vectors --stack DIR` reports a vendored copy that
  differs from CNS's file in any field.
* CNS `links.yml`, job `kernel-digest`: on a pull request or push to main
  touching `cns/gate.py` or the contract files, copies CNS's files over the
  vendored ones in a STACK-Kernel checkout and runs the two Rust suites
  below. STACK-Kernel does not depend on CNS to build or test.
* Here, `cargo test -p stack-sentinel --test cns_vectors`: rendering bytes
  and digest of every vector and case, every refusal, exact counts.
* Here, `cargo test -p stack-trident --test cns_digest`: restricted entries
  identical in rendering and digest and accepted in a sealed envelope; every
  other entry refused with a typed error; exact counts; the depth boundary.

To update: regenerate in CNS, copy both files here, change the exact counts
in the two test files if the number of entries changed, and make both suites
pass.

## Versioning and compatibility

* A change that alters the digest of any input that is valid today is
  breaking. It needs a new `digest_version`, and both Rust reproductions
  change with it. The 24 schema 1 digests are frozen by test in CNS.
* Turning an accepted input into a refusal is breaking for that input. CNS
  did this once (lone surrogates and `bytearray`, `memoryview`,
  `array.array` became `TypeError`); none of those had a digest Rust could
  reproduce, since JSON cannot carry them.
* Adding vectors, cases, refusals or metadata keeps `cns-digest/1`, but the
  vendored copies and the exact counts here must follow, so it needs a
  STACK-Kernel change.
* Changes in CNS that require a STACK-Kernel review: any edit to
  `cns/gate.py::_canonical` or `subject_digest`, either contract file, or
  the `restricted_v1` rule in `cns_composition/digest_vectors.py`.
* Widening `restricted_v1` (floats, larger integers, more depth in the
  Trident) is a STACK-Kernel change with its own review, and the CNS
  generator's `restricted_v1` function changes with it.
