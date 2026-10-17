## Sources

Five web pages and six local files were opened; seven papers the network blocked are cited only from memory and search summaries.

*Sources opened while writing this manual; the local files are read-only repositories and the reference workspace*

### Web pages

| Source | What it supports |
|---|---|
| [dudect README](https://github.com/oreparaz/dudect) | Passing dudect does not prove code constant time ("Absolutely not"); its own reading of t below 10 is "maybe constant time". |
| [dudect source, src/dudect.h](https://raw.githubusercontent.com/oreparaz/dudect/master/src/dudect.h) | A failure line of 10, with a comment that TVLA practice uses 4.5; percentile cropping; the second-order test. |
| [tlsfuzzer timing analysis guide](https://raw.githubusercontent.com/tlsfuzzer/tlsfuzzer/master/docs/source/timing-analysis.rst) | Samples needed grow as 1/e^2 for an effect of size e; the noise sources a timing runner must control; KS use; a negative result does not prove a side channel absent. |
| [binsec/rel](https://github.com/binsec/rel) | Constant-time checking of machine code by relational symbolic execution, described as bounded verification and bug-finding (IEEE S&P 2020). |
| [Replication of Brumley and Boneh (dj311)](https://github.com/dj311/remote-timing-attacks-are-practical/blob/master/README.md) | A 2020 attempt found RSA blinding on by default in later mod_ssl, and had not recovered a key when its log ends. |

### Local files

| Source | What it supports |
|---|---|
| [CNS gate.py](https://github.com/wking53214/CNS/blob/main/cns/gate.py) | GatePosition (ALPHA, OMEGA), GateOutcome (PASS, RETRY, TERMINAL_BREACH) and `subject_digest`, a SHA-256 over a type-tagged rendering. Public, Apache-2.0. |
| [sentinel_os twin_custody.py](file:///home/user/sentinel_os/sentinel_os/twin_custody.py) | The Python verifier that tack-sentinel matches (`verify_rows`, `deep_verify_row`, `check_head_anchor`), and the 16-character hash prefixes in its messages. |
| [sentinel_os canonical_fields.py](file:///home/user/sentinel_os/sentinel_os/canonical_fields.py) | `OPTIONAL_HASHED_FIELDS`, the shared list of optional columns that enter a row's hash when present. |
| [sentinel_os api_key_auth.py](file:///home/user/sentinel_os/sentinel_os/api_key_auth.py) | `_find_key_constant_time` checks every key with `hmac.compare_digest` and no early exit; its two failure replies differ in text. |
| [observe-perceive observe_consolidated.py](file:///home/user/observe-perceive/observe_consolidated.py) | `sanitize_context` returns a cleaned copy plus notes: the repair approach the Inlet deliberately does not take. |
| [tack-anc-harness victim.rs](file:///tmp/claude-0/-home-user/dc79eb2b-c581-5d0f-9c7a-4872a4d2458f/scratchpad/tack/crates/tack-anc-harness/src/victim.rs) | The early-exit victim `leaky_validate` and the constant-time control `ct_validate`, over a 32-byte token. |

These claims rest on memory or search-engine summaries, because the network refused the papers:

- The epoch leakage bound of log^2 T bits (Askarov, Zhang and Myers, CCS 2010), and its language-level form (Zhang, Askarov and Myers, PLDI 2012).
- Remote timing resolution of 15 to 100 us across the Internet and about 100 ns on a LAN (Crosby, Wallach and Riedi, ACM TISSEC 2009).
- RSA key extraction from an OpenSSL-based server on a local network (Brumley and Boneh, USENIX Security 2003).
- The TVLA origin of the 4.5 line (Goodwill, Jun, Jaffe and Rohatgi, NIST workshop 2011), corroborated by the opened dudect source.
- ct-verif's method of checking LLVM IR through product programs (Almeida et al., USENIX Security 2016).
- The dudect paper's method (Reparaz, Balasch and Verbauwhede, DATE 2017), confirmed only through its opened source and README.
