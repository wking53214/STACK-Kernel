# Run log

One entry per logged run: rules commit, corpus hash, held-out hash, numbers.
Raw output is in the JSON file named in the entry.

## 2026-11-05 held-out `heldout_2026-11-05.jsonl`, BEFORE any rule change

- Rules: `crates/stack-trident/src/puzzle/rules.rs` as at commit `67bdf31`
  (unchanged by the harness commit). Evidence configuration: default rules,
  deny markers `TROJAN`, `EXFIL-TOKEN`.
- Held-out SHA-256: `b2869df2e62456d23fd4e597e6762abaf03531f6fb9393f5375abfd4baa7b321`
  (matches `heldout_manifest.json`).
- Corpus SHA-256 (over file names and file hashes): `41a23169aae651c773478f41fa33587f9e6d8772f6f8954f836a21c62197a42b`.
- Raw output: `before_67bdf31.json`.
- Held-out: 76 hostile, 69 benign. Caught 31 of 76 (40.8 percent, Wilson 95
  percent 30.4 to 52.0). False positives 12 of 69 (17.4 percent, 10.2 to 28.0).
- Disclosure: the file was authored by the same agent that then read the rule
  source in the same session, so it is not blind to the rule internals; it was
  written to cover each family and the known baseline failure classes, not to
  fit the word lists. The run was executed twice against the same frozen rules
  (the first time the output was cut by a pipe); the output is deterministic
  and identical. No rule changed between the two.
