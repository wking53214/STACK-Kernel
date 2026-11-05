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

## 2026-11-05 held-out `heldout_2026-11-05.jsonl`, AFTER Step 2

- Rules: `rules.rs` with SHA-256 `9282f00fafbd23b4e0571bfff7aac8575ab4abbb41ee91b32b6a90f91bf28425`
  (the Step 2 commit). Same evidence configuration.
- Held-out SHA-256 unchanged (`b2869df2...b321`); the manifest matched.
- Raw output: `after_step2.json` (corpus section lists the development files
  as they were at that run, without the held-out file).
- Caught 57 of 76 (75.0 percent, Wilson 95 percent 64.2 to 83.4), up from
  31 (40.8). False positives 10 of 69 (14.5 percent, 8.1 to 24.7), down from
  12 (17.4). One run, after all rule changes were done.
- The file is now **retired**: it was run against changed rules, so it was
  moved to `corpus/` as a development set (hash unchanged) and the manifest
  says so. No unseen held-out set remains.

### Held-out, per family (hostile: caught of total; benign: flagged of total)

| Family | Before | After |
|---|---|---|
| plain_injection | 12 of 13 | 12 of 13 |
| split_phrase | 7 of 9 | 7 of 9 |
| invisible_chars | 5 of 11 | 11 of 11 |
| homoglyph | 0 of 12 | 12 of 12 |
| separator | 2 of 10 | 10 of 10 |
| encoding | 0 of 7 | 0 of 7 |
| paraphrase | 0 of 8 | 0 of 8 |
| harmful_build | 5 of 6 | 5 of 6 |
| benign_general | 0 of 27 flagged | 0 of 27 flagged |
| benign_near_miss | 12 of 42 flagged | 10 of 42 flagged |

Benign near-miss changes: three "secret" false positives fixed (secret recipe,
secret to staying productive, secret hiding spot), one new false positive
(`print YOUR_API_KEY_HERE`, caused by treating the underscore as a word
separator; recorded as R2-E-18). The nine other near-miss flags are the known
ones of the ported rules and the deny list.

### Development files, before and after (caught, missed, benign flagged, benign clean)

| File | Before | After |
|---|---|---|
| benign | 0, 0, 6, 43 | 0, 0, 6, 43 |
| dev | 18, 0, 0, 0 | 18, 0, 0, 0 |
| encodings | 0, 6, 0, 0 | 2, 4, 0, 0 |
| heldout_v1 | 12, 2, 0, 0 | 12, 2, 0, 0 |
| paraphrases | 0, 8, 0, 0 | 0, 8, 0, 0 |
| race02_evasions | 1, 15, 1, 0 | 14, 2, 0, 1 |
| red_team | 18, 0, 0, 0 | 18, 0, 0, 0 |
| split | 3, 1, 0, 0 | 3, 1, 0, 0 |

Percent and HTML-entity escapes (the two missed `race02_evasions` rows) are
not decoded: see the report for why.
