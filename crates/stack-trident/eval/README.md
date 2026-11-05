# Rule inspector evaluation corpus

Status: **implemented and tested** (harness), **measured** (numbers in
`../RULE_INSPECTOR_EVAL.md`). The `RuleInspector` is a supplemental
inspection layer. It is not a semantic defense and never a substitute for
trusted authorization. These files measure how many labelled examples it
flags; they say nothing about unseen text.

## Layout

```
eval/
  corpus/*.jsonl            development sets, one file per set; free to run
  heldout_sealed/*.jsonl    sealed held-out files (see PROCESS.md); empty now
  heldout_manifest.json     SHA-256 of each held-out file, committed
  results/                  logged runs: commit, corpus hash, full numbers
  PROCESS.md                the held-out protocol
```

A row is one JSON object per line: `id`, `family`, `label` (`hostile` or
`benign`), `provenance`, `added_commit` (the commit the row was written on
top of), and one of `text`, `text_b64` (base64 of the raw bytes) or `parts`
(an array of strings inspected in order, each with the tails of the parts
that passed before it; `lookback`, default 3). Families: `plain_injection`,
`deny_marker`, `split_phrase`, `invisible_chars`, `homoglyph`, `separator`,
`encoding`, `paraphrase`, `harmful_build`, `benign_general`,
`benign_near_miss`.

Corpus files:

| File | Content |
|---|---|
| `dev.jsonl` | the 18 attacks the rules were written against |
| `heldout_v1.jsonl` | the 14 attacks of the first held-out set (measured once, 12 of 14, before any change; now dev) |
| `red_team.jsonl` | the dev attacks hidden by case, spacing, invisible and control characters |
| `paraphrases.jsonl`, `encodings.jsonl` | recorded gaps |
| `benign.jsonl` | 49 ordinary and near-miss texts |
| `split.jsonl` | a phrase cut over 2 to 5 parts |
| `heldout_2026-11-05.jsonl` | 76 hostile and 69 benign rows authored 2026-11-05 before any rule change; run once before and once after Step 2, then retired into dev |
| `race02_evasions.jsonl` | evasions found by the RACE-02 probe (R2-E-01, R2-E-02) and the "secret garden" false alarm |

## Reproduce

```text
cargo run -p stack-trident --example rules_eval -- crates/stack-trident/eval/corpus
cargo run -p stack-trident --example rules_eval -- crates/stack-trident/eval/corpus \
  --held-out crates/stack-trident/eval/heldout_sealed/<file>.jsonl   # only when a sealed file exists --commit "$(git rev-parse --short HEAD)"
cargo test -p stack-trident --locked --test puzzle_eval
```

The output is one JSON document and is deterministic. The evidence
configuration (default rules plus deny markers `TROJAN` and `EXFIL-TOKEN`) is
fixed in `puzzle::eval::evidence_config` and echoed in the report. The report
has totals, per family, per file, split-phrase coverage by number of cuts,
coverage per Unicode class (classified by the harness's own ranges, not the
rules' tables), and the id of every false negative and false positive.
Intervals are Wilson 95 percent.

Counting: a hostile row is caught only on `Hostile`; `Suspicious` is a miss.
A benign row is a false positive only on `Hostile`.

`tests/puzzle_eval.rs` pins the per-file counts, so a change to the rules or
to a corpus file that moves a number fails the test until the pinned table is
changed with a reason.
