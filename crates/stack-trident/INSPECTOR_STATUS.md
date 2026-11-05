# Status of the puzzle inspector

Labels: **implemented**, **tested**, **experimental**, **planned**. The
`RuleInspector` and the puzzle gate are **implemented** and **tested** as a
supplemental inspection layer. Nothing here is a semantic defense.

- `Released` from the puzzle gate is not a permit. It means the pieces of a
  puzzle are complete and the inspector found no known pattern. It is never
  authorization, and no code may treat it as authorization.
- Suspicious content cannot override an independent authorization decision,
  and a clean verdict cannot grant one. Authorization is decided elsewhere
  (`stack-authority`, `stack-admission`, `stack-receipt`) from signed
  capabilities and decisions.
- Four things stay distinct and are reported separately:
  1. suspicious structure (`Finding::Suspicious`: not UTF-8, NUL, too many
     control characters, too large; not a breach);
  2. known hostile patterns (`Finding::Hostile`: a deny marker, an injection
     phrase, a harmful-build sentence; a breach);
  3. untrusted content (every whole, whatever the verdict);
  4. an actual authorization failure (not decided by this module).
- The inspector does not see paraphrases, encodings (percent, HTML entity,
  base64, ROT13, leetspeak, hex), translations, look-alike characters outside
  its short tables, or meaning assembled across separate messages. The
  measured numbers and the examples it misses are in `RULE_INSPECTOR_EVAL.md`.

**[tested]** `tests/puzzle_supplemental_guard.rs` fails when `stack-authority`,
`stack-admission` or `stack-receipt` (or any other workspace crate) names the
puzzle module or an inspector type, and when `stack-authority` or
`stack-receipt` depends on `stack-trident`. It is a grep-style tripwire: it
cannot see use through a path it does not scan.
