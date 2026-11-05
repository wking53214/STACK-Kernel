# Held-out protocol

The point of a held-out set is that nobody tuned the rules against it. That
holds only until it is run against changed rules, so the protocol is short and
strict.

1. **Author** the held-out file in `heldout_sealed/`. Record the date, the
   author, what the author had seen of the rule internals, and that no rule
   change has happened since. Commit the file's SHA-256 in
   `heldout_manifest.json` with status `sealed`.
2. **Freeze** the rules and the evidence configuration. Record the commit hash
   of the frozen rules. Nothing under `src/puzzle/rules.rs` changes between
   freeze and the "before" run.
3. **Run once** for the "before" number:
   `rules_eval <corpus> --held-out <file> --commit <frozen commit>`. The
   harness checks the file's hash against the manifest and exits 2 on a
   mismatch. Save the full output in `results/` and add a line to
   `results/LOG.md` (commit, corpus hash, held-out hash, numbers).
4. **Change** the rules, with the dev sets (`corpus/`) as the measuring tool.
   The held-out file is not run during this step, and no test runs it; the
   test suite only checks its hash.
5. **Run once** for the "after" number against the changed rules, log it the
   same way.
6. **Retire.** A held-out file that has been run against changed rules is no
   longer held out. Move it into `corpus/` (status `retired` in the manifest,
   path updated, hash unchanged) and author a fresh sealed file before the
   next rule change. A rule change is not measured by an unseen set unless a
   sealed file exists at that moment.

What this does not give: a held-out set authored by the same people who wrote
the rules shares their blind spots, and a few dozen rows give wide intervals
(see the Wilson bounds in every report). The numbers describe these rows.
