"""Produce the named-anchor fixtures with sentinel_os's own anchor writer.

Run from anywhere, read-only against a sentinel_os checkout:

    python3 -I generate.py /path/to/sentinel_os /path/to/CNS

It reads the head of tests/fixtures/differential/base_post_receipts.json and
calls twin_custody.write_head_anchor (the real Python code, which signs the
optional name with head_anchor_payload) with the TEST FIXTURE KEY below, a
fixed sealed_at and two names (ASCII, and non-ASCII to pin the ensure_ascii
encoding of the signed payload). twin_custody imports cns.gate, taken from
the CNS checkout given second. Bytecode writing is off, so nothing in either
checkout is modified.
"""
import json
import os
import sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(sys.argv[1], "sentinel_os"))
sys.path.insert(1, sys.argv[2])

import twin_custody  # noqa: E402

# TEST FIXTURE KEY, the one sentinel_os's suite labels as not a real secret.
KEY = b"fixture-attestation-key-not-a-real-secret"
SEALED_AT = "2026-11-04T00:00:00+00:00"

with open(os.path.join(HERE, "..", "differential", "base_post_receipts.json"), encoding="utf-8") as fh:
    rows = sorted(json.load(fh)["rows"], key=lambda r: r["id"])

for out, name in (("named_ascii.anchor", "nightly-checkpoint 2026-11-04"),
                  ("named_non_ascii.anchor", "Kontrollpunkt über Nacht ✓")):
    twin_custody.write_head_anchor(os.path.join(HERE, out), rows[-1]["current_hash"], len(rows),
                                   KEY, sealed_at=SEALED_AT, name=name)
