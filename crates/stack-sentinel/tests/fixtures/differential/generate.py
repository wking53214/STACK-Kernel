#!/usr/bin/env python3
"""Generate the differential fixtures for tack-sentinel.

Run with the sentinel_os virtualenv, pointing at a sentinel_os checkout:

    SENTINEL_OS=/home/user/sentinel_os PYTHONDONTWRITEBYTECODE=1 \\
        /opt/venvs/sos/bin/python tests/fixtures/differential/generate.py

It is read-only with respect to sentinel_os: it imports twin_custody and
authorized_by_attestation, and runs tools/verify_receipts.py as a subprocess
on temporary files. It writes only into this directory:

* base_post_receipts.json: a ledger export built with the sentinel_os
  witness and attestation functions, carrying what the pre-receipts fixture
  lacks (an attestation_policy marker, subject_digest, abv3, abv2 and legacy
  signatures, a derived shuffle_seed, every record kind, non-ASCII text,
  floats that exercise repr, and big ints).
* manifest.json: mutated exports, each stored as a small diff against a base
  (so the Rust side rebuilds exactly the file Python checked), with the
  anchor and key file used and the verdict the Python tool printed.
* corpus.json: JSON texts with Python's json.dumps output in both separator
  styles and the CNS subject digest, to pin the serializer byte for byte.

Every key in here is a TEST FIXTURE, never a real secret.
"""

import copy
import hashlib
import json
import os
import random
import struct
import subprocess
import sys
import tempfile

SENTINEL_OS = os.environ.get("SENTINEL_OS", "/home/user/sentinel_os")
KERNEL = os.path.join(SENTINEL_OS, "sentinel_os")
TOOL = os.path.join(SENTINEL_OS, "tools", "verify_receipts.py")
sys.dont_write_bytecode = True
sys.path.insert(0, KERNEL)

import twin_custody as tc  # noqa: E402
from governance import authorized_by_attestation as att  # noqa: E402
from cns.gate import subject_digest  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.dirname(HERE)

# TEST FIXTURE KEYS. The first is the key sentinel_os's own suite labels
# "fixture-attestation-key-not-a-real-secret".
FIXTURE_KEY = b"fixture-attestation-key-not-a-real-secret"
OTHER_KEY = b"tack-sentinel-other-test-fixture-key-not-a-real-secret"
SEALED_AT = "2026-09-30T00:00:00+00:00"

COLUMNS = list(tc.SHIPPED_COLUMNS)


def blank_row(i, kind):
    row = {c: None for c in COLUMNS}
    row["id"] = i
    row["timestamp"] = f"2026-09-30T00:00:{i:02d}+00:00"
    row["record_kind"] = kind
    return row


def seal(row, prev, sign=None):
    """Chain, sign (abv3 / abv2 / legacy / None) and hash one row."""
    row["previous_hash"] = prev
    if sign == "abv3":
        row["authorized_by_sig"] = att.sign_authorized_by(
            row["authorized_by"], prev, row["record_kind"], FIXTURE_KEY,
            content_prehash=tc.content_prehash_of(row))
    elif sign == "abv2":
        row["authorized_by_sig"] = att.sign_authorized_by(
            row["authorized_by"], prev, row["record_kind"], FIXTURE_KEY)
    elif sign == "legacy":
        row["authorized_by_sig"] = att._hmac_hex(
            FIXTURE_KEY, att._payload(row["authorized_by"], prev, row["record_kind"]))
    row["current_hash"] = tc.recompute_current_hash(row)
    return row["current_hash"]


def decision(i, input_data, **extra):
    row = blank_row(i, "governance_decision")
    row.update(action_type="governance_decision", node="billing_queue",
               cassette_version="ivr:standard-ivr:2.0.3", input_data=input_data,
               policy_parameters={"threshold": 0.7, "ceiling": 1e16, "floor": 1e-05},
               reason="decision \u00e9 with \"quotes\" and a \\ backslash",
               decision_output={"approved": True, "confidence": 0.1 + 0.2,
                                "gate": {"position": "omega", "outcome": "pass"}},
               previous_value=0.5, applied_value=0.6,
               data={"parameter_changed": True, "note": "caf\u00e9 \u2615"})
    row.update(extra)
    if row["input_data"]:
        row["subject_digest"] = subject_digest(row["input_data"])
    return row


def build_post_receipts():
    rows = []
    prev = "genesis"
    fp = att.key_fingerprint(FIXTURE_KEY)

    r = blank_row(1, "legacy")
    r.update(action_type="threshold_adjust", node="billing_queue", previous_value=-0.0,
             applied_value=3.0, reason="legacy caf\u00e9 \u2615 \U0001F600 tab\tline\u2028end",
             data={"floats": [0.1, 1e16, 1e-05, 123456789.125, 5e-324, 1.7976931348623157e308],
                   "big": 2 ** 70, "neg": -(2 ** 65), "nested": {"z": [], "a": {}},
                   "ctrl": "\x01\x7f\x1f", "why": "fixture"})
    prev = seal(r, prev); rows.append(r)

    r = blank_row(2, "attestation_policy")
    r.update(action_type="attestation_policy", node="ledger",
             reason=f"authorized_by attestation enforced from this row under key {fp}",
             data={"record_kind": "attestation_policy", "parameter_changed": False,
                   "key_fingerprint": fp, "enforced_at": SEALED_AT})
    prev = seal(r, prev); rows.append(r)

    r = decision(3, {"score": 0.93, "caller": "\u00fc\u00f1\u00ee", "items": [1, 2.5, None, True],
                     "big": 2 ** 80},
                 authorized_by="harness:production", model_identity="model-x")
    prev = seal(r, prev, "abv3"); rows.append(r)

    r = decision(4, {"score": 0.5, "flags": {"b": False, "a": 0}},
                 ai_cost={"model": "m", "input_tokens": 12, "output_tokens": 1, "cost_usd": 0.0},
                 outcome_obligation="loan_performance@24mo", cassette_code_hash="c" * 64)
    prev = seal(r, prev); rows.append(r)

    r = blank_row(5, "observed_event")
    r.update(action_type="observed_event", node="ivr",
             input_data={"episode_id": "ep-1", "event_id": "ev-1", "domain": "ivr",
                         "kind": "friction", "occurred_at": 1727654400.25,
                         "observed_at": 1727654401.0, "source": "twilio",
                         "provenance": "verified", "method": None,
                         "fields": {"count": 2}, "detail": {"note": "\u00e9"},
                         "schema_version": 1, "reducer_version": "r1"})
    prev = seal(r, prev); rows.append(r)

    r = blank_row(6, "contract_egress")
    r.update(action_type="contract_egress", node="dpo", cassette_version="contract:v1",
             authorized_by="dpo:acme", decision_output={"finding": "granted", "risk": 0.25},
             data={"counterparty": "acme", "decision": "granted", "data_scope": ["calls"],
                   "recipient": "auditor", "recipient_class": "regulator", "purpose": "audit",
                   "approval_reference": "APR-1", "occurred_at": SEALED_AT})
    prev = seal(r, prev, "abv2"); rows.append(r)

    r = blank_row(7, "decision_supersession")
    r.update(action_type="decision_supersession", node="billing_queue",
             cassette_version="ivr:standard-ivr:2.0.3", supersedes_id=3,
             supersedes_hash=rows[2]["current_hash"], authorized_by="auditor:jane-doe",
             reason="corrected", decision_output={"approved": False})
    prev = seal(r, prev, "abv2"); rows.append(r)

    r = decision(8, {"score": 0.71, "text": "seeded row"}, authorized_by="harness:production")
    r["shuffle_seed"] = att.derive_shuffle_seed(prev, "governance_decision", FIXTURE_KEY)
    prev = seal(r, prev, "abv3"); rows.append(r)

    r = blank_row(9, "human_selection")
    r.update(action_type="human_selection", node="review", cassette_version="ivr:standard-ivr:2.0.3",
             decision_hash=rows[7]["current_hash"], decision_output={"recommended": "a"},
             data={"human_selection": "b", "rationale": "reviewer \u00e9"})
    prev = seal(r, prev); rows.append(r)

    r = blank_row(10, "regulatory_disclosure")
    r.update(action_type="regulatory_disclosure", node="reg", cassette_version="reg:tcpa:1",
             decision_output={"finding": "disclosed"},
             data={"regulation": "TCPA", "check": "consent", "action": "disclose", "subject": "s-1"})
    prev = seal(r, prev); rows.append(r)

    r = blank_row(11, "cassette_binding")
    r.update(action_type="cassette_binding", node="ivr:standard-ivr:2.0.4",
             cassette_version="ivr:standard-ivr:2.0.4", cassette_hash="e" * 64,
             data={"parameter_changed": False, "record_kind": "cassette_binding"})
    prev = seal(r, prev); rows.append(r)

    r = blank_row(12, "recommendation_shadow_run")
    r.update(action_type="recommendation_shadow_run", node="shadow", cassette_version="mortgage:v1",
             input_data={"rate": 6.125}, decision_output={"recommend": "modify"},
             data={"recommendation_kind": "loan_mod", "subject": "loan-1"})
    prev = seal(r, prev); rows.append(r)

    r = blank_row(13, "recommendation_shadow_score")
    r.update(action_type="recommendation_shadow_score", node="shadow",
             shadow_run_hash=rows[11]["current_hash"], input_data={"actual": "modified"},
             decision_output={"score": 1.0})
    prev = seal(r, prev); rows.append(r)

    r = blank_row(14, "outcome_harm_event")
    r.update(action_type="outcome_harm_event", node="harm", cassette_version="mortgage:v1",
             decision_output={"harm": "late fee"},
             data={"harmed_decision": rows[2]["current_hash"], "harm_kind": "financial",
                   "subject": "loan-1", "discovered_at": SEALED_AT})
    prev = seal(r, prev); rows.append(r)

    r = blank_row(15, "regulatory_cassette_inserted")
    r.update(action_type="regulatory_cassette_inserted", node="reg",
             cassette_version="reg:tcpa:1", authorized_by="auditor:jane-doe",
             cassette_hash="a" * 64, data={"mode": "enforce", "regulation": "TCPA"})
    prev = seal(r, prev, "legacy"); rows.append(r)

    r = decision(16, {"score": 0.2, "items": []}, authorized_by="harness:production")
    prev = seal(r, prev, "abv3"); rows.append(r)
    return rows


# ---------------------------------------------------------------------------
# running the Python tool
# ---------------------------------------------------------------------------

TMP = tempfile.mkdtemp(prefix="tack-sentinel-diff-")


def run_tool(rows, anchor_text, key_text, fps):
    export = {"format": "sentinel_os.ledger_export.v1", "columns": COLUMNS, "rows": rows}
    export_path = os.path.join(TMP, "export.json")
    with open(export_path, "w") as fh:
        json.dump(export, fh, default=str)
    anchor_path = os.path.join(TMP, "ledger.anchor")
    if os.path.exists(anchor_path):
        os.remove(anchor_path)
    if anchor_text is not None:
        with open(anchor_path, "w") as fh:
            fh.write(anchor_text)
    key_path = os.path.join(TMP, "keys.txt")
    with open(key_path, "w") as fh:
        fh.write(key_text)
    env = {k: v for k, v in os.environ.items() if not k.startswith("ICEBERG_LEDGER_ATTESTATION")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    run = subprocess.run([sys.executable, TOOL, "--export", export_path, "--anchor", anchor_path,
                          "--trusted-fingerprints", ",".join(fps), "--key-file", key_path],
                         capture_output=True, text=True, env=env)
    lines = run.stdout.splitlines()
    first = lines[0] if lines else ""
    parts = first.split(" ")
    verdict = parts[0] if parts and parts[0] else None
    row = None
    if len(parts) > 1 and parts[1].startswith("row="):
        row = parts[1][4:]
    also = any(line.startswith("  also: ") for line in lines)
    return {"exit": run.returncode, "verdict": verdict, "row": row, "also": also,
            "stdout": run.stdout, "stderr_tail": run.stderr.strip().splitlines()[-1:] if run.stderr else []}


def export_digest(rows):
    export = {"format": "sentinel_os.ledger_export.v1", "columns": COLUMNS, "rows": rows}
    return hashlib.sha256(json.dumps(export, sort_keys=True, default=str).encode()).hexdigest()


def anchor_for(rows, key=FIXTURE_KEY, entries=None, head=None):
    entries = len(rows) if entries is None else entries
    if head is None:
        head = rows[entries - 1]["current_hash"] if entries > 0 else "0" * 64
    return tc.build_head_anchor(head, entries, key, sealed_at=SEALED_AT)


def anchor_text(anchor):
    return json.dumps(anchor, indent=2, sort_keys=True) + "\n"


# ---------------------------------------------------------------------------
# mutations: each works on a list of (origin index, row) pairs
# ---------------------------------------------------------------------------

def pairs(base):
    return [(i, copy.deepcopy(r)) for i, r in enumerate(base)]


def rechain(ps, start):
    for i in range(start, len(ps)):
        if i > 0:
            ps[i][1]["previous_hash"] = ps[i - 1][1]["current_hash"]
        ps[i][1]["current_hash"] = tc.recompute_current_hash(ps[i][1])


def flip_char(s, at):
    c = s[at]
    return s[:at] + ("0" if c != "0" else "1") + s[at + 1:]


def canon(v):
    return json.dumps(v, sort_keys=True, default=str)


def diff(base, ps):
    out = []
    for origin, row in ps:
        b = base[origin]
        entry = {"base": origin}
        sets = {k: v for k, v in row.items() if k not in b or canon(v) != canon(b[k])}
        dels = [k for k in b if k not in row]
        if sets:
            entry["set"] = sets
        if dels:
            entry["del"] = dels
        out.append(entry)
    return out


def rows_of(ps):
    return [r for _, r in ps]


CASES = []


def case(name, base_name, base, ps, anchor="base", keys=(FIXTURE_KEY,), fps=None):
    rows = rows_of(ps)
    if anchor == "base":
        a_text = anchor_text(anchor_for(base))
    elif anchor is None:
        a_text = None
    else:
        a_text = anchor
    key_text = "".join(k.decode() + "\n" for k in keys)
    fps = [att.key_fingerprint(k) for k in keys] if fps is None else fps
    py = run_tool(rows, a_text, key_text, fps)
    CASES.append({"name": name, "base": base_name, "rows": diff(base, ps),
                  "export_sha256": export_digest(rows), "anchor": a_text,
                  "key_file": key_text, "fingerprints": fps, "python": py})
    return py


def idx(base, pred):
    return next(i for i, r in enumerate(base) if pred(r))


def scripted(base_name, base):
    n = len(base)
    case("clean", base_name, base, pairs(base))
    ps = pairs(base); ps.reverse()
    case("reorder_array_reversed", base_name, base, ps)
    ps = pairs(base); ps[1], ps[4] = ps[4], ps[1]
    case("reorder_array_swap", base_name, base, ps)
    ps = pairs(base); ps[2][1]["id"], ps[5][1]["id"] = ps[5][1]["id"], ps[2][1]["id"]
    case("swap_ids", base_name, base, ps)
    for k in (0, n // 2, n - 1):
        ps = pairs(base); ps[k][1]["reason"] = str(ps[k][1]["reason"]) + " edited"
        case(f"edit_reason_row{k}", base_name, base, ps)
        ps = pairs(base); ps[k][1]["reason"] = str(ps[k][1]["reason"]) + " edited"; rechain(ps, k)
        case(f"edit_reason_row{k}_rechained", base_name, base, ps)
        ps = pairs(base); ps[k][1]["current_hash"] = flip_char(ps[k][1]["current_hash"], 7)
        case(f"flip_current_hash_row{k}", base_name, base, ps)
        ps = pairs(base); ps[k][1]["previous_hash"] = flip_char(ps[k][1]["previous_hash"], 0) \
            if ps[k][1]["previous_hash"] != "genesis" else "genesiS"
        case(f"flip_previous_hash_row{k}", base_name, base, ps)
    ps = pairs(base); del ps[n // 2]
    case("delete_middle_row", base_name, base, ps)
    ps = pairs(base); del ps[n // 2]; rechain(ps, n // 2)
    case("delete_middle_row_rechained", base_name, base, ps)
    ps = pairs(base); del ps[0]
    case("delete_first_row", base_name, base, ps)
    ps = pairs(base); del ps[-1]
    case("delete_last_row", base_name, base, ps)
    ps = pairs(base); del ps[-3:]
    case("delete_last_three_rows", base_name, base, ps)
    ps = pairs(base); del ps[-3:]
    case("delete_last_three_rows_reanchored", base_name, base, ps,
         anchor=anchor_text(anchor_for(rows_of(ps))))
    ps = pairs(base); del ps[3][1]["node"]
    case("drop_required_column", base_name, base, ps)
    case("anchor_missing", base_name, base, pairs(base), anchor=None)
    case("anchor_garbage", base_name, base, pairs(base), anchor="{not json")
    case("anchor_wrong_version", base_name, base, pairs(base),
         anchor=anchor_text(dict(anchor_for(base), v=2)))
    a = anchor_for(base); a["head"] = flip_char(a["head"], 3)
    case("anchor_head_flipped", base_name, base, pairs(base), anchor=anchor_text(a))
    a = anchor_for(base); a["entries"] = a["entries"] + 2
    case("anchor_entries_edited", base_name, base, pairs(base), anchor=anchor_text(a))
    case("anchor_sealed_two_more_rows", base_name, base, pairs(base),
         anchor=anchor_text(tc.build_head_anchor("f" * 64, n + 2, FIXTURE_KEY, sealed_at=SEALED_AT)))
    case("anchor_sealed_earlier_prefix", base_name, base, pairs(base),
         anchor=anchor_text(anchor_for(base, entries=n - 4)))
    case("anchor_prefix_wrong_head", base_name, base, pairs(base),
         anchor=anchor_text(anchor_for(base, entries=n - 4, head=base[n - 2]["current_hash"])))
    case("anchor_zero_entries", base_name, base, pairs(base),
         anchor=anchor_text(anchor_for(base, entries=0)))
    case("anchor_by_other_key_trusted", base_name, base, pairs(base),
         anchor=anchor_text(anchor_for(base, key=OTHER_KEY)), keys=(FIXTURE_KEY, OTHER_KEY))
    case("anchor_by_other_key_untrusted", base_name, base, pairs(base),
         anchor=anchor_text(anchor_for(base, key=OTHER_KEY)))
    case("untrusted_key_only", base_name, base, pairs(base), keys=(OTHER_KEY,))
    case("fingerprint_without_key", base_name, base, pairs(base), keys=(OTHER_KEY,),
         fps=[att.key_fingerprint(FIXTURE_KEY)])
    case("both_keys_trusted", base_name, base, pairs(base), keys=(OTHER_KEY, FIXTURE_KEY))

    signed = [i for i, r in enumerate(base) if r.get("authorized_by_sig")]
    for k in signed:
        ps = pairs(base)
        sig = ps[k][1]["authorized_by_sig"]
        ps[k][1]["authorized_by_sig"] = flip_char(sig, len(sig) - 5); rechain(ps, k)
        case(f"flip_signature_row{k}_rechained", base_name, base, ps)
        ps = pairs(base); ps[k][1]["authorized_by"] = "attacker:mallory"; rechain(ps, k)
        case(f"rename_authorized_by_row{k}_rechained", base_name, base, ps)
        ps = pairs(base); ps[k][1]["authorized_by_sig"] = None; rechain(ps, k)
        case(f"null_signature_row{k}_rechained", base_name, base, ps)


def receipts_cases(base):
    name = "post_receipts"
    decisions = [i for i, r in enumerate(base) if r["record_kind"] == "governance_decision"]
    first, second = decisions[0], decisions[1]
    ps = pairs(base); ps[second][1]["subject_digest"] = ps[first][1]["subject_digest"]
    case("copy_subject_digest", name, base, ps)
    ps = pairs(base); ps[second][1]["subject_digest"] = ps[first][1]["subject_digest"]; rechain(ps, second)
    case("copy_subject_digest_rechained", name, base, ps)
    ps = pairs(base); ps[first][1]["subject_digest"] = ps[second][1]["subject_digest"]; rechain(ps, first)
    case("copy_subject_digest_onto_signed_rechained", name, base, ps)
    ps = pairs(base); ps[second][1]["input_data"] = dict(ps[second][1]["input_data"], score=0.99)
    case("edit_input_data", name, base, ps)
    ps = pairs(base); ps[second][1]["input_data"] = dict(ps[second][1]["input_data"], score=0.99)
    rechain(ps, second)
    case("edit_input_data_rechained", name, base, ps)
    ps = pairs(base); ps[second][1]["subject_digest"] = None; rechain(ps, second)
    case("strip_subject_digest_rechained", name, base, ps)
    for k in (first, second):
        ps = pairs(base); ps[k][1]["shuffle_seed"] = "0" * 64; rechain(ps, k)
        case(f"forge_seed_row{k}_rechained", name, base, ps)
    seeded = idx(base, lambda r: r.get("shuffle_seed"))
    ps = pairs(base); ps[seeded][1]["shuffle_seed"] = flip_char(ps[seeded][1]["shuffle_seed"], 9)
    rechain(ps, seeded)
    case("flip_seed_rechained", name, base, ps)
    ps = pairs(base); ps[seeded][1]["shuffle_seed"] = None; rechain(ps, seeded)
    case("strip_seed_rechained", name, base, ps)
    marker = idx(base, lambda r: r["record_kind"] == "attestation_policy")
    ps = pairs(base); ps[marker][1]["reason"] = "edited"; rechain(ps, marker)
    case("edit_marker_rechained", name, base, ps)
    ps = pairs(base); del ps[marker]; rechain(ps, marker)
    case("delete_marker_rechained", name, base, ps)
    # the Python test's untrusted-key case: signatures fail before the anchor
    ps = pairs(base)
    ps[5][1]["authorized_by_sig"] = "abv2.0123456789abcdef." + "0" * 64; rechain(ps, 5)
    case("signature_names_unknown_key_rechained", name, base, ps)
    ps = pairs(base); ps[10][1]["data"] = dict(ps[10][1]["data"], parameter_changed=True)
    case("edit_data_flag_unhashed_kind", name, base, ps)
    ps = pairs(base); ps[0][1]["data"]["floats"][0] = 0.1000000000000001; rechain(ps, 0)
    case("edit_float_last_digit_rechained", name, base, ps)
    ps = pairs(base); ps[0][1]["previous_value"] = 0.0
    case("negative_zero_to_zero", name, base, ps)


def random_cases(base_name, base, rng, count):
    fields_skip = {"id"}
    kept = 0
    attempts = 0
    while kept < count and attempts < count * 5:
        attempts += 1
        ps = pairs(base)
        k = rng.randrange(len(ps))
        row = ps[k][1]
        field = rng.choice(sorted(c for c in row if c not in fields_skip))
        op = rng.choice(["str", "int", "float", "none", "flip", "del", "append"])
        if op == "str":
            row[field] = rng.choice(["x", "", "\u00e9", "genesis", "0" * 64])
        elif op == "int":
            row[field] = rng.choice([0, 1, -7, 2 ** 64])
        elif op == "float":
            row[field] = rng.choice([0.0, -0.0, 0.5, 1e16, 1e-05])
        elif op == "none":
            row[field] = None
        elif op == "flip":
            if not isinstance(row[field], str) or not row[field]:
                continue
            row[field] = flip_char(row[field], rng.randrange(len(row[field])))
        elif op == "del":
            del row[field]
        elif op == "append":
            ps.append((k, copy.deepcopy(row)))
        if rng.random() < 0.5:
            try:
                rechain(ps, k)
            except Exception:  # a mutation the witness itself cannot hash
                continue
        py = run_tool(rows_of(ps), anchor_text(anchor_for(base)),
                      FIXTURE_KEY.decode() + "\n", [att.key_fingerprint(FIXTURE_KEY)])
        if py["verdict"] not in ("VERIFIED", "TAMPERED", "TRANSPLANTED", "SEED_FORGED",
                                 "TRUNCATED", "UNATTESTED"):
            SKIPPED.append({"base": base_name, "field": field, "op": op,
                            "stderr_tail": py["stderr_tail"]})
            continue
        CASES.append({"name": f"random_{base_name}_{kept:03d}_{field}_{op}", "base": base_name,
                      "rows": diff(base, ps), "export_sha256": export_digest(rows_of(ps)),
                      "anchor": anchor_text(anchor_for(base)),
                      "key_file": FIXTURE_KEY.decode() + "\n",
                      "fingerprints": [att.key_fingerprint(FIXTURE_KEY)], "python": py})
        kept += 1


SKIPPED = []


# ---------------------------------------------------------------------------
# serializer corpus
# ---------------------------------------------------------------------------

def random_float(rng):
    pick = rng.random()
    if pick < 0.3:
        return struct.unpack("<d", struct.pack("<Q", rng.getrandbits(64)))[0]
    if pick < 0.5:
        return rng.uniform(-1e6, 1e6)
    if pick < 0.7:
        return rng.random() * 10 ** rng.randint(-30, 30)
    if pick < 0.85:
        return round(rng.uniform(-1000, 1000), rng.randint(0, 6))
    return rng.choice([0.0, -0.0, 1e15, 1e16, 9999999999999998.0, 1e-4, 1e-5, 0.1, 0.2 + 0.1,
                       5e-324, 2.2250738585072014e-308, 1.7976931348623157e308])


def random_str(rng):
    alphabet = ["a", "Z", " ", "\"", "\\", "/", "\n", "\t", "\x00", "\x1f", "\x7f", "\x80",
                "\u00e9", "\u2028", "\u2615", "\ufeff", "\uffff", "\U0001F600", "\U0010FFFF", "{", ":"]
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))


def random_value(rng, depth=0):
    kinds = ["null", "bool", "int", "float", "str"] + (["list", "dict"] if depth < 4 else [])
    k = rng.choice(kinds)
    if k == "null":
        return None
    if k == "bool":
        return rng.random() < 0.5
    if k == "int":
        return rng.choice([0, -1, 7, 2 ** 53 + 1, -(2 ** 70), rng.randint(-10 ** 30, 10 ** 30)])
    if k == "float":
        f = random_float(rng)
        return f
    if k == "str":
        return random_str(rng)
    if k == "list":
        return [random_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {random_str(rng): random_value(rng, depth + 1) for _ in range(rng.randint(0, 4))}


def corpus_entry(text):
    v = json.loads(text)
    try:
        cns = {"digest": subject_digest(v)}
    except TypeError:
        cns = {"error": "TypeError"}
    ledger = json.dumps(v, sort_keys=True, default=str)
    return {"text": text, "ledger": ledger,
            "compact": json.dumps(v, sort_keys=True, separators=(",", ":"), default=str),
            "ledger_sha256": hashlib.sha256(ledger.encode()).hexdigest(), "cns": cns}


def build_corpus(rng):
    texts = ["1E5", "1e-7", "-0", "-0.0", "0.000001", "0.0001", "0.00001", "1e22", "1e16",
             "1e15", "123456789012345678901234567890", "123456789012345678901234567890.5",
             "1e308", "1e309", "-1e309", "5e-324", "2.4e-324", "2.5e-324", "NaN", "Infinity",
             "-Infinity", "[NaN, 1]", "{\"a\": {\"b\": [1.0, -0.0, 0.0]}}", "\"\\u00e9\"",
             "\"\\ud83d\\ude00\"", "\"\\/\"", "\"\\b\\f\\n\\r\\t\"", "\"raw \u00e9 \U0001F600\"",
             "{\"\u00e9\": 1, \"e\": 2, \"E\": 3, \"\U0001F600\": 4, \"\uffff\": 5}",
             " [ 1 , 2 ] ", "true", "false", "null", "{}", "[]", "\"\"",
             "0.1", "0.30000000000000004", "100.0", "1.5e300", "4.35", "9007199254740993.0"]
    out = [corpus_entry(t) for t in texts]
    for _ in range(400):
        v = random_value(rng)
        text = json.dumps(v, ensure_ascii=rng.random() < 0.5)
        out.append(corpus_entry(text))
    return out


def main():
    rng = random.Random(20260930)
    with open(os.path.join(FIXTURES, "ledger_export_pre_receipts.json")) as fh:
        pre = json.load(fh)["rows"]
    post = build_post_receipts()
    with open(os.path.join(HERE, "base_post_receipts.json"), "w") as fh:
        json.dump({"format": "sentinel_os.ledger_export.v1", "columns": COLUMNS, "rows": post},
                  fh, indent=1, sort_keys=True, default=str)
        fh.write("\n")

    scripted("pre_receipts", pre)
    scripted("post_receipts", post)
    receipts_cases(post)
    random_cases("pre_receipts", pre, rng, 40)
    random_cases("post_receipts", post, rng, 60)

    bases = {"pre_receipts": "../ledger_export_pre_receipts.json",
             "post_receipts": "base_post_receipts.json"}
    with open(os.path.join(HERE, "manifest.json"), "w") as fh:
        json.dump({"generated_by": "tests/fixtures/differential/generate.py",
                   "tool": "sentinel_os/tools/verify_receipts.py", "bases": bases,
                   "python_no_verdict": SKIPPED, "cases": CASES},
                  fh, indent=1, sort_keys=True, default=str)
        fh.write("\n")
    with open(os.path.join(HERE, "corpus.json"), "w") as fh:
        json.dump({"entries": build_corpus(rng)}, fh, indent=1, sort_keys=True)
        fh.write("\n")
    tally = {}
    for c in CASES:
        tally[c["python"]["verdict"] or f"exit{c['python']['exit']}"] = \
            tally.get(c["python"]["verdict"] or f"exit{c['python']['exit']}", 0) + 1
    print(f"{len(CASES)} cases, python verdicts {sorted(tally.items())}, "
          f"{len(SKIPPED)} random mutations where python printed no verdict")


if __name__ == "__main__":
    main()
