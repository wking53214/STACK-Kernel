"""Generates cns-decision-roots.json from the real CNS SuperGate.

Run read-only against a CNS checkout, in isolated mode so no site or
PYTHONPATH module can be planted:

    python3 -I gen_cns_decision_roots.py /home/user/CNS <cns commit> > cns-decision-roots.json

The committed file was produced at CNS commit 4acd8f958a091900d43f553eba7fe83f7d33c4d6.
Every root below is what cns_composition.super_gate.SuperGate.decide
returned; nothing is computed here. The gates are the FakeGate of CNS's
own test suite: each binds its verdict to subject_digest({"candidate":
candidate}). The nonce, proof and times of a Decision are process-local
and not recorded (the Rust verifier cannot check them and says so).
"""

import json
import sys

sys.path.insert(0, sys.argv[1])

from cns.gate import GateOutcome, GatePosition, GateResult, subject_digest  # noqa: E402
from cns_composition.super_gate import Judged, SuperGate  # noqa: E402

A, OM = GatePosition.ALPHA, GatePosition.OMEGA
PASS, RETRY, BREACH = GateOutcome.PASS, GateOutcome.RETRY, GateOutcome.TERMINAL_BREACH


class FakeGate:
    def __init__(self, name, position, outcome=PASS, bind=True):
        self.name, self.position, self._outcome, self._bind = name, position, outcome, bind

    def check(self, candidate):
        subject = self.name if self._bind else ""
        digest = subject_digest({"candidate": candidate}) if self._bind else ""
        return GateResult(gate=self.name, position=self.position, outcome=self._outcome,
                          reason=f"{self.name} says {self._outcome.value}", subject=subject,
                          subject_digest=digest)


def case(name, seats, candidates, required=None, **kwargs):
    gate = SuperGate(seats, required=required or tuple(f"{r}:{g.name}" for r, g in seats), **kwargs)
    decision = gate.decide(candidates)
    return {
        "name": name,
        "seats": list(decision.seats),
        "verdicts": [
            {"gate": r.gate, "position": r.position.value, "outcome": r.outcome.value,
             "subject": r.subject, "digest": r.subject_digest}
            for r in decision.run.results
        ],
        "root": decision.root,
        "allowed": decision.allowed,
        "outcome": decision.outcome.value,
    }


reads = lambda c: Judged(identity="doc-1", digest=subject_digest({"doc": c}))  # noqa: E731
cases = [
    case("two_seats_all_pass",
         [("Governance_Gateway", FakeGate("door", A)), ("DIT", FakeGate("judge", OM))],
         {"Governance_Gateway:door": "request", "DIT:judge": "text"}),
    case("three_seats_with_same_subject",
         [("Governance_Gateway", FakeGate("door", A)), ("DIT", FakeGate("judge", OM))],
         {"Governance_Gateway:door": "shared", "DIT:judge": "shared"},
         required=("Governance_Gateway:door", "DIT:judge", "CNS:same_subject"),
         same_subject={"Governance_Gateway:door": reads, "DIT:judge": reads}),
    case("omega_retry",
         [("Governance_Gateway", FakeGate("door", A)), ("DIT", FakeGate("judge", OM, RETRY))],
         {"Governance_Gateway:door": "request", "DIT:judge": "text"}),
    case("alpha_breach_omega_not_run",
         [("Governance_Gateway", FakeGate("door", A, BREACH)), ("DIT", FakeGate("judge", OM))],
         {"Governance_Gateway:door": "request", "DIT:judge": "text"}),
    case("unbound_pass",
         [("Governance_Gateway", FakeGate("door", A, bind=False)), ("DIT", FakeGate("judge", OM))],
         {"Governance_Gateway:door": "request", "DIT:judge": "text"}),
    case("seat_order_differs_from_run_order",
         [("DIT", FakeGate("judge", OM)), ("HERALD", FakeGate("source", A)), ("HERALD", FakeGate("confidence", OM))],
         {"DIT:judge": "text", "HERALD:source": "src", "HERALD:confidence": "conf"}),
    case("unicode_candidate",
         [("Governance_Gateway", FakeGate("door", A)), ("DIT", FakeGate("judge", OM))],
         {"Governance_Gateway:door": "café ✓ \U0001f642", "DIT:judge": "日本語"}),
]

json.dump({
    "schema": "stack-receipt-cns-decision-roots/1",
    "comment": __doc__.strip().splitlines()[0] + " See the module docstring of gen_cns_decision_roots.py.",
    "cns_commit": sys.argv[2] if len(sys.argv) > 2 else "",
    "cases": cases,
}, sys.stdout, indent=2, ensure_ascii=True)
sys.stdout.write("\n")
