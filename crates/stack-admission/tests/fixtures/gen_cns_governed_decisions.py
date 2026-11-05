"""Generates cns-governed-decisions.json from the real CNS SuperGate.

Run read-only against a CNS checkout, in isolated mode so no site or
PYTHONPATH module can be planted:

    python3 -I gen_cns_governed_decisions.py /home/user/CNS <cns commit> > cns-governed-decisions.json

The committed file was produced at CNS commit 4acd8f958a091900d43f553eba7fe83f7d33c4d6.
Every root below is what cns_composition.super_gate.SuperGate.decide
returned; nothing is computed here. Each gate judges the governed subject
itself: its verdict binds to the subject's identity and to
cns.gate.subject_digest(content), which is what the kernel recomputes.
The subject content is integer-only so it lies inside the Trident's
restricted digest domain (docs/cns-digest-contract.md). The nonce, proof
and times of a Decision are process-local and not recorded.
"""

import json
import sys

sys.path.insert(0, sys.argv[1])

from cns.gate import GateOutcome, GatePosition, GateResult, subject_digest  # noqa: E402
from cns_composition.super_gate import SuperGate  # noqa: E402

A, OM = GatePosition.ALPHA, GatePosition.OMEGA
PASS, RETRY, BREACH = GateOutcome.PASS, GateOutcome.RETRY, GateOutcome.TERMINAL_BREACH

SUBJECT = {
    "identity": "invoice-42",
    "content": {
        "doc": "invoice-42",
        "amount": 1200,
        "lines": [{"sku": "A1", "qty": 2}, {"sku": "B7", "qty": 1}],
        "approved": True,
        "note": None,
    },
}
OTHER_SUBJECT = {
    "identity": "invoice-43",
    "content": {"doc": "invoice-43", "amount": 99, "lines": [], "approved": False, "note": None},
}


class GovernedGate:
    """A gate that judges the governed subject: it binds its verdict to the
    subject's identity and to the CNS digest of the subject's content."""

    def __init__(self, name, position, outcome=PASS, bind=True):
        self.name, self.position, self._outcome, self._bind = name, position, outcome, bind

    def check(self, candidate):
        subject = candidate["identity"] if self._bind else ""
        digest = subject_digest(candidate["content"]) if self._bind else ""
        return GateResult(gate=self.name, position=self.position, outcome=self._outcome,
                          reason=f"{self.name} says {self._outcome.value}", subject=subject,
                          subject_digest=digest)


def case(name, seats, subject, required=None):
    gate = SuperGate(seats, required=required or tuple(f"{r}:{g.name}" for r, g in seats))
    decision = gate.decide({f"{r}:{g.name}": subject for r, g in seats})
    return {
        "name": name,
        "identity": subject["identity"],
        "subject": subject["content"],
        "subject_digest": subject_digest(subject["content"]),
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


door_judge = lambda **kw: [("Governance_Gateway", GovernedGate("door", A, **kw.get("door", {}))),  # noqa: E731
                           ("DIT", GovernedGate("judge", OM, **kw.get("judge", {})))]
cases = [
    case("all_pass", door_judge(), SUBJECT),
    case("other_subject_all_pass", door_judge(), OTHER_SUBJECT),
    case("three_seats_all_pass",
         door_judge() + [("HERALD", GovernedGate("confidence", OM))], SUBJECT),
    case("omega_retry", door_judge(judge={"outcome": RETRY}), SUBJECT),
    case("alpha_breach_omega_not_run", door_judge(door={"outcome": BREACH}), SUBJECT),
    case("unbound_pass", door_judge(door={"bind": False}), SUBJECT),
    case("missing_required_seat",
         [("Governance_Gateway", GovernedGate("door", A)), ("HERALD", GovernedGate("confidence", OM))],
         SUBJECT),
]

json.dump({
    "schema": "stack-admission-cns-governed-decisions/1",
    "comment": __doc__.strip().splitlines()[0] + " See the module docstring of gen_cns_governed_decisions.py.",
    "cns_commit": sys.argv[2] if len(sys.argv) > 2 else "",
    "cases": cases,
}, sys.stdout, indent=2, ensure_ascii=True)
sys.stdout.write("\n")
