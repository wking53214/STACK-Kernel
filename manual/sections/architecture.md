# Architecture

A request crosses six components in a fixed order: Inlet Winnowing Filter, Elastic Bumpers, Traffic Cop and Green Wave Routing, Minotaur String, Inter-Agent Trident, and the Sentinel Hash-Chain. Tractor Transmission runs in a side lane. It changes the configuration only while no request is in flight, so a shift never happens partway through a request.

The ANC (Active Timing Cancellation) boundary wraps the whole request path, from the Inlet through the Sentinel. Replies are released on the schedule the ANC strategy sets, not when the work finishes. The Inlet and Elastic Bumpers are inside the boundary because the bumper is not constant time: a boundary that began at the Traffic Cop would leave the bumper's timing visible. This is a design decision. No crate composes the components into one pipeline yet, so no code enforces it today.

Each boundary either passes the request on or refuses it with an outcome word: PASS, RETRY, or TERMINAL_BREACH. Refusals from the Inlet and Elastic Bumpers are padded like any other reply, which costs a slot for each one. A request shed for lack of capacity is the exception: it is answered at once with RETRY, because that reply reveals only load. The Traffic Cop sheds using only information the caller can see. After the release, a verdict becomes one of three exits: TERMINAL_BREACH aborts, because no correction repairs the request; RETRY lets the caller resubmit; PASS returns the result.

Inter-Agent Trident verifies the envelope on every handoff to and from another agent or repository.

The Sentinel Hash-Chain is the only component that exists today. It lives in sentinel_os, and the Rust verifier in this repository checks its chain offline. The design records the verdict before the reply is released, so no reply leaves without a ledger entry. The cost is that the ledger write falls inside the timed window, so the ANC release time has to leave room for it.
