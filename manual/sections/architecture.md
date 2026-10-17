# Architecture

A request crosses six components in a fixed order: Inlet Winnowing Filter, Elastic Bumpers, Traffic Cop and Green Wave Routing, Minotaur String, Inter-Agent Trident, and the Sentinel Hash-Chain. Tractor Transmission runs in a side lane. It changes the configuration only while no request is in flight, so a shift never happens partway through a request.

The ANC (Active Timing Cancellation) boundary wraps the request path, so that replies are released on the schedule the ANC strategy sets rather than when the work finishes. Where the boundary starts is an open question. Elastic Bumpers are not constant time, so a boundary that begins at admission to the Traffic Cop leaves the bumper's timing outside it.

Each boundary either passes the request on or refuses it with an outcome word: PASS, RETRY, or TERMINAL_BREACH. A refusal before admission is sent at once. Traffic Cop sheds load using only information the caller can see, and a shed request is answered with RETRY. After the release, a verdict becomes one of three exits: TERMINAL_BREACH aborts, because no correction repairs the request; RETRY lets the caller resubmit; PASS returns the result.

Inter-Agent Trident verifies the envelope on every handoff to and from another agent or repository.

The Sentinel Hash-Chain is the only component that exists today. It lives in sentinel_os, and the Rust verifier in this repository checks its chain offline. Whether the verdict is recorded before or after the reply is released is also open. Recording before release means no reply leaves without a ledger entry, at the cost of putting the ledger write inside the timed window.
