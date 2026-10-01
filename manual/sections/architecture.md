## Architecture section: done, and I looked at the render

I replaced the pending block `mbc9j78cmdq.66` in prose node `603b928d-09c6` with the four parts you asked for. They went in as one batch: the widget create plus a prose replace. The doc is now at rev 15.

- `mbc9j78cmdq.305125`: the heading "## Architecture".
- `.305138`: the lead sentence. It says one request crosses six components in a fixed order, and the Tractor Transmission runs in a side lane and changes the configuration only when no request is in flight.
- `.305321`: the embed. It points at widget `e0d27dee-29d2` (published as pub 1, status "live", no diagnostics), with the caption "request path · 6 components in order, 1 side lane, ANC boundary marked".
- `.305322`: the reading sentence under the diagram.

Doc: https://claude.ai/code/artifact/e5a974be-0af6-49f3-b654-edd1e7d86f23

### What the diagram shows
- **Title:** "Inside the ANC box, every reply waits for its release time". The subtitle says only the Sentinel Hash-Chain exists today (in sentinel_os) and the other six are new designs.
- **Shape:** the path runs left to right as a staircase, because six explained boxes in one row cannot be read at the doc's 760 width.
  - Top row: request → Inlet Winnowing Filter → Elastic Bumpers.
  - The path then drops straight down into the ANC box, where it crosses the edge labelled "admission timestamp".
  - Inside the box: Traffic Cop and Green Wave → Minotaur String (drawn as a container around an inner "Execution" box) → Inter-Agent Trident → down to the Sentinel Hash-Chain.
- **Box text:** each box has its name plus two or three short lines taken from the doc's own lead sentences, such as "4,307 banned characters", "up to 3 corrections", "64 levels and 100,000 steps" and "all three checks".
- **Trident handoffs:** a dashed external box, "another repository or agent", sits above the Trident. A two-way arrow labelled "every handoff, both ways" connects them across the ANC edge.
- **ANC boundary:** a tinted box from the admission timestamp to the "response release" label on its bottom edge. A note inside it says every reply in the box, refusals included, waits for release.
- **Exits and outcomes:**
  - Inlet and Bumpers: arrows up to "refused before admission: RETRY or TERMINAL_BREACH, sent at once".
  - Traffic Cop: an amber arrow leaves through the ANC left edge, labelled "RETRY: shed, sent at once". Shedding using public information only is written in the Traffic Cop box.
  - After the release, the path splits into three colour-coded exits: TERMINAL_BREACH ("abort: no correction repairs it", red), RETRY ("caller may resubmit", amber) and PASS ("result returned", green). PASS is the one straight below the Sentinel.
- **Tractor Transmission:** a side lane at the bottom. Its box says "changes the gear (the configuration) only while the line is stopped", and the lane text says a shift waits for zero requests in flight. Two dashed arrows labelled "sets the gear" rise to the Inlet and to the ANC box, so the gear reaches the whole line.
- **Emphasis:** the Sentinel is the only highlighted box, because it is the only component that exists today.

### The render
I read the screenshot (pub 1, no render errors). No text is cut off, no words cross a border, no connector runs through a box or a label, and everything is readable at doc scale. I made no corrections because the first render was already clean. The PNG is at `/root/.claude/projects/-home-user/dc79eb2b-c581-5d0f-9c7a-4872a4d2458f/tool-results/mcp-Claude_Docs-blob-1790846586944-ab4p0r.png`.

### Two things for whoever edits the doc
1. **The brief's ANC box conflicts with the doc.** The Elastic Bumpers section (block `mbc9j78cmdq.95238`) says: "The bumper is not constant time, so ANC (Active Timing Cancellation) must wrap the whole request boundary." Your brief starts the ANC box at the Traffic Cop admission, which leaves bumper refusals unpadded. I drew it as briefed and said so plainly in the reading sentence. One of the two needs to change: either move the admission timestamp before the bumpers, or reword the Bumpers section.
2. **I placed the Sentinel inside the ANC box, which is my own call.** The brief and the doc do not say whether the verdict is recorded before or after the release. I put the recording before the release so that no reply leaves without a ledger record. The cost is that the ledger write's time falls inside the timed window. If the kernel should record after release instead, as the doc's rule that telemetry records after the release time might suggest, the box's right edge would move above the Sentinel.