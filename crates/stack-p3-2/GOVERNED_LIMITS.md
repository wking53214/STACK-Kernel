# Governed limits (kernel side)

`governed_limits.rs` lets the P3.2 kernel read per-agent limits that an external governance
service may tighten (wking53214/experimental, `scripts/adjudication_server.py`). The service
can lower a limit on its own. Only a named human can raise one, and the kernel treats its own
configured default as a hard ceiling either way.

| Piece | What it does |
|---|---|
| `boundary_id(agent, kind)` | `stack.agent.<agent>.<deadline_ns\|tokens_capacity\|memory_capacity_bytes>`; ids outside `[A-Za-z0-9._-]{1,64}` become `h-` + first 24 hex of SHA-256, matching the Python side |
| `HttpSource` | `GET /boundaries/<id>`, plain HTTP, optional bearer token, timeouts, 64 KB response cap |
| `FileSource` | JSON snapshot `{"<boundary id>": limit}` for hosts with no network path |
| `GovernedLimits::effective(agent, kind, default)` | cached read (TTL), returns `min(governed, default)` |
| `HardPreemptionKernel::begin_transaction_governed` | starts a transaction with the governed deadline |

Failure behaviour (each tested): service down, slow, 401/404/500, malformed JSON, or a value
that is zero, negative, fractional-bad, a string or null leaves the last good value in force, or
the default if there is none. A governed value above the default is ignored and counted.
`stats()` exposes `source_errors`, `invalid_values`, `above_ceiling`.

Limits: HTTP has no TLS, so run it on loopback or a trusted network with a read-only
(source) token. A read blocks up to the source timeout on a cache miss; call `effective` from a
refresher thread if that matters. Only the Rust crate is covered; the C++ headers do not read
governed limits yet. Memory and token limits are readable through `LimitKind` but nothing in
this crate enforces them yet; only the deadline is wired in.

Contract check against the live Python service:
`GOVERNED_E2E_PORT=<port> GOVERNED_E2E_TOKEN=<token> cargo test -p stack-p3-2 -- --ignored e2e`
