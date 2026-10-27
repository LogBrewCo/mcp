# LogBrew MCP

The hosted LogBrew MCP server lets an AI agent read telemetry from your
LogBrew projects. You do not install it. Add its URL to your MCP client:

```text
https://mcp.logbrew.co/mcp
```

- **Transport:** Streamable HTTP. The server accepts MCP protocol versions
  `2026-07-28`, `2025-11-25` and `2025-06-18`.
- **Authorization:** OAuth. Your client opens the LogBrew authorization page,
  you sign in, and you select the projects that the agent can read. The `read`
  scope lets the agent read. Operations that change data need the separate
  `write` scope, which you can decline when you approve the connection.
- **Read-only:** The agent cannot change issues, projects or account settings.
  A read of a project that you did not approve returns `permission_denied`.
- **Connection lifetime:** An access token is valid for 1 hour, and the client
  refreshes it while you use the connection. A connection ends after 30 days
  without use, or 90 days after you approved it. Revoke a connection in the
  LogBrew dashboard under Settings > MCP connections, or with
  `logbrew mcp revoke`.

## What an agent can read

The server has 2 tools, both annotated read-only:

| Tool | What it does |
| --- | --- |
| `search` | Finds read operations and returns the contract of one operation: its input and output schemas, permission, cost, safety and stability. |
| `execute` | Runs one operation that `search` found and returns structured data, or an error with a stable code and a next action. |

The operations read issues (investigation, lists, activity, owners and
ownership rules), logs, traces, spans, metrics, product actions, releases,
signal volume and product analytics. The [operation reference](docs/operations.md)
lists every operation in the shipped catalog and its limits.

## Supported clients

Any MCP client that completes LogBrew authorization can connect. The client can
publish a client ID metadata document or register dynamically.

[Connect an AI agent with MCP](https://docs.logbrew.co/guides/mcp) shows the
setup for many clients. For example, in Claude Code:

```sh
claude mcp add --transport http logbrew https://mcp.logbrew.co/mcp
claude mcp login logbrew
```

## Development

Use Rust 1.99.1, cargo-deny 0.20.2 and Tombi 1.7.2. Run every required gate
from the repository root:

```sh
scripts/check-all.sh
```

CI runs the same script. Tests use local HTTPS servers and synthetic
credentials.

`server.json` describes the hosted server for the MCP Registry. Check it with
`mcp-publisher validate` after you change it.

The dependency policy in `deny.toml` covers normal, build and test dependencies
across the resolved graph. It checks license requirements and registry sources,
rejects wildcard versions, and constrains reviewed features to exact dependency
versions. Five exact duplicate version exceptions preserve incompatible upstream
APIs; no dependency subtree is excluded. Unused license and source allowances
fail the check, and every warning fails.

The toolchain file pins rustfmt and Clippy with Rust 1.99.1. The server uses
the official MCP Rust SDK, rmcp 3.5.1, with Axum and Tokio. Cargo.lock records
the resolved dependency graph.

The operation validator accepts object-rooted JSON, rejects duplicate
keys at every depth, and preserves exact numbers. Limits are 64 nested
containers, 256 characters per number, and decimal exponents from -1024 to
1024. Input, output, and schema byte limits apply before parsing. Schemas use
JSON Schema 2020-12 by default with format assertions and no external loading.

Startup file loading supports Linux and macOS. It requires
operator-managed directories and absolute regular-file paths, checks byte and
permission bounds, and rejects final-component symlinks. Files are opened
without waiting for a FIFO writer and their identity is checked before reading.
The configuration reader accepts a private file up to 16 KiB with
version `"5"` only. Every field is required and must appear exactly once with a
nonempty string value: `listen`, `resource`, `issuer`,
`introspection_endpoint`, `execution_endpoint`, `service_client_id`,
`service_secret_file`, `catalog_file`, `catalog_sha256`, `certificate_file` and
`private_key_file`. The `admission` object is also required (see below). It
rejects unknown fields, case aliases, duplicate decoded keys, invalid UTF-8,
trailing documents, and inline secret fields. It preserves secret-file
references without opening them.

Two optional fields send request telemetry to a LogBrew project. They must
appear together: `telemetry_endpoint`, the HTTPS ingest URL, and
`telemetry_key_file`, a private file that holds the project's ingest key with
no trailing newline. Each finished request, search, and execution becomes one
span with its duration and a fixed outcome such as `completed`,
`unauthorized`, or `unavailable`. An execution also names its operation, but
only when the catalog contains it. An outcome that this server or the API
caused (`configuration`, `invalid_output`, `unavailable`, or `deadline`) also
opens an issue, such as `mcp execute logs.read.v1 unavailable`. Telemetry never
contains tool arguments, results, tokens, client identity, or error text. At
most 1,024 records wait for delivery, and the server sends at most one request
per second. When the queue is full or a request fails, the server drops those
records and reports how many in its next request. Telemetry never delays or
rejects an MCP request.

`admission` limits requests that have not proven authority, per client:

```json
"admission": {"burst": 16, "per_minute": 600, "tracked_clients": 10000,
  "rejected_token_seconds": 30, "trusted_proxy": "127.0.0.1"}
```

Each MCP request reserves one unit of its client's budget before it takes a
request slot or starts introspection; a request whose token verifies gets the
unit back. A client may start `burst` (1 to 64) unverified requests at once,
refilled at `per_minute` (1 to 60000). Beyond that the server answers HTTP 429
with `Retry-After` in whole seconds and the body
`too many unauthenticated requests`, without introspection. Up to
`tracked_clients` (1 to 100000) clients get their own budget; idle clients are
evicted, and the rest share one overflow budget, so memory stays bounded. IPv6
clients are grouped by /64. The client is the TCP peer, or the single
`X-Real-IP` address when the peer is the optional `trusted_proxy`. A token that
introspection rejected (inactive, invalid or missing scope) is
refused for `rejected_token_seconds` (0 to 300, 0 disables) without asking
again; up to 4096 token digests are kept, never tokens. Unavailable
introspection is never remembered.

One service login, `service_client_id` with the secret in
`service_secret_file`, authenticates both introspection and execution. The
issuer and API must hold the same pair. `issuer` must equal the authorization
server's issuer identifier byte for byte, and `resource` must equal the audience
the issuer binds into tokens. Startup rejects an issuer that ends with `/`,
because it would deny every request. Introspection alone decides which clients
can connect. The server accepts any client ID that the authorization server
confirms, if it has 1 to 2048 printable ASCII characters. Every request
needs the delegated `read` scope. An operation whose permission is `write`
also needs the separately granted `write` scope. Without it, `execute`
answers HTTP 403 before contacting the API, with an `insufficient_scope`
challenge that asks for `read write`. Scopes are not configurable. The server
publishes RFC 9728 protected resource metadata at
`/.well-known/oauth-protected-resource` followed by the resource path. The
document names the issuer as the only authorization server and lists the
`read` and `write` scopes. The 401 challenge asks for `read` only, and every
401 and 403 challenge links to the document.

The separate service loader reads referenced material and constructs the
authenticated handler without opening a listener or contacting upstream services.
It requires a numeric IP and nonzero port, verifies the catalog SHA-256, parses
the matching TLS certificate/key pair, and applies service endpoint and credential
validation. File limits are 8 MiB for the catalog, 256 KiB for certificates,
64 KiB for the private key, and 8 KiB per machine secret. Key and secret files
must have no group or other permissions. Secret bytes are used exactly as stored,
without newline trimming. Temporary loaded key/secret buffers are cleared after
assembly; the service retains the credentials it needs.

The server can run from source with an operator-provided configuration:

```sh
cargo run --locked -- /absolute/path/to/config.json
```

It validates startup material before binding the configured address. Outbound
connections use system TLS trust, with no inherited proxy or custom dial hooks.
SIGINT and SIGTERM request graceful shutdown. Startup and serving failures exit
nonzero without printing paths, credentials, or upstream responses. Source builds
identify themselves as `development`. Use `cargo run --locked -- --version` to
check the package version without loading configuration.

Check the configuration and its referenced files before starting or replacing
a process:

```sh
cargo run --locked -- --check-config /absolute/path/to/config.json
```

The check uses the same loader as startup, then exits without binding a listener
or contacting either upstream service. It can run while the server is listening
on the configured address. Exit status 0 means local validation passed; status 1
means it failed. The executable prints no configuration or credential values.
This check does not prove upstream availability, authorization, certificate
renewal or client connectivity. Startup checks the files again when serving.

Native process tests cover offline startup, both shutdown signals, listener
release, mismatched certificate/key rejection, and stalled connections. The
process admits at most 64 connections, including TLS negotiation, and closes
excess connections without queueing them. TLS negotiation and HTTP/1 header
reading each have a five-second deadline. Authenticated requests have a
ten-second deadline; graceful shutdown waits up to twelve seconds. An incomplete
drain exits nonzero.

Local HTTPS tests cover pending execution
cancellation, current-request authorization, revocation, and response boundaries.
The standalone process and HTTPS regression tests share the same serving code.
Tests verify that graceful shutdown closes the listener before active execution
finishes, preserves the complete response, and releases the connection. Cancelling
the serving future closes active requests and stops their upstream work. Request
capacity recovers after cancellation without starting excess introspection work.

Current-version request tests require protocol version and client capabilities
on each request. Client identity is optional. Missing or mismatched routing
headers receive HTTP 400 with a `HeaderMismatch` error. Unsupported versions
receive the supported-version list; unknown methods receive HTTP 404 with a
JSON-RPC method error. Client response messages, batches, and invalid request IDs
are rejected before execution.
Handler validation errors use HTTP 200 with a JSON-RPC error response. Missing
required request metadata remains an HTTP 400 error.

The server accepts MCP `2026-07-28`, `2025-11-25`, and `2025-06-18`. A client
on `2025-11-25` or `2025-06-18` starts with `initialize` and then sends the
negotiated version in the `MCP-Protocol-Version` header. The server answers
these clients without sessions: it returns no `Mcp-Session-Id`, and every
request carries its own bearer token and gets the same authorization as a
`2026-07-28` request. Versions before `2025-06-18` are not supported, because
they have no OAuth resource indicator and no structured tool results.

Content negotiation parses complete media types, accepts case variants and
repeated Accept fields, and requires both JSON and event-stream support with
positive quality values. Current-version GET and DELETE requests receive HTTP
405. Incoming legacy session and event IDs are ignored without creating sessions.
An actual TLS HTTP/2 test covers configured authority, authorization, header
validation, complete results, and cancellation.

Introspected `iat` and `nbf` times may lead the local clock by up to 60
seconds; a later time is rejected. Authorization tests reject expired credentials, mismatched issuer or audience,
missing required scopes, invalid identity references, and incomplete or malformed
introspection responses before execution. Oversized introspection bodies and
headers and unexpected media types also fail closed. Synthetic HTTPS fixtures
verify one service login and OAuth component encoding at both upstream
endpoints.

The request router requires the configured resource host, including its port,
on every request. A supplied Origin must be the single configured HTTPS origin;
empty, null, duplicate, foreign, or different-scheme origins are rejected even
for metadata reads. Forwarded headers do not change either check. The SDK's
loopback-host heuristic is replaced by this configured-host check so a loopback
proxy hop can preserve the public host. Browser cross-site protection remains
enabled.

`catalog/operations.json` is the operation catalog the hosted server loads. The
LogBrew API generates it from the request and response types of its public
read endpoints; this repository ships the generated file unchanged.
`catalog/operations.json.sha256` pins its SHA-256 digest in `sha256sum` format.
Deployments set `catalog_sha256` to that digest, and a test fails if the file,
the pin, and the operation reference in `docs/operations.md` disagree. To
update the catalog, replace both files in one change and update the reference.

The catalog loader accepts format version 1 and requires an expected
SHA-256 digest from trusted release configuration. It rejects files above 8 MiB,
duplicate keys, unknown metadata fields, unsupported formats, invalid operation
contracts, and any permission other than `read` or `write`. A `read` operation
must be `read_only`. A `write` operation must declare `safety: write`, a title,
and hints that are not read-only. `search` is always read-only. `execute` is
read-only unless the catalog has a write operation; then it declares
`readOnlyHint: false`, and `destructiveHint: true` if any operation may delete
data. Loading a catalog does not grant access to its operations.

The tools return a `data`/`error` envelope with catalog provenance.
Operation input is limited to 4 KiB and output data to 2 MiB. Envelope metadata
has a separate bounded allowance so it does not consume the operation's budget.
Local HTTPS tests verify complete maximum-size results in both structured JSON
and text content, and rejection of output one byte over its limit.
`provenance.definition_sha256` identifies the sorted serialized operation
definitions used for discovery or execution. It is not the raw catalog-file
digest, a deployment receipt, or proof that returned telemetry is current.
Provenance is null when a request fails before catalog handling or a result
cannot be encoded within its limit. Raw artifact integrity remains a separate
startup check against the configured SHA-256.

Both tools advertise the same result schema. It distinguishes successful data
from errors, requires valid catalog provenance for success, and constrains error
codes, matching recovery actions, and retry delays. Local tests validate that
schema and reject inconsistent envelopes.

Errors include `code`,
`next_action`, and `retry_after_ms`. Invalid input points to the input contract;
invalid service output is a separate error and does not return the rejected
data. An unknown retry delay is `null`, distinct from zero. The server does not
retry an operation automatically. An unavailable result asks callers to check
operation status before repeating a potentially state-changing request.
