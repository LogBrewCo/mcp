# LogBrew MCP

Source repository for LogBrew's Model Context Protocol server.

Development is in progress. This repository does not yet provide a released
server, install command, or verified hosted connection endpoint.

The [draft operation reference](docs/operations.md) describes the current read
catalog and its evidence, permission and recovery boundaries. It is source
documentation, not a released capability list.

## Development

Use Rust 1.99.0. The HTTP transport is under development. Its tests use
local HTTPS servers and synthetic credentials; they do not prove hosted access.

```sh
cargo test --locked --all-targets -- --test-threads=2
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

Use cargo-deny 0.20.2 for the dependency policy gate:

```sh
cargo run --manifest-path tools/notices/Cargo.toml --locked --offline --bin logbrew-mcp-policy-check -- /absolute/path/to/cargo-deny
```

Fetch the locked dependency graph and cargo-deny's standard-library replacement
data before an offline run. Use the pinned tool's `cargo deny fetch std-replacement`
command for that data. The Rust gate verifies the tool version, process status,
structured logs and a complete final summary. Data-loading errors fail even if
cargo-deny returns zero. Run it from this repository root to check the server.
The [tool guide](tools/notices/AGENTS.md) records its host and output limits.
The policy covers
normal, build, and test dependencies across the resolved graph. It checks
license requirements and registry sources, rejects wildcard versions, and
constrains reviewed features to exact dependency versions. Five exact duplicate
version exceptions preserve incompatible upstream APIs; no dependency subtree
is excluded. Unused license and source allowances fail the check. Binary
distributions must include LICENSE, licenses/rmcp-3.5.0.txt, and all other
applicable dependency notices. The SDK license is preserved from its
[published source commit](https://github.com/modelcontextprotocol/rust-sdk/blob/0cde3c5cf3e6aff0cc852ce6045f107e95991f48/LICENSE).
Complete notice bundling remains required before release.

The toolchain file pins rustfmt and Clippy with Rust 1.99.0. The server uses
the official MCP Rust SDK, rmcp 3.5.0, with Axum and Tokio. Cargo.lock records
the resolved dependency graph. All diagnostics must be resolved
before release. Authorization, operation discovery, execution isolation and
client integration remain required before a usable server can be released.

The draft operation validator accepts object-rooted JSON, rejects duplicate
keys at every depth, and preserves exact numbers. Limits are 64 nested
containers, 256 characters per number, and decimal exponents from -1024 to
1024. Input, output, and schema byte limits apply before parsing. Schemas use
JSON Schema 2020-12 by default with format assertions and no external loading.
These source-level checks do not establish hosted operation availability.

Startup file loading is under development for Linux and macOS. It requires
operator-managed directories and absolute regular-file paths, checks byte and
permission bounds, and rejects final-component symlinks. Files are opened
without waiting for a FIFO writer and their identity is checked before reading.
The draft configuration reader accepts a private file up to 16 KiB. Version
`"2"` requires `client_allowlist_file`. Version `"1"` also accepts that field;
without it, no client is authorized. Each supplied field must appear exactly once
with a nonempty string value. It rejects unknown fields, case aliases, duplicate
decoded keys, invalid UTF-8, trailing documents, and inline secret fields. It
preserves secret-file references without opening them.

The separate service loader reads referenced material and constructs the
authenticated handler without opening a listener or contacting upstream services.
It requires a numeric IP and nonzero port, verifies the catalog SHA-256, parses
the matching TLS certificate/key pair, and applies service endpoint and credential
validation. File limits are 8 MiB for the catalog, 256 KiB for certificates,
64 KiB for the private key, and 8 KiB per machine secret. Key and secret files
must have no group or other permissions. Secret bytes are used exactly as stored,
without newline trimming. Temporary loaded key/secret buffers are cleared after
assembly; the service retains the credentials it needs. These tests do not prove
certificate renewal, hosted deployment, or client compatibility.

The draft command can be run from source with an operator-provided configuration:

```sh
cargo run --locked -- /absolute/path/to/config.json
```

It validates startup material before binding the configured address. Outbound
connections use system TLS trust, with no inherited proxy or custom dial hooks.
SIGINT and SIGTERM request graceful shutdown. Startup and serving failures exit
nonzero without printing paths, credentials, or upstream responses. Source builds
identify themselves as `development`. This command is not a released package
or verified hosted service.

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
drain exits nonzero. These limits do not establish a performance target or prove
hosted capacity.

The Rust migration is in progress. Local HTTPS tests cover pending execution
cancellation, current-request authorization, revocation, and response boundaries.
The standalone process and HTTPS regression tests share the same serving code.
Tests verify that graceful shutdown closes the listener before active execution
finishes, preserves the complete response, and releases the connection. Cancelling
the serving future closes active requests and stops their upstream work. Request
capacity recovers after cancellation without starting excess introspection work.
Remaining authorization, tenant isolation, deployment, and supported-client
checks must pass before release. Existing Go results do not establish Rust
behavior.

Current-version request tests require protocol version and client capabilities
on each request. Client identity is optional. Missing or mismatched routing
headers receive HTTP 400 with a `HeaderMismatch` error. Unsupported versions
receive the supported-version list; unknown methods receive HTTP 404 with a
JSON-RPC method error. Client response messages, batches, and invalid request IDs
are rejected before execution.

Content negotiation parses complete media types, accepts case variants and
repeated Accept fields, and requires both JSON and event-stream support with
positive quality values. Current-version GET and DELETE requests receive HTTP
405. Incoming legacy session and event IDs are ignored without creating sessions.
An actual TLS HTTP/2 test covers configured authority, authorization, header
validation, complete results, and cancellation. These are local protocol checks,
not a supported-client compatibility claim.

Authorization tests reject expired credentials, mismatched issuer or audience,
missing required scopes, invalid identity references, and incomplete or malformed
introspection responses before execution. Oversized introspection bodies and
headers and unexpected media types also fail closed. Synthetic HTTPS fixtures
verify separate machine credentials and OAuth component encoding at both
upstream endpoints. These checks do not prove the hosted issuer or backend policy.

The request router requires the configured resource host, including its port,
on every request. A supplied Origin must be the single configured HTTPS origin;
empty, null, duplicate, foreign, or different-scheme origins are rejected even
for metadata reads. Forwarded headers do not change either check. The SDK's
loopback-host heuristic is replaced by this configured-host check so a loopback
proxy hop can preserve the public host. Browser cross-site protection remains
enabled. This local test does not prove a deployed proxy configuration.

The draft catalog loader accepts format version 1 and requires an expected
SHA-256 digest from trusted release configuration. It rejects files above 8 MiB,
duplicate keys, unknown metadata fields, unsupported formats, and invalid
operation contracts. Loading a catalog does not grant access to its operations.

The draft tools return a `data`/`error` envelope with catalog provenance.
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
