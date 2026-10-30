# Changelog

This file lists the changes in each version of the hosted LogBrew MCP server
at `https://mcp.logbrew.co/mcp`. Versions follow
[Semantic Versioning](https://semver.org/).

## 0.4.0 (2026-10-31)

### Added

- Analytics reads that compare each rate with the previous period, give the
  sample size and a test of each change, and link example sessions and users
  to their actions and traces: `analytics.overview.v4`,
  `analytics.properties.v3`, `analytics.funnel.v2`, `analytics.retention.v3`,
  `analytics.paths.v2` and `analytics.segments.compare.v3`.
- `actions.list.v1` accepts `session_id` to read one example session.
- The registry entry has the LogBrew icon.

### Changed

- `execute` describes which operations change data, which changes need a
  confirming call, and which calls are safe to repeat. `search` says that it
  never changes data. Every argument of both tools has a description.
- The operation reference is now part of the README.
- The server keeps one copy of the bearer token for each request.

## 0.3.0 (2026-10-29)

### Added

- `issues.investigate.v17` adds suspect commits from the deploy where an issue
  first appeared, and links each in-app frame to its source file and line.

## 0.2.0 (2026-10-29)

### Added

- Write operations under the separately granted `write` scope: resolve,
  reopen, archive, prioritize and assign issues, create projects and project
  keys, revoke keys, send a test event, and load or remove sample data.
  Archiving, key revocation and sample-data removal need a second, confirming
  call.
- A read that lists the projects a connection can read.
- `issues.investigate.v16` lists related issues from the same crash site or
  trace.
- Human-readable titles for `search` and `execute`.
- A description of how issue priority is derived.

### Changed

- Any MCP client that completes LogBrew authorization can connect.

## 0.1.0 (2026-10-26)

The first version of the hosted server.

### Added

- The `search` tool finds read operations and returns the contract of one
  operation.
- The `execute` tool runs an operation that `search` found and returns
  structured data, or an error with a stable code and a next action.
- OAuth authorization. Every request needs the `read` scope.
- Protected resource metadata at `/.well-known/oauth-protected-resource`.
- MCP protocol versions `2026-07-28`, `2025-11-25` and `2025-06-18`, served
  without sessions.
- A per-client limit on requests that have not proven authority. Over the
  limit, the server answers HTTP 429 with `Retry-After`.
