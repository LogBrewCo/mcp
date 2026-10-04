# LogBrew MCP

This repository owns the LogBrew MCP server, its protocol tests, and its release
packaging. Keep changes within this repository's public responsibilities.

## Development

- Read the README and inspect Git status before changing files. Preserve
  unrelated work.
- Use supported, versioned LogBrew APIs. Do not import private backend code or
  depend on another checkout's filesystem.
- Check current official MCP specifications, SDK releases, client compatibility,
  and advisories before changing protocol behavior or dependencies.
- Keep tools, transports, authentication, errors, and supported versions
  explicit. Do not claim untested protocol or client support.
- Use pinned tools and reproducible builds. Add focused tests for changed
  behavior and document the actual check commands when introducing tooling.
- Keep connection URLs and package identities independent of source directory
  layout so a repository move does not require client reconfiguration.

## Code review

- Reject credentials, customer data, private instructions, internal reports,
  and infrastructure details in source, examples, history, or release artifacts.
- Verify authorization, tenant isolation, resource bounds, redaction, and
  explicit partial or unavailable results for affected behavior.
- Treat source checks, registry publication, installation, hosted deployment,
  and customer-visible behavior as separate evidence. Do not claim release
  completion from a source test alone.
