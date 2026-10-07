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

Use the native Rust Tombi 1.7.2 CLI for TOML checks. Verify `tombi --version`
before running it. Acquire the exact version from its
[official release](https://github.com/tombi-toml/tombi/releases/tag/v1.7.2).
From this repository root, run:

```sh
TOMBI_CACHE_HOME=tools/quality/schemastore/cache tombi lint --offline --quiet --error-on-warnings --diagnostics-format json --diagnostics-file /dev/stdout
TOMBI_CACHE_HOME=tools/quality/schemastore/cache tombi format --offline --check --quiet
```

Every lint diagnostic fails. Keep the bundled schema graph, its source bindings,
LICENSE and NOTICE intact. Recheck the graph and array-order exceptions before
changing Tombi, the schemas or a manifest. Do not refresh the bundled cache in place.

## Code review

- Reject credentials, customer data, private instructions, internal reports,
  and infrastructure details in source, examples, history, or release artifacts.
- Verify authorization, tenant isolation, resource bounds, redaction, and
  explicit partial or unavailable results for affected behavior.
- Treat source checks, registry publication, installation, hosted deployment,
  and customer-visible behavior as separate evidence. Do not claim release
  completion from a source test alone.
