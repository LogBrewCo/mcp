# LogBrew MCP

This repository owns the LogBrew MCP server and its protocol tests. The server
ships only as the hosted LogBrew service. Do not add downloadable binaries,
installers or binary license-notice bundles unless a self-hosted distribution
is requested. Keep changes within this repository's public responsibilities.

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

`scripts/check-all.sh` is the required gate. CI runs the same script. It
needs Rust 1.99.0 from `rust-toolchain.toml`, cargo-deny 0.20.2 and the native
Rust Tombi 1.7.2 CLI from their official releases, and it checks each tool
version before use.

Every lint, policy and Tombi diagnostic fails. Keep the bundled Tombi schema
graph in `tools/quality/schemastore`, its source bindings, LICENSE and NOTICE
intact. Recheck the graph and array-order exceptions before changing Tombi, the
schemas or a manifest. Do not refresh the bundled cache in place.

## Code review

- Reject credentials, customer data, private instructions, internal reports,
  and infrastructure details in source, examples, history, or release artifacts.
- Verify authorization, tenant isolation, resource bounds, redaction, and
  explicit partial or unavailable results for affected behavior.
- Treat source checks, hosted deployment,
  and customer-visible behavior as separate evidence. Do not claim release
  completion from a source test alone.

## Public history

Commits, pull-request titles and bodies, branch names, READMEs, and release
notes describe user-visible behavior only. Do not name hosting, network,
storage, or deployment internals, non-public repositories, local paths,
plans, agent sessions, costs, or real user data. Do not add AI attribution.

`scripts/public-guard.sh` enforces this. The required `Public guard` status
scans every new commit, commit message, changed path, branch name, and
pull-request title and body. Run `bash scripts/public-guard.sh install` once
per checkout to scan commit messages and pushes locally. Never use
`--no-verify`. If a finding is a false positive, change the rule in its own
pull request first; never split, encode, or reword text only to pass the
guard.
