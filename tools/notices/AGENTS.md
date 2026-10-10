# Source notices and packaging

This Rust package owns locked dependency and Rust standard-library notices,
binary archives, selected recipient materials, relinking inputs, and the
dependency policy gate. Follow the repository-root instructions and preserve
unrelated work.

Preserve upstream notices verbatim and every exact version, source revision,
archive URL, file size and checksum. Keep private inputs, research, credentials
and workstation details outside public files and artifacts.

Use [README.md](README.md) for the workflow affected by the task:

- [Source notices](README.md#source-notices): dependency policy, notice generation,
  source prefixes and encoded upstream text.
- [Rust standard-library notices](README.md#rust-standard-library-notices):
  toolchain, GCC, glibc and system-header inputs, compiler bindings and object
  rebuild recipes.
- [GNU final-link inputs](README.md#gnu-final-link-inputs): capture validation,
  path mapping, object replacement and relink verification.
- [Selected recipient materials](README.md#selected-recipient-materials):
  bound source, header, license and recipe bundles.
- [Binary archives](README.md#binary-archives): package formats, notices, load
  requirements, path remapping and extracted-executable tests.

Keep each workflow's schemas, bounds, publication behavior and external
requirements intact. An inventory, package or matching reconstructed file does
not prove complete source, permissions, protected release, runtime compatibility,
hosted access or actual-client support.

For Rust or dependency-policy changes, run these checks from this directory
with Rust 1.99.0 and cargo-deny 0.20.2:

```sh
cargo test --locked --offline --all-targets -- --test-threads=2
cargo clippy --locked --offline --all-targets -- -D warnings
cargo fmt --all -- --check
cargo run --locked --offline --bin logbrew-mcp-policy-check -- /absolute/path/to/cargo-deny
```

Fetch the locked graph and the pinned tool's standard-library replacement data
before offline checks. Use the policy gate from the package whose graph is being
checked. Every diagnostic fails except its documented, tested informational
codes; preserve their review dates and scope in the reference.

Choose verification for the changed behavior. For documentation-only changes,
verify links, exact preserved procedures and the applicable source checks.
Do not rerun unaffected runtime suites solely because this guide moved. Retain
the checked evidence, commit a coherent change, and remove finished disposable
outputs while preserving the inputs needed to reproduce them.
