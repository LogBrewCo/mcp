# Source notices

This Rust package owns locked dependency and Rust standard-library source notices,
their inclusion in MCP binary archives, and the checked dependency policy gate.
Preserve upstream notice text verbatim. Keep package versions, registry archive
checksums, source commits, source URLs, and file checksums exact.

Run these checks from this directory with Rust 1.99.0 and cargo-deny 0.20.2:

```sh
cargo test --locked --offline --all-targets -- --test-threads=2
cargo clippy --locked --offline --all-targets -- -D warnings
cargo fmt --all -- --check
cargo run --locked --offline --bin logbrew-mcp-policy-check -- /absolute/path/to/cargo-deny
```

Fetch the locked dependencies before offline checks. Fetch standard-library
replacement data with the pinned tool's `cargo deny fetch std-replacement`
command before offline policy checks. The Rust policy command runs cargo-deny
0.20.2 with locked, offline, warning-denied license, ban and source checks.
It rejects a failed process, warning or error logs, malformed records, and a
missing, duplicate or incomplete final summary. Every diagnostic fails except
two codes documented by cargo-deny 0.20.2: `accepted` at help severity reports
satisfied license requirements, and `skipped` at note severity reports an
explicit version exception in `bans.skip`. Tree skips and other codes fail.
The command uses debug output so every accepted diagnostic is present and
requires exact per-check summary counts. These narrow exceptions preserve
successful policy decisions; they do not allow a warning or error. Reviewed
2026-10-04; review again by 2026-11-04 or before changing cargo-deny or policy.
Compensating tests cover unknown codes, severity changes, missing or repeated
records, mismatched totals and actual locked graphs. Upstream definitions are
in [license checks](https://github.com/EmbarkStudios/cargo-deny/blob/0.20.2/src/licenses.rs)
and [ban diagnostics](https://github.com/EmbarkStudios/cargo-deny/blob/0.20.2/src/bans/diags.rs).
This policy gate does not prove all release checks.

Run it from the package whose dependency graph you are checking. Pass a trusted
regular executable in an operator-managed directory. The command rejects a
relative path or final-component symlink and verifies the exact tool version.
Version checking has a five-second execution deadline and 4 KiB per output pipe.
Policy checking has a 120-second execution deadline and 8 MiB per output pipe.
Each JSON record is limited to 1 MiB, with at most 16,384 records. On completion,
failure or timeout, cleanup requests termination of the owned process group
before reaping the leader. Group termination remains best effort. This is
not a sandbox for an untrusted executable
or proof of a kernel-level termination deadline. Linux and macOS are the
supported hosts.

Generate the input metadata
from the MCP repository root:

```sh
cargo metadata --locked --offline --all-features --format-version 1 > /absolute/path/to/metadata.json
```

Run the generator from this directory. Pass the Cargo registry cache directory
that contains the locked `.crate` archives:

```sh
cargo run --locked --offline -- /absolute/path/to/metadata.json ../../Cargo.lock /absolute/path/to/registry/cache ../../licenses/sources.json /absolute/path/to/notices.json
```

The output covers named license and attribution files from the entire lockfile,
including inactive and development dependencies, plus explicitly bound source-file
prefixes. A supplement may provide a `source_prefix` object with `archive_path`,
`bytes`, and `sha256` for the complete source file. Its notice text must be an
exact nonempty prefix of that file in the verified published archive. The archived
`path_in_vcs` must map the archive path to the recorded upstream path. Metadata
and named notice files cannot be prefix selections. Each selected source file is
limited to 1 MiB; selected files and named notices share an 8 MiB per-archive
budget. The output records the full-file binding, prefix length and
`checked_published_archive_source_prefix` provenance. Shared text appears once,
with a separate reference for each source file. Whole upstream supplements retain
their existing provenance.

For vendored or generated files that cannot use the parent repository's raw-file
URL, set `source_prefix.source_url_kind` to `"published_archive"` and use the exact
`https://static.crates.io/crates/NAME/NAME-VERSION.crate` URL. The package revision,
archive checksum, complete-file binding, repository path and exact prefix remain
required. `source_commit` identifies the published package's checkout; it does not
claim the revision of a vendored submodule. The JSON inventory records the URL
kind, and readable archives label the notice as a verified archive-member prefix.
An omitted URL kind keeps the existing repository-file URL check.

Permission policy, final binary
and toolchain notices, release provenance, and tool timing require separate proof.
Never claim a completed release from successful inventory generation.

## Rust standard-library notices

Use the trusted source binding for the exact release and target. Verify the
official distribution manifest and component archive before accepting new hashes.
The binding must cover COPYRIGHT, LICENSE-APACHE, LICENSE-MIT, and the shipped
COPYRIGHT-library.html. The installed library notice must match the archived file.

```sh
cargo run --locked --offline --bin logbrew-mcp-toolchain-notices -- /absolute/path/to/rust-sources.json /absolute/path/to/distribution.toml /absolute/path/to/rustc.tar.gz /absolute/path/to/COPYRIGHT-library.html /absolute/path/to/toolchain-notices.json
```

This command preserves the four texts verbatim. It verifies the bound distribution
checksum, release, target, commit, date, URL, archive checksum, file sizes, and text
checksums. It reads all gzip members and footers without extracting files. Limits
are 128 MiB compressed, 512 MiB expanded, 4096 entries, 1 MiB of path text, 2 MiB
per notice, 4 MiB of notice text, and 8 MiB of output. The full distribution
manifest may be 2 MiB; the source binding may be 8 KiB.

Both commands require operator-managed directories on Linux or macOS. Inputs must
be bounded regular files; final-component links and special files are rejected.
Outputs use exclusive staging and atomic replacement. A failure before replacement
preserves the previous output. An error after replacement reports unconfirmed
directory durability. These checks do not prove hardware power-loss recovery.

Standard-library source notices are a superset, not a final binary license decision.
Target linkage, permission policy, distribution inclusion, provenance, platform
execution, and required timing checks remain separate gates.

Compare the linked standard-library crates with Rust's `library/Cargo.lock` at
the pinned source commit. The compiler's COPYRIGHT-library.html may omit crates
from that graph. For Rust 1.99.0, `licenses/rust-1.99.0-stdlib-supplement.json`
preserves additional registry notices and compiler-builtins attribution with
exact upstream source bindings. Include its applicable `components` in the
linked-target inventory before packaging. Keep all notice text verbatim and
verify the registry archive pins and the Rust and LLVM source commits. The
supplement does not select licenses or prove complete linked-component coverage.

## Binary archives

Use an operator-verified packaging plan. Its format_version is 1, 2 or 3 and its
package_version and rust_release match this package's pins. Record target,
build_identity, source_revision, and cargo_lock_sha256. An uncommitted revision
requires the development identity. The binary, project_license, sdk_license,
dependency_notices, and toolchain_notices records each contain only bytes and
sha256. Every input must match its recorded size and lowercase SHA-256.
The plan rejects unknown and duplicate fields.

From this directory:

```sh
cargo run --locked --offline --bin logbrew-mcp-package -- /absolute/path/to/plan.json /absolute/path/to/logbrew-mcp /absolute/path/to/mcp /absolute/path/to/package.tar.gz
```

Version 1 contains exactly the binary, LICENSE, licenses/rmcp-3.5.0.txt, both
notice inventories, and MANIFEST.json beneath the package version and target.
Version 2 requires a linked_target_notices size/checksum binding and adds
licenses/linked-target-notices.json. Version 1 rejects that binding. The linked
inventory is limited to 4 MiB and uses format_version 1 with scope
linked_target_source_notices, target, binary_sha256, and components. Each component
has name, version, source_url, and notices. Each notice has upstream_path, sha256,
and text. The source URL uses HTTPS without credentials, query or fragment.
Component identities and notice paths must be unique; text hashes must match.
Limits are 64 components, 16 notices per component, 256 notices total, and 512 KiB
per text. The inventory target and binary checksum must match the packaging plan.
MANIFEST.json records the bound inventory and keeps coverage, compilation
eligibility, permission policy and release evidence as external requirements.
Version 3 requires the same inputs as version 2 and adds six readable files:
licenses/DEPENDENCIES.txt, licenses/LINKED-TARGET.txt, and the four original Rust
notices under licenses/rust/. COPYRIGHT-library.html stays HTML. The dependency
file lists each package and notice path, including supplemental upstream notices,
then includes each unique text once under its SHA-256. Linked notices retain their
component, source URL and upstream path. Upstream text is copied verbatim; headings
and separators are outside that text. The manifest binds every readable file to
its source inventory and records the derived file's size and checksum. Version 3
rejects missing, unreferenced or inconsistent dependency texts and incomplete Rust
notice coverage. It allows at most 512 dependency packages, 4096 notice references,
1 MiB per dependency text and 2 MiB per Rust text. The dependency text output is
limited to 32 MiB and linked text output to 8 MiB. These copies do not select
licenses or satisfy the external permission and release gates.
It uses fixed order, ownership and timestamps. The binary mode is 0755; other
entries are 0644. Input limits are 64 MiB for the binary, 512 KiB per license,
16 MiB for dependency notices, 8 MiB for toolchain notices, and 1 MiB for Cargo.lock.
The plan is limited to 16 KiB. Compressed output is limited to 64 MiB and uses
the shared atomic publisher. No directory walk, extraction, binary execution or
network access occurs.
The output path must not replace the plan, binary, lockfile or bound notice inputs.

The command checks 64-bit little-endian Mach-O or ELF header identity and
architecture. MANIFEST.json also records binary_load_requirements parsed from
the bound binary. macOS records include one deployment command, linked libraries,
and rpaths. Linux records include the interpreter, linked libraries, rpaths,
runpaths, and GNU symbol version requirements. Missing, conflicting, truncated,
or oversized load metadata is rejected. Mach-O load commands are limited to
4096 before parsing. ELF program headers are limited to 4096.

Mach-O commands must exactly fill the declared command region and have valid
eight-byte sizes. Each command is parsed within its own slice. Library and rpath
strings, build-tool records and segment sections must fit their own command.
All requirement strings share limits of 256 strings, 4096 bytes per string,
and 8 KiB of JSON text.
The complete requirement report is limited to 16 KiB.

These declarations do not prove complete executable validity, GNU ABI support,
or OS and runtime compatibility. The manifest marks runtime compatibility and
final linked-target notices as external_required, and static components as
not_evaluated. Declared build and revision metadata require
independent build provenance. Notice scopes, Rust release and target, and the
lockfile hash must agree. Bundling a source superset does not select licenses or
close the final linked-target notice audit.

The binary must not contain the checked workstation path markers. Remap source
paths before building. Cargo's trim-paths profile option remains unstable; use
stable rustc path remapping and the C/C++ compiler's file-prefix mapping.
Run this command from the MCP repository root, replacing the example directories:

```sh
RUSTFLAGS="--remap-path-prefix=/absolute/path/to/mcp=logbrew-mcp --remap-path-prefix=/absolute/path/to/cargo-home=cargo-home --remap-path-prefix=/absolute/path/to/build=build" \
CFLAGS="-ffile-prefix-map=/absolute/path/to/mcp=logbrew-mcp -ffile-prefix-map=/absolute/path/to/cargo-home=cargo-home -ffile-prefix-map=/absolute/path/to/build=build" \
CXXFLAGS="-ffile-prefix-map=/absolute/path/to/mcp=logbrew-mcp -ffile-prefix-map=/absolute/path/to/cargo-home=cargo-home -ffile-prefix-map=/absolute/path/to/build=build" \
cargo build --locked --offline --release --bin logbrew-mcp
```

The selected marker check is not a complete private-content or security scan.
Release authorization, protected checks, final licenses, supported platforms,
installation, hosted operation and real-client proof remain separate gates.

Run the server's existing process suite against an extracted development archive
by setting `LOGBREW_MCP_PACKAGE_EXECUTABLE` to its absolute executable path:

```sh
LOGBREW_MCP_PACKAGE_EXECUTABLE=/absolute/path/to/extracted/bin/logbrew-mcp cargo test --locked --offline --test process -- --test-threads=2
```

Run this from the server repository root. The harness clears the server's
environment and keeps the source tests' assertions. An empty or unusable supplied
path fails without selecting Cargo's binary. With the variable unset, ordinary
source tests use Cargo's binary. These tests prove only the exercised local
development executable behavior; they do not prove hosted or real-client access.

On Linux, an operator-verified GNU runtime fixture can supply its loader and
one absolute library directory. Keep the executable byte-identical to the
extracted archive:

```sh
LOGBREW_MCP_PACKAGE_EXECUTABLE=/absolute/path/to/extracted/bin/logbrew-mcp \
LOGBREW_MCP_PACKAGE_LOADER=/absolute/path/to/runtime/ld-linux-aarch64.so.1 \
LOGBREW_MCP_PACKAGE_LIBRARY_PATH=/absolute/path/to/runtime/libraries \
cargo test --locked --offline --test process -- --test-threads=2
```

Both loader options must be present. Relative paths, empty values, library search
lists and loader options on other hosts fail before launch. The harness clears
the child environment, disables the loader cache and keeps the existing process
assertions. A loader failure never falls back to Cargo's executable. The loader
and libraries are trusted test inputs; this option does not isolate the process
from host files or prove which libraries it loads. Verify the loaded library
closure independently before claiming runtime compatibility. One runtime fixture
does not establish support for an entire operating-system version.
