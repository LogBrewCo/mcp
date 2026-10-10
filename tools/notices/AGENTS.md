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

The supplement manifest is limited to 512 KiB and 1024 notice references. Each
reference must pass the existing archive, revision, URL and text checks.

The output covers named license and attribution files from the entire lockfile,
including inactive and development dependencies, plus explicitly bound source-file
prefixes. A supplement may provide a `source_prefix` object with `archive_path`,
`bytes`, and `sha256` for the complete source file. Its notice text must be an
exact nonempty prefix of that file in the verified published archive. The archived
`path_in_vcs` must map the archive path to the recorded upstream path. Metadata
and named notice files cannot be prefix selections. Each selected source file is
limited to 1 MiB; selected files and named notices share a 16 MiB per-archive
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

When upstream text contains trailing spaces or other bytes that a plain text
asset cannot preserve through source checks, store a single JSON string in a
sibling file. Set `file_encoding` to an object with `format: "json_string"`,
`bytes`, and `sha256` for that encoded file. The notice's existing `sha256`
continues to bind the decoded upstream text. Both encoded input and decoded
text are limited to 1 MiB. The generator verifies both bindings, preserves the
decoded bytes exactly, and records the encoding binding in the inventory.
It rejects other formats, malformed strings, trailing documents and empty text.
Source-prefix checks apply to decoded text. Do not normalize upstream whitespace
or change the source checks to accommodate it.

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

For GCC 15.2.0-16ubuntu1 startup inputs, include the complete `COPYING3` and
`COPYING.RUNTIME` texts from the `gcc-runtime` component in
`licenses/gnu-startup-source-notices.json`. The asset preserves the source
comment and both license documents with full-file bindings. Compare the exact
texts with the required and final linked-target inventories, then verify their
readable copies in the archive. Check shared GCC runtime inputs separately;
their package and source versions can differ from the startup files. These
texts do not establish compilation eligibility or distribution permissions.

For the captured `libgcc-s1` 16-20260322-1ubuntu1 input, include the
`gcc-shared-runtime` component from
`licenses/gnu-shared-runtime-source-notices.json`. Its complete copyright text
comes from the matching `gcc-16-base` package. Preserve every byte, including
the final newline, and compare its binding with the package archive. The base
copyright covers the wider GCC collection. It contains the runtime exception
and refers to the separate GPL text; include the complete `COPYING3` text from
the startup asset as well. Verify exact inventory and readable-archive copies.
The runtime file binding records this captured package, not a current compiler
release or complete corresponding source.

GNU builds can compile header implementations into linked objects. Audit those
contributions separately from startup objects and shared libraries. When a build
includes the glibc `bsearch` header implementation, include its complete source
file and the complete LGPL text in the linked-target inventory. The components in
`licenses/gnu-header-source-notices.json` preserve both files for the recorded
glibc source version. The header text must match its full-file source binding,
including its license comment and implementation. Verify the actual header
version before using this asset for another build. Compare every applicable
source-notice component with the
final inventory before packaging, then verify the exact texts in both the JSON
inventory and its readable archive copy. A source asset outside the archive
does not supply the recipient's notice. This check does not establish license
permissions or complete linked-component coverage.
Verify the remaining corresponding-source and relinking materials before release.

Version 2 of `licenses/gnu-header-rebuild-recipe.json` records the two
header-dependent AWS-LC C inputs, their reference objects, and the Clang 23.1.3 build arguments
for the recorded GNU target. Replace each named root in an argument with its
local absolute directory. The `source` root contains the verified extracted
AWS-LC registry archive. The `headers` root contains the complete matching
`bits/stdlib-bsearch.h`. The `sysroot` and `clang_headers` roots contain the exact
system and compiler-resource headers. `objects` and `dependencies` are output
directories.
Append `per_source_arguments` after `arguments`, replacing `source_path` and
`object` with that source record's values. Pass the resulting argument array
directly to the verified compiler without shell expansion.

Verify the bound `compiler_inputs` manifest before materializing inputs. It
records 134 distinct source/include files by root, relative path, size and
checksum. Preserve the `usr/include/` layout beneath `sysroot`; compiler-resource
paths are relative to `clang_headers`. Verify every file against its recorded
binding. The recipe disables default include paths with `-nostdinc` and supplies
the explicit include directories. Missing headers must fail the rebuild; do not
add unchecked host include paths to make it succeed. The manifest describes
unmodified inputs. Record a modified complete header's binding separately.

Each `clang_headers` record also identifies its complete upstream source file
at the compiler's recorded commit. Verify that file against the existing size
and checksum, and preserve its source comments. The manifest's
`compiler.source_license` binds the complete `clang/LICENSE.TXT` from that commit
to `licenses/clang-23.1.3.txt`. Include that exact text with recipient materials.
These source bindings do not establish complete distribution permissions.

The bound `system_header_sources` asset records source bindings and selected
derivations for 78 system headers. Its `source_archives` identify the glibc upstream and
Ubuntu patch archives by URL, size and checksum. For each header, verify the
source file against its recorded binding, apply its listed patches in order,
and verify the complete result against `input_binding`. Preserve whitespace.
Unpatched source files must already match that input binding. Verify the bound
patch series and include this asset and both source archives with recipient
materials.

The asset also binds complete Linux v7.0 files to its recorded source commit.
Three kernel headers match those files without changes. The `linux/limits.h`
derivation changes only the two listed UAPI guards. Verify that the complete
source needs none of the install script's other transformations. The ARM64
`asm/errno.h` derivation produces the listed include wrapper. Verify the
mandatory-header selection, architecture file inventory and generator rule.
These are selected-rule reconstructions; a complete upstream build is unrun.
Include every bound Linux source file and both complete Linux license texts with
recipient materials. Preserve their full bytes and source comments.
For a JSON-string license asset, verify `file_encoding`, decode the string, and
verify the complete decoded text against its source binding before inclusion.
The glibc `gnu/stubs.h` selector records its complete generator and ABI selection
sources. Reconstruct its preamble, includes and conditional wrappers from those
rules, then verify every output byte against `input_binding`. This selected-rule
reconstruction does not execute a complete glibc build. The generated
`gnu/stubs-lp64.h` function list remains explicitly unqualified. Matching source and
derived bytes do not prove the original Ubuntu package derivation, complete
corresponding source, or distribution permissions.

Verify the archive, every compiled source and include input, the complete header,
and the compiler version and source commit before using the recipe. With the
unmodified header, both outputs must match their reference-object bindings.
Modified-header outputs can differ. This recipe supplies object rebuild inputs;
the complete library source, application objects, final link command, recipient
execution, and license permissions remain separate release requirements.

## GNU final-link inputs

Export a checksum-bound plain tar archive produced by LLD 23.1.3 `--reproduce`:

```sh
cargo run --locked --offline --bin logbrew-mcp-relink -- /absolute/path/to/relink-plan.json /absolute/path/to/capture.tar /absolute/path/to/relink.tar.gz
```

The strict plan uses `format_version: 1` or `2`, this package's `package_version` and
`rust_release`, `build_identity` (`development` or the package version), a
40-character lowercase hexadecimal `source_revision`, and a supported GNU
`target` (`aarch64-unknown-linux-gnu` or `x86_64-unknown-linux-gnu`).
`input_archive` and `reference_binary` each contain `bytes` and `sha256`.
The reference binary binding is operator-supplied metadata; the exporter does
not read or execute that binary. `linker` contains `version: "23.1.3"` and
`source_commit: "0d261d1ca552c95a8f007e061c787ac7132fbcbc"`. The archived
`version.txt` must match that exact LLD identity. `archive_root` names the
capture's single top-level directory. `path_maps` contains at most 32 objects
with relative `from` and `to` prefixes. Source prefixes must be distinct and
nonoverlapping; every map must occur in an input or search-directory argument.
`private_path_markers` contains 1 to 16 nonempty ASCII strings of at most
256 bytes each. Unknown and duplicate fields fail.

Version 2 reads a gzip-compressed tar wrapper directly. It requires
`capture_wrapper` with a compressed-file `binding` (`bytes` and `sha256`) and
the relative `member` path of the enclosed plain LLD archive. `input_archive`
continues to bind that enclosed archive. Version 1 rejects a wrapper binding.
The command verifies both sets of bytes and keeps the existing export unchanged.
The wrapper is limited to 64 MiB compressed, 96 MiB expanded, 64 regular members,
64 MiB per member and 64 KiB of path text. Every path must be safe and unique.
Links, special entries, corrupt gzip framing, additional gzip streams and
missing, unaligned or nonzero tar end records fail. It reads the wrapper in
memory and never writes the enclosed plain archive to disk. Wrapper companions
are omitted from the export and are not recipient materials.

Mappings replace complete path components in archive paths and response input
and search-directory arguments. Other input bytes remain unchanged. Standard
GNU library paths can remain in place for captured linker scripts. The response
must contain exactly one `--chroot .`, target-matching `-m` and runtime loader,
one `-o`, and at least one captured input. GNU quotes and escapes are parsed and
written as quoted arguments, one per line. Unterminated quotes, incomplete
escapes, nested response files and unknown options fail. Supported flags are
`-EL`, `--eh-frame-hdr`, `-pie`, `--fix-cortex-a53-843419`, `--as-needed`,
`-Bstatic`, `-Bdynamic`, `--gc-sections`, `--strip-all`; operands are `-L`,
`-l`, `-z` (`relro`, `now`, `noexecstack`), `--hash-style gnu`, `-O 1`,
`--Map`, `--dependency-file`, and `--why-extract` (also `--why-extract=PATH`).
Output paths must be relative and must not overwrite inputs or the manifest.

The exporter reads bounded regular inputs without extracting or executing them.
Limits are 16 KiB per plan, 64 MiB per archive and combined input payload,
1024 regular files, 32 MiB per file, 2 MiB of input path text, and 128 KiB per
original or rewritten response. Links, special files, duplicate paths, unsafe
paths, destination collisions and nonzero trailing tar data fail. Every output
path, file body and manifest is checked for the selected private markers. This
check covers those exact strings; it does not prove absence of all private data.

The deterministic output contains `relink/` files and a size/checksum manifest.
Publication uses the shared atomic writer and rejects input aliases. Failure
before replacement preserves the previous output. Run the verified linker with
`@response.txt` from the extracted `relink` directory, then independently verify
the output binary binding. Unchanged executable reproduction, complete
corresponding source, source modification and relinking, and license permissions
remain external requirements. Exporting inputs does not complete a release.

`licenses/gnu-header-relink-recipe.json` records the library replacement and final
link for the same GNU development input set. Verify `link_inputs_archive` before
extracting it into an operator-managed directory. Resolve `library.path` beneath
`link_working_directory`. Verify the library binding, its regular-member count,
and the bound `object_rebuild_recipe` before making changes.

First rebuild both objects with the unmodified complete header and verify their
reference bindings. Then make a permitted header change and rebuild the objects.
Replace `{library}` in the archiver arguments with the local library path and
`{objects}` with the rebuilt-object directory. Pass the argument array directly
to the verified archiver. Every other regular archive member must retain its
name, size and checksum; only `replacement_members` can change. Preserve the
original manifest as a reference and record modified header, object, archive and
output bindings separately. All other captured link inputs must remain unchanged.

Run the verified linker with its argument array from `link_working_directory`.
For an unmodified-header rebuild, the binary must match `unmodified_output`.
Modified outputs need new bindings and functional checks. Verify that the
required changed object sections reached the executable; presence in an archive
alone does not prove that they were linked. The recipe covers the recorded input
set. Complete matching source and system-header materials, recipient execution,
license permissions and release verification remain required.

## Selected recipient materials

Bundle selected source archives, headers, recipes, licenses and final-link inputs
with an operator-verified plan:

```sh
cargo run --locked --offline --bin logbrew-mcp-materials -- /absolute/path/to/materials-plan.json /absolute/path/to/materials.tar.gz
```

The strict plan uses `format_version: 1`, this package's `package_version` and
`rust_release`, `build_identity` (`development` or the package version), a
40-character lowercase hexadecimal `source_revision`, and GNU `target`
(`aarch64-unknown-linux-gnu` or `x86_64-unknown-linux-gnu`). `reference_binary`
contains `bytes` and `sha256`. This is operator-supplied metadata; the command
does not read that binary or establish build provenance.

Each `files` entry contains an absolute `input_path`, an archive-relative `path`,
a `kind` (`source_archive`, `header`, `recipe`, `license` or `link_inputs`), and
a `binding` containing `bytes` and `sha256`. Verify those bindings independently.
Unknown and duplicate fields fail. Destinations use ASCII letters, digits,
slashes, underscores, hyphens and periods. Unsafe paths, duplicates,
ancestor/descendant collisions and the reserved `MANIFEST.json` path fail.
`private_path_markers` contains 1 to 16 nonempty ASCII strings of at most
256 bytes each. The command rejects those exact strings in destination paths,
raw file bodies and its generated manifest. Compressed nested archives are
opaque; this check cannot establish their privacy or contents.

Limits are 128 KiB per plan, 256 files, 512 bytes per destination path, 64 KiB
of destination path text, 32 MiB per file, 64 MiB of combined input payload and
64 MiB of compressed output. Files are read and appended individually. Reuse
verified archives directly instead of copying or expanding them for packaging.
There is no directory walk, extraction, binary execution or network access.

The deterministic archive contains the selected bytes beneath `materials/`
and a `MANIFEST.json` with their destinations, kinds, sizes and checksums.
Input paths and selected marker values stay outside the manifest. The manifest
records the plan checksum, fixed build metadata and explicit external
requirements. Selection does not prove complete corresponding source,
component coverage, recipient modification/relink execution, license permissions
or release eligibility. Verify these separately before distributing a complete
recipient bundle.

Inputs must be bounded regular files in operator-managed directories. Final
component links and special files fail. Publication uses the shared atomic
writer and rejects plan/file aliases, including hard links. Failure before
replacement preserves the previous output. Remove finished disposable outputs
after preserving the checks and the inputs needed to reproduce them.

## Binary archives

Use an operator-verified packaging plan. Its format_version is 1, 2, 3 or 4 and its
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

Version 1 contains exactly the binary, LICENSE, licenses/rmcp-3.5.1.txt, both
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

Version 4 includes the version 3 files and requires a `required_linked_notices`
size/checksum binding for `licenses/required-linked-notices.json`. This inventory
uses the linked inventory's strict schema and limits, with scope
`required_linked_source_notices`. Its target and binary hash must match the plan.
List the components and source notices independently verified as applicable to
that build. Packaging requires each component's exact name, version and source
URL and each notice's path, checksum and verbatim text in the linked inventory.
Additional linked notices are allowed. The archive preserves the required
inventory, and the manifest records its binding and checked counts. Versions
1 through 3 reject this binding. This check detects omission of declared
requirements; selecting those requirements, complete coverage, compilation
eligibility and license permissions remain external gates. The output path must
not replace the required inventory.

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

If a copied source tree retains old or fixed timestamps, ensure Cargo rebuilds
the affected MCP test executable before using a shared target directory. Refresh
the timestamps of explicitly selected copied inputs, or invalidate only this
package's artifacts with `cargo clean --package logbrew-mcp` against the test
run's target directory. Verify copied file contents against the source revision
and retain compiler output that confirms the rebuild. A cached pass does not
prove changed source. Reuse dependency caches and leave canonical source
timestamps intact. The [Cargo clean reference](https://doc.rust-lang.org/cargo/commands/cargo-clean.html)
describes package selection and the `--dry-run --verbose` preview.

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
