#!/usr/bin/env bash
# Run every required repository gate. CI runs this same script.
set -euo pipefail

cd "$(dirname "$0")/.."

require_version() {
  local actual
  actual="$("$1" --version)"
  if [[ "$actual" != "$2" && "$actual" != "$2 "* ]]; then
    printf 'Expected %s, found %s.\n' "$2" "$actual" >&2
    exit 1
  fi
}

require_version cargo-deny "cargo-deny 0.20.2"
require_version tombi "tombi 1.7.2"

export TOMBI_CACHE_HOME=tools/quality/schemastore/cache
tombi lint --offline --quiet --error-on-warnings
tombi format --offline --check --quiet

cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo deny --locked check --deny warnings licenses bans sources
cargo test --locked --all-targets -- --test-threads=2
