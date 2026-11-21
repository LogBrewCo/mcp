#!/usr/bin/env bash
# Run every required repository gate. CI runs this same script.
set -euo pipefail

cd "$(dirname "$0")/.."

require_version() {
  local actual line
  actual="$("$1" --version)"
  while IFS= read -r line; do
    if [[ "$line" == "$2" || "$line" == "$2 "* ]]; then
      return 0
    fi
  done <<<"$actual"
  printf 'Expected %s, found %s.\n' "$2" "$actual" >&2
  exit 1
}

bash scripts/check-tool-matrix.sh
bash scripts/test-check-tool-matrix.sh
bash scripts/check-suppressions.sh
bash scripts/test-check-suppressions.sh
bash scripts/check-dependabot.sh
bash scripts/test-check-dependabot.sh

require_version actionlint "1.7.12"
require_version shellcheck "version: 0.11.0"
require_version cargo-deny "cargo-deny 0.20.2"
require_version tombi "tombi 1.11.3"

actionlint
shell_scripts=()
while IFS= read -r script; do
  shell_scripts+=("$script")
done < <(git ls-files '*.sh')
shellcheck --external-sources --severity=info "${shell_scripts[@]}"

export TOMBI_CACHE_HOME=tools/quality/schemastore/cache
tombi lint --offline --quiet --error-on-warnings
tombi format --offline --check --quiet

cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo deny --locked check --deny warnings advisories bans licenses sources
cargo test --locked --all-targets -- --test-threads=2
