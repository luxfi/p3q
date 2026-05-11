#!/usr/bin/env bash
# P3Q strict-PQ lint gate.
#
# Refuses any *.rs or Cargo.toml in the workspace that **imports** a
# forbidden hash family or proof-system primitive. The list is the
# canonical strict-PQ exclusion set from CONTRIBUTING.md.
#
# Documentation prose is allowed to mention forbidden primitives by
# name — the lint inspects only actual code-level references:
#
#   * Cargo.toml dependency keys (e.g. `bn254 = "..."`,
#     `[dependencies.bn254]`, `[*-dependencies.bn254]`)
#   * Rust `use` / `extern crate` / `mod` statements
#
# Exits non-zero on the first match.

set -uo pipefail

cd "$(dirname "$0")/.."

patterns=(
  "bn254"
  "kzg"
  "groth16"
  "plonk_kzg"
  "halo"
  "blake3"
  "poseidon"
  "monolith"
  "rescue"
)

# Collect candidate files. macOS bash 3.2 has no `mapfile`, so we
# materialise the list in a tempfile and iterate via line-read.
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

if git rev-parse --git-dir >/dev/null 2>&1; then
  git ls-files '*.rs' 'Cargo.toml' '**/Cargo.toml' > "$tmp" 2>/dev/null || true
else
  find . -type f \( -name '*.rs' -o -name 'Cargo.toml' \) \
       -not -path './target/*' \
       -not -path './scripts/*' \
       -not -name 'README.md' \
       -not -name 'CONTRIBUTING.md' > "$tmp"
fi

found_any=0

for pattern in "${patterns[@]}"; do
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    case "$f" in
      *.rs)
        # Rust imports: `use X`, `extern crate X`, `mod X` where X is or
        # ends with the forbidden token. Attribute prefixes (e.g.
        # `#[allow(unused)]`) on the same line are allowed.
        if grep -nEi "\b(use|extern[[:space:]]+crate|mod)[[:space:]]+([a-z0-9_]+::)*${pattern}([:;{[:space:]]|$)" "$f"; then
          echo "FORBIDDEN(rust import) ${pattern} in $f" >&2
          found_any=1
        fi
        ;;
      Cargo.toml|*/Cargo.toml)
        # Cargo dep keys: `<name> = ...` or `[<...>dependencies.<name>]`.
        if grep -nEi "^[[:space:]]*${pattern}[[:space:]]*=" "$f"; then
          echo "FORBIDDEN(cargo dep key) ${pattern} in $f" >&2
          found_any=1
        fi
        if grep -nEi "^[[:space:]]*\[[a-z0-9_.-]*dependencies\.[a-z0-9_-]*${pattern}[a-z0-9_-]*\][[:space:]]*$" "$f"; then
          echo "FORBIDDEN(cargo dep table) ${pattern} in $f" >&2
          found_any=1
        fi
        ;;
    esac
  done < "$tmp"
done

if [ "$found_any" -ne 0 ]; then
  echo
  echo "P3Q strict-PQ profile forbids: BN254, KZG, Groth16, PLONK/KZG," >&2
  echo "Halo, BLAKE3, Poseidon, Monolith, Rescue. See CONTRIBUTING.md." >&2
  exit 1
fi

echo "lint_forbidden.sh: clean."
