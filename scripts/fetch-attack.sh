#!/usr/bin/env bash
# Fetch upstream IoC lists into an untracked local directory.
#
# Vendor lists are not vendored into this repo: upstream licensing is often
# unstated (the Wiz IoC repo publishes no LICENSE). Pull them locally instead.
set -euo pipefail

DEST="${CANARY_ATTACK_DIR:-$HOME/.canary/attacks}"

usage() {
	cat >&2 <<'EOF'
usage: fetch-attack.sh <source>

sources:
  wiz     github.com/wiz-sec-public/wiz-research-iocs  (per-incident CSVs)
  ossf    github.com/ossf/malicious-packages           (OSV format, canonical)

destination: $CANARY_ATTACK_DIR, default ~/.canary/attacks
EOF
	exit 2
}

[ $# -eq 1 ] || usage

case "$1" in
wiz) repo="https://github.com/wiz-sec-public/wiz-research-iocs.git" ;;
ossf) repo="https://github.com/ossf/malicious-packages.git" ;;
*) usage ;;
esac

mkdir -p "$DEST"
target="$DEST/$1"

if [ -d "$target/.git" ]; then
	git -C "$target" pull --ff-only
else
	git clone --depth 1 "$repo" "$target"
fi

echo "fetched $1 -> $target"
cat <<EOF

Upstream lists are not attack files yet. Convert one — CSV parsing lives in Go
because 358 of the 446 rows in the keyv list quote their version lists, and
splitting those on commas in shell corrupts them silently:

  canary attacks import -csv $target/reports/<report>.csv \\
    -id <id> -name '<label>' -started <RFC3339> -source <url> \\
    > $DEST/<id>.json

Artifacts (C2 domains, dropped filenames) are not in the CSV — add them by hand
from the report, and give every filename artifact a pathScope.
EOF
