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

incident-shaped (clone, then convert a per-incident CSV with `canary import`):
  wiz        github.com/wiz-sec-public/wiz-research-iocs   (per-incident CSVs, no license)
  ossf       github.com/ossf/malicious-packages            (OSV format, canonical)
  shai-hulud github.com/Cobenian/shai-hulud-detect         (MIT, compromised-packages.txt)

corpus-shaped (clone; loaded by `internal/corpus`, NOT converted to attack files):
  datadog    github.com/DataDog/malicious-software-packages-dataset  (Apache-2.0, manifest.json)
  pypi-mal   github.com/lxyeternal/pypi_malregistry            (PyPI, NO LICENSE)

destination: $CANARY_ATTACK_DIR, default ~/.canary/attacks
EOF
	exit 2
}

[ $# -eq 1 ] || usage

case "$1" in
wiz)       repo="https://github.com/wiz-sec-public/wiz-research-iocs.git" ;;
ossf)      repo="https://github.com/ossf/malicious-packages.git" ;;
shai-hulud) repo="https://github.com/Cobenian/shai-hulud-detect.git" ;;
datadog)   repo="https://github.com/DataDog/malicious-software-packages-dataset.git" ;;
pypi-mal)  repo="https://github.com/lxyeternal/pypi_malregistry.git" ;;
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

case "$1" in
wiz|ossf)
	cat <<EOF

Upstream lists are not attack files yet. Convert one — CSV parsing lives in Go
because 358 of the 446 rows in the keyv list quote their version lists, and
splitting those on commas in shell corrupts them silently:

  canary import -csv $target/reports/<report>.csv \\
    -id <id> -name '<label>' -started <RFC3339> -source <url> \\
    > $DEST/<id>.json

Artifacts (C2 domains, dropped filenames) are not in the CSV — add them by hand
from the report, and give every filename artifact a pathScope.
EOF
	;;
shai-hulud)
	cat <<EOF

shai-hulud-detect ships compromised-packages.txt (MIT, name:version list).
It is a source adapter input, not a vendor CSV — see TASK_TODO.
EOF
	;;
datadog)
	cat <<EOF

DataDog ships samples/<ecosystem>/manifest.json (Apache-2.0). It is a cumulative
corpus, not an incident: load it with `canary corpus $target` (internal/corpus),
do NOT convert it to an attack file — it has no single forensic window.
EOF
	;;
pypi-mal)
	cat <<EOF

pypi_malregistry is a PyPI corpus with NO upstream license: use it locally,
never commit or redistribute it. Same corpus shape as DataDog — load with
`canary corpus $target`, not `canary import`.
EOF
	;;
esac
