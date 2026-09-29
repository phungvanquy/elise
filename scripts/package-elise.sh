#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo 'Usage: package-elise.sh <binary> <amd64|arm64> <output-dir>' >&2
    exit 1
fi

binary=$1
arch=$2
output_dir=$3
case "$arch" in amd64|arm64) ;; *) echo 'Unsupported Elise architecture' >&2; exit 1 ;; esac
[[ -x "$binary" ]] || { echo 'Elise binary is missing or not executable' >&2; exit 1; }

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
stage=$(mktemp -d /tmp/v2bx-elise-package.XXXXXX)
trap 'rm -r -- "$stage"' EXIT

mkdir -p "$stage/elise"
install -m 0755 "$binary" "$stage/elise/elise"
install -m 0644 "$root/rust/elise/LICENSE" "$stage/elise/LICENSE"
install -m 0644 "$root/rust/elise/README.md" "$stage/elise/README.md"
cp -a "$root/rust/elise/example" "$stage/elise/example"

asset="elise-linux-${arch}.tar.gz"
tar -czf "$output_dir/$asset" -C "$stage" elise
(cd "$output_dir" && sha256sum "$asset" > "$asset.sha256")
