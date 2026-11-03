#!/usr/bin/env bash
# Builds the fake Trivy release tarball used by the tests.
#
# Usage: build-fake-trivy.sh <state_dir> <out_tarball>
#
# The tarball has the layout of a real Trivy release (`trivy` at the root plus
# a LICENSE). Its `trivy` is fake-trivy.sh with the absolute <state_dir> baked
# in, so every case gets its own tarball and its own sha256; lib.sh writes that
# sha256 into the case copy's bin/trivy.pin.
set -euo pipefail

if [ $# -ne 2 ]; then
  printf 'usage: %s <state_dir> <out_tarball>\n' "$0" >&2
  exit 2
fi

state="$1"
out="$2"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$state" in
  /*) ;;
  *) printf 'build-fake-trivy: state dir must be absolute: %s\n' "$state" >&2; exit 2 ;;
esac
case "$state" in
  *"'"*) printf 'build-fake-trivy: state dir must not contain a quote\n' >&2; exit 2 ;;
esac
[ -d "$state" ] || { printf 'build-fake-trivy: no such dir: %s\n' "$state" >&2; exit 2; }

stage="$(mktemp -d "$state/fake-trivy-stage.XXXXXX")"
template="$(cat "$here/fake-trivy.sh")"
printf '%s\n' "${template//@STATE_DIR@/"$state"}" > "$stage/trivy"
chmod 755 "$stage/trivy"
printf 'Fake Trivy for tests only. Not Trivy.\n' > "$stage/LICENSE"

# Relative member names and a relative archive name: GNU tar on Git Bash
# would read a `C:` prefix as a remote host.
( cd "$stage" && tar -czf fake-trivy.tar.gz trivy LICENSE )
mv "$stage/fake-trivy.tar.gz" "$out"
rm -rf "$stage"
