#!/usr/bin/env bash
# Fake `trivy` for the Action's tests. TEMPLATE: build-fake-trivy.sh copies it
# into the fake release tarball as `trivy`, replacing the STATE placeholder
# below with the case's shim state directory (the Action runs trivy under
# `env -i`, so the fake cannot rely on any test environment variable).
#
# Behaviour:
#   - every invocation appends a block to $STATE/trivy.log (format in lib.sh)
#     and touches $STATE/trivy.ran (marker: the binary was executed at all);
#   - `--version` / `-v` / `version` prints "Version: <pinned version>";
#   - otherwise it reads `--format|-f <fmt>` and `--output|-o <file>` and
#     writes $STATE/trivy-fixtures/<fmt> (json or cyclonedx) to the output
#     file, or to stdout without --output; the literal token @CWD@ in the
#     fixture is replaced by the working directory of the invocation;
#   - $STATE/trivy-fixtures/exit_code, if present, makes it exit with that
#     code before writing anything;
#   - an unsupported or missing --format exits 2.
set -euo pipefail

STATE='@STATE_DIR@'

{
  printf 'invocation\n'
  printf 'cwd %s\n' "$PWD"
  for a in "$@"; do
    printf 'arg %s\n' "$a"
  done
  while IFS= read -r name; do
    printf 'env %s\n' "$name"
  done < <(compgen -e)
  printf 'end\n'
} >> "$STATE/trivy.log"
: > "$STATE/trivy.ran"

case "${1:-}" in
  --version|-v|version)
    printf 'Version: %s\n' "$(cat "$STATE/trivy-version")"
    exit 0
    ;;
esac

die() {
  printf 'fake trivy: %s\n' "$1" >&2
  exit 2
}

format=""
output=""
while [ $# -gt 0 ]; do
  case "$1" in
    -f|--format)
      [ $# -ge 2 ] || die "$1 needs a value"
      format="$2"
      shift 2
      ;;
    --format=*)
      format="${1#--format=}"
      shift
      ;;
    -o|--output)
      [ $# -ge 2 ] || die "$1 needs a value"
      output="$2"
      shift 2
      ;;
    --output=*)
      output="${1#--output=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [ -f "$STATE/trivy-fixtures/exit_code" ]; then
  code="$(cat "$STATE/trivy-fixtures/exit_code")"
  if [ "$code" != "0" ]; then
    printf 'fake trivy: forced exit %s\n' "$code" >&2
    exit "$code"
  fi
fi

case "$format" in
  json|cyclonedx) ;;
  *) die "unsupported --format '$format'" ;;
esac

src="$STATE/trivy-fixtures/$format"
[ -f "$src" ] || die "no fixture for --format $format"

emit() {
  if grep -qF -e '@CWD@' "$src"; then
    local content
    content="$(cat "$src")"
    printf '%s\n' "${content//@CWD@/"$PWD"}"
  else
    cat "$src"
  fi
}

if [ -n "$output" ]; then
  emit > "$output"
else
  emit
fi
