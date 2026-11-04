#!/usr/bin/env bash
# Fake `trivy` for the Action's tests. TEMPLATE: build-fake-trivy.sh copies it
# into the fake release tarball as `trivy`, replacing the STATE placeholder
# below with the case's shim state directory (the Action runs trivy under
# `env -i`, so the fake cannot rely on any test environment variable).
#
# Behaviour:
#   - every invocation appends a block to $STATE/trivy.log (format in lib.sh:
#     cwd, HOME, args, env names, the files under its cwd with their sha256,
#     every file under its cwd with .git/ included, and the config/ignore
#     files real Trivy would read from its cwd) and
#     touches $STATE/trivy.ran (marker: the binary was executed at all);
#   - `--version` / `-v` / `version` prints "Version: <pinned version>";
#   - otherwise it reads `--format|-f <fmt>` and `--output|-o <file>` and
#     writes $STATE/trivy-fixtures/<fmt> (json or cyclonedx) to the output
#     file, or to stdout without --output; the literal token @CWD@ in the
#     fixture is replaced by the working directory of the invocation, and
#     the literal token @SCANARG@ by its path argument (the LAST argument,
#     as in `trivy fs [flags] PATH`): real Trivy names the SBOM subject
#     (metadata.component.name) after that argument;
#   - $STATE/trivy-fixtures/exit_code, if present, makes it exit with that
#     code before writing anything;
#   - an unsupported or missing --format exits 2.
set -euo pipefail

STATE='@STATE_DIR@'

{
  printf 'invocation\n'
  printf 'cwd %s\n' "$PWD"
  printf 'home %s\n' "${HOME:-}"
  for a in "$@"; do
    printf 'arg %s\n' "$a"
  done
  while IFS= read -r name; do
    printf 'env %s\n' "$name"
  done < <(compgen -e)
  # What it would scan: every regular file under its cwd except .git/, as
  # "file <path relative to cwd> <sha256>", sorted.
  while IFS= read -r -d '' f; do
    sum="$(sha256sum < "$f")"
    printf 'file %s %s\n' "${f#./}" "${sum%% *}"
  done < <(find . -path ./.git -prune -o -type f -print0 | sort -z)
  # Every regular file under its cwd, .git/ included, as "seen <path>":
  # what a crafted commit managed to put in front of the scanner anywhere.
  while IFS= read -r -d '' f; do
    printf 'seen %s\n' "${f#./}"
  done < <(find . -type f -print0 | sort -z)
  # Real Trivy reads a config file (-c/--config, default "trivy.yaml") and
  # an ignore file (--ignorefile, default ".trivyignore") relative to its
  # cwd; an empty value reads none. Modelled: "reads <kind> <file>" when the
  # file it would read exists.
  config=trivy.yaml
  ignorefile=.trivyignore
  prev=""
  for a in "$@"; do
    case "$prev" in
      -c|--config) config="$a" ;;
      --ignorefile) ignorefile="$a" ;;
    esac
    case "$a" in
      --config=*) config="${a#--config=}" ;;
      --ignorefile=*) ignorefile="${a#--ignorefile=}" ;;
    esac
    prev="$a"
  done
  if [ -n "$config" ] && [ -f "$config" ]; then
    printf 'reads config %s\n' "$config"
  fi
  if [ -n "$ignorefile" ] && [ -f "$ignorefile" ]; then
    printf 'reads ignorefile %s\n' "$ignorefile"
  fi
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

scanarg="${*: -1}"
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
  if grep -qF -e '@CWD@' -e '@SCANARG@' "$src"; then
    local content
    content="$(cat "$src")"
    content="${content//@CWD@/"$PWD"}"
    printf '%s\n' "${content//@SCANARG@/"$scanarg"}"
  else
    cat "$src"
  fi
}

if [ -n "$output" ]; then
  emit > "$output"
else
  emit
fi
