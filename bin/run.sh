#!/usr/bin/env bash
# Seetrex Compliance Action -- step 2 of action.yml.
#
# Order (plan D1 §3): visibility, event, default branch, inputs; then either a
# control request (repin/close, no scan) or: pinned Trivy download checked by
# sha256 before extraction, two scans of `.` under `env -i`, reduction by the
# jq filters, attestations read from the commit tree, size measurement, body
# check, dry-run report or OIDC token + POST, and the answer handled from files
# only. Every fixed line below is compared verbatim by tests/.
#
# Filters (bin/filters/, all called with -f, input from a file or stdin):
#   sbom.jq, trivy.jq        raw document on stdin -> reduced document (-c)
#   body_check.jq            `jq -n -e` with the body file on stdin (the
#                            filter reads its input itself, so a file with
#                            two JSON values is refused): exit 0 iff the
#                            document push may be sent. Control literals
#                            never pass through it.
#   summary_full.jq,
#   summary_counters.jq      the 200 response file -> markdown (-r); each
#                            prints its own "## Seetrex Compliance" header
#   dry_run.jq               the body file (push or control) -> plain lines
#                            (-r): body keys, string sizes, attestation count;
#                            it never looks inside a document.
#   The rest of a dry run (plan §3 step 15) is run.sh's own (jq cannot hash):
#   each file as sent (name, bytes, sha256), the whole body (bytes, sha256),
#   and the number of SBOM components (every nesting level) and of entries of
#   the reduced vulnerability report (also when it is left out). No name,
#   identifier or package of a finding is ever printed.
# A missing filter stops the run before anything is downloaded or sent.
set -euo pipefail
umask 077

readonly PUSH_URL='https://api.seetrex.com/v1/action/push'
readonly AUDIENCE_QUERY='audience=https%3A%2F%2Fapi.seetrex.com'
readonly CANONICAL_CAP=1048576
readonly BODY_CAP=3145728
readonly MAX_ATTESTATIONS=32

L_PUBLIC='Seetrex Compliance runs on private and internal repositories only. This repository is not private, or its visibility could not be read: nothing was scanned or sent.'
L_NOT_PUSH='Seetrex Compliance records push events only: nothing was sent.'
L_NON_DEFAULT="This run is not on the repository's default branch: nothing was sent."
L_401="Seetrex did not accept this run (401). Either the repository's owner is not admitted yet, or this branch is not the one registered for this repository. If you renamed your default branch, run once with request-repin: true."
L_LEFT_OUT='The vulnerability report was too large to send and was left out; the server was told, and the obligations that read it are not current.'
L_TOO_LARGE='The SBOM and attestations do not fit in one request even without the vulnerability report: nothing was sent.'
L_TRIVY_SHA='The Trivy download does not match its pinned sha256: nothing was scanned or sent.'
# shellcheck disable=SC2016  # literal backticks
L_NO_OIDC='The workflow lacks `permissions: id-token: write`: nothing was sent.'

WORK=""
cleanup() {
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then
    rm -rf -- "$WORK"
  fi
}
trap cleanup EXIT

# Prints a line to the log and appends it to the job summary.
say() {
  printf '%s\n' "$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

die() {
  say "$1"
  exit 1
}

# Soft failure (our outage, rate or quota): warning, green job unless strict.
soft_exit() {
  printf '::warning::%s\n' "$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
  if [ "$STRICT" = true ]; then
    exit 1
  fi
  exit 0
}

sha256_of() {
  local line
  line="$(sha256sum -- "$1")"
  printf '%s\n' "${line%% *}"
}

bytes_of() {
  local n
  n="$(wc -c < "$1")"
  printf '%s\n' "${n//[[:space:]]/}"
}

# ------------------------------------------------------------- 1-2. basics
if [ -z "${RUNNER_TEMP:-}" ] || [ ! -d "$RUNNER_TEMP" ]; then
  die "RUNNER_TEMP is not set: nothing was sent."
fi
OUT_DIR="$RUNNER_TEMP/seetrex-out"
rm -rf -- "$OUT_DIR"

jq_version="$(jq --version 2> /dev/null || true)"
jq_version="${jq_version%$'\r'}"
if ! [[ "$jq_version" =~ ^jq-([0-9]+)\.([0-9]+) ]] \
  || [ "${BASH_REMATCH[1]}" -lt 1 ] \
  || { [ "${BASH_REMATCH[1]}" -eq 1 ] && [ "${BASH_REMATCH[2]}" -lt 7 ]; }; then
  die "Seetrex Compliance needs jq 1.7 or later on the runner: nothing was sent."
fi

# ------------------------------------------------------- 3. private only
# Anything but a JSON `true` (false, missing, null, a string, an unreadable or
# absent event file) is treated as public: nothing is scanned, in dry-run too.
if [ -z "${GITHUB_EVENT_PATH:-}" ] || [ ! -f "$GITHUB_EVENT_PATH" ] \
  || ! jq -e '.repository.private == true' "$GITHUB_EVENT_PATH" > /dev/null 2>&1; then
  say "$L_PUBLIC"
  exit 0
fi

# ---------------------------------------------------------- 4. push only
if [ "${GITHUB_EVENT_NAME:-}" != push ]; then
  say "$L_NOT_PUSH"
  exit 0
fi

# ------------------------------------------------- 5. default branch only
default_branch="$(jq -r '.repository.default_branch | strings' "$GITHUB_EVENT_PATH" 2> /dev/null || true)"
default_branch="${default_branch%$'\r'}"
if [ -z "$default_branch" ] || [ "${GITHUB_REF:-}" != "refs/heads/$default_branch" ]; then
  say "$L_NON_DEFAULT"
  exit 0
fi

# ------------------------------------------------- 6-7. identifiers, inputs
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || die "GITHUB_SHA is not a 40-character commit id: nothing was sent."
[[ "${GITHUB_REPOSITORY_ID:-}" =~ ^[0-9]{1,20}$ ]] || die "GITHUB_REPOSITORY_ID is not numeric: nothing was sent."
if [ -z "${GITHUB_WORKSPACE:-}" ] || [ ! -d "$GITHUB_WORKSPACE" ]; then
  die "GITHUB_WORKSPACE is not a directory: nothing was sent."
fi

DRY_RUN="${INPUT_DRY_RUN:-false}"
STRICT="${INPUT_STRICT:-false}"
REPIN="${INPUT_REQUEST_REPIN:-false}"
CLOSE="${INPUT_REQUEST_CLOSE:-false}"
for pair in "dry-run=$DRY_RUN" "strict=$STRICT" "request-repin=$REPIN" "request-close=$CLOSE"; do
  case "${pair#*=}" in
    true|false) ;;
    *)
      die "Input ${pair%%=*} must be true or false: nothing was sent."
      ;;
  esac
done
SUMMARY="${INPUT_SUMMARY:-full}"
case "$SUMMARY" in
  full|counters) ;;
  *) die "Input summary must be full or counters: nothing was sent." ;;
esac
if [ "$REPIN" = true ] && [ "$CLOSE" = true ]; then
  die "request-repin and request-close cannot be used together: nothing was sent."
fi

FILTERS="${GITHUB_ACTION_PATH:-}/bin/filters"
WORK="$(mktemp -d "$RUNNER_TEMP/seetrex-work.XXXXXX")"

# ------------------------------------------------- 16. OIDC token (helper)
# The JWT never touches argv: it is masked, written into a 600 header file and
# the variable is dropped.
fetch_token() {
  if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
    die "$L_NO_OIDC"
  fi
  case "$ACTIONS_ID_TOKEN_REQUEST_URL" in
    https://*) ;;
    *) die "The runner's OIDC token URL is not https: nothing was sent." ;;
  esac
  [[ "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" =~ ^[^[:space:]]+$ ]] \
    || die "The runner's OIDC request token is malformed: nothing was sent."
  printf '::add-mask::%s\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN"
  local sep='?' code rc=0 jwt
  case "$ACTIONS_ID_TOKEN_REQUEST_URL" in
    *'?'*) sep='&' ;;
  esac
  printf 'Authorization: Bearer %s\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" > "$WORK/token-request.hdr"
  chmod 600 "$WORK/token-request.hdr"
  code="$(curl -sS --proto '=https' --max-time 30 -H @"$WORK/token-request.hdr" \
    -o "$WORK/token.json" -w '%{http_code}' \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}${sep}${AUDIENCE_QUERY}")" || rc=$?
  rm -f -- "$WORK/token-request.hdr"
  if [ "$rc" -ne 0 ] || [ "$code" != 200 ] || [ ! -f "$WORK/token.json" ]; then
    rm -f -- "$WORK/token.json"
    die "The OIDC token could not be obtained from the runner: nothing was sent."
  fi
  jwt="$(jq -r '.value | strings' "$WORK/token.json" 2> /dev/null || true)"
  rm -f -- "$WORK/token.json"
  jwt="${jwt%$'\r'}"
  if ! [[ "$jwt" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$ ]]; then
    die "The OIDC token could not be obtained from the runner: nothing was sent."
  fi
  printf '::add-mask::%s\n' "$jwt"
  printf 'Authorization: Bearer %s\n' "$jwt" > "$WORK/auth.hdr"
  chmod 600 "$WORK/auth.hdr"
  unset jwt
}

# ------------------------------------------------------ 17. POST + retries
HTTP=""
post_once() {
  local code rc=0
  rm -f -- "$WORK/resp"
  code="$(curl -sS --proto '=https' --max-time 60 -H @"$WORK/auth.hdr" \
    -H 'Content-Type: application/json' --data-binary @"$WORK/body.json" \
    -o "$WORK/resp" -w '%{http_code}' "$PUSH_URL")" || rc=$?
  if [ "$rc" -ne 0 ] || ! [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then
    HTTP=000
  else
    HTTP="$code"
  fi
  [ -f "$WORK/resp" ] || : > "$WORK/resp"
}

resp_is_json() {
  jq -e 'type == "object"' "$WORK/resp" > /dev/null 2>&1
}

# The `error` code of the answer, only if it is a short lower-case token.
resp_error() {
  local e
  e="$(jq -r 'if type == "object" then (.error | strings) else empty end' "$WORK/resp" 2> /dev/null || true)"
  e="${e%$'\r'}"
  if [[ "$e" =~ ^[a-z_]{1,64}$ ]]; then
    printf '%s\n' "$e"
  fi
}

# Up to 3 attempts (waits 10 s, 30 s), only when the server or the transport
# asks for it; never on new_repository_budget_reached. Safe: pushes are
# idempotent on the server side.
post_with_retries() {
  local attempt=1 retry delay
  while :; do
    post_once
    retry=0
    case "$HTTP" in
      200) resp_is_json || retry=1 ;;
      000|408|503) retry=1 ;;
      429) [ "$(resp_error)" = new_repository_budget_reached ] || retry=1 ;;
      5[0-9][0-9]) retry=1 ;;
    esac
    if [ "$retry" = 0 ] || [ "$attempt" -ge 3 ]; then
      return 0
    fi
    delay=10
    if [ "$attempt" -eq 2 ]; then
      delay=30
    fi
    sleep "$delay"
    attempt=$((attempt + 1))
  done
}

# Exit table for everything but a 200 with a JSON object (plan §3 step 19).
handle_failure() {
  local err msg
  case "$HTTP" in
    200) soft_exit "Seetrex answered with something that is not JSON, and the retries ran out: nothing was recorded." ;;
    000) soft_exit "Seetrex could not be reached, and the retries ran out: nothing was recorded." ;;
    408) soft_exit "Seetrex timed out reading the request (408), and the retries ran out: nothing was recorded." ;;
    429)
      if [ "$(resp_error)" = new_repository_budget_reached ]; then
        soft_exit "Seetrex is not admitting new repositories right now (429); the next push will try again: nothing was recorded."
      fi
      soft_exit "Seetrex is limiting the rate of requests (429), and the retries ran out: nothing was recorded."
      ;;
    5[0-9][0-9]) soft_exit "Seetrex is unavailable ($HTTP), and the retries ran out: nothing was recorded." ;;
    400)
      err="$(resp_error)"
      if [ "$err" = repository_not_supported ]; then
        die "Seetrex does not support this repository (400): nothing was recorded."
      fi
      say "Seetrex rejected the request as malformed (400): nothing was recorded."
      msg="$(jq -r --arg re "^[a-z0-9 ,.'-]{1,120}\$" \
        'if type == "object" then (.message | strings | select(test($re))) else empty end' \
        "$WORK/resp" 2> /dev/null || true)"
      msg="${msg%$'\r'}"
      local re="^[a-z0-9 ,.'-]{1,120}\$"
      if [ -n "$msg" ] && [[ "$msg" =~ $re ]]; then
        say "Seetrex said: $msg"
      fi
      exit 1
      ;;
    401) die "$L_401" ;;
    403) die "Seetrex refused the origin of the request (403): nothing was recorded." ;;
    409) die "This repository is deactivated in Seetrex (409): nothing was recorded." ;;
    413) die "The request was too large for Seetrex (413): nothing was recorded." ;;
    *) die "Seetrex answered with an unexpected code ($HTTP): nothing was recorded." ;;
  esac
}

# ------------------------------------------------------------ 8. control
if [ "$REPIN" = true ] || [ "$CLOSE" = true ]; then
  what=repin
  if [ "$CLOSE" = true ]; then
    what=close
  fi
  printf '{"%s":true}' "$what" > "$WORK/body.json"
  if [ "$DRY_RUN" = true ]; then
    if [ -f "$FILTERS/dry_run.jq" ]; then
      jq -r -f "$FILTERS/dry_run.jq" < "$WORK/body.json" > "$WORK/dry.md" \
        || die "The dry-run report could not be rendered."
      cat "$WORK/dry.md"
      if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        cat "$WORK/dry.md" >> "$GITHUB_STEP_SUMMARY"
      fi
    fi
    say "Dry run: a $what request would be sent to Seetrex, with no documents. Nothing was sent."
    exit 0
  fi
  fetch_token
  post_with_retries
  if [ "$HTTP" = 200 ] && resp_is_json; then
    say "Seetrex accepted the $what request."
    exit 0
  fi
  handle_failure
fi

# ------------------------------------------------------- filters present
for f in sbom trivy body_check summary_full summary_counters dry_run; do
  [ -f "$FILTERS/$f.jq" ] || die "The Action is incomplete (bin/filters/$f.jq is missing): nothing was scanned or sent."
done
git -C "$GITHUB_WORKSPACE" cat-file -e "$GITHUB_SHA^{commit}" 2> /dev/null \
  || die "The commit of this run is not checked out in the workspace (run actions/checkout first): nothing was scanned or sent."

# ---------------------------------------------------------- 9. Trivy pin
pin="${GITHUB_ACTION_PATH:-}/bin/trivy.pin"
[ -f "$pin" ] || die "bin/trivy.pin is missing: nothing was scanned or sent."
trivy_version=""
sha_64=""
sha_arm=""
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%$'\r'}"
  if [[ "$line" =~ ^TRIVY_VERSION=([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    trivy_version="${BASH_REMATCH[1]}"
  elif [[ "$line" =~ ^TRIVY_SHA256_LINUX_64BIT=([0-9a-f]{64})$ ]]; then
    sha_64="${BASH_REMATCH[1]}"
  elif [[ "$line" =~ ^TRIVY_SHA256_LINUX_ARM64=([0-9a-f]{64})$ ]]; then
    sha_arm="${BASH_REMATCH[1]}"
  fi
done < "$pin"
if [ -z "$trivy_version" ] || [ -z "$sha_64" ] || [ -z "$sha_arm" ]; then
  die "bin/trivy.pin is malformed: nothing was scanned or sent."
fi
[ "${RUNNER_OS:-}" = Linux ] || die "Seetrex Compliance runs on Linux runners only: nothing was scanned or sent."
case "$(uname -m)" in
  x86_64|amd64) asset=Linux-64bit; want_sha="$sha_64" ;;
  aarch64|arm64) asset=Linux-ARM64; want_sha="$sha_arm" ;;
  *) die "Seetrex Compliance runs on x86_64 and arm64 runners only: nothing was scanned or sent." ;;
esac

trivy_url="https://github.com/aquasecurity/trivy/releases/download/v${trivy_version}/trivy_${trivy_version}_${asset}.tar.gz"
curl -fsSL --proto '=https' --max-time 300 -o "$WORK/trivy.tar.gz" "$trivy_url" \
  || die "The Trivy download failed: nothing was scanned or sent."
printf '%s  trivy.tar.gz\n' "$want_sha" > "$WORK/trivy.sha256"
# The checksum is verified BEFORE anything is extracted.
( cd "$WORK" && sha256sum -c --status trivy.sha256 ) || die "$L_TRIVY_SHA"
mkdir "$WORK/trivy-bin"
( cd "$WORK/trivy-bin" && tar -xzf ../trivy.tar.gz trivy ) \
  || die "The Trivy download could not be unpacked: nothing was scanned or sent."
TRIVY="$WORK/trivy-bin/trivy"
[ -f "$TRIVY" ] || die "The Trivy download could not be unpacked: nothing was scanned or sent."
chmod 700 "$TRIVY"

# ---------------------------------------------------------- 10. scans
# Only `.` is scanned, from the workspace, so no runner path names the subject;
# Trivy sees a minimal environment (no runner tokens) and writes under WORK.
CACHE_DIR="$RUNNER_TEMP/seetrex-trivy-cache"
mkdir -p "$CACHE_DIR"
scan_env=(PATH="$PATH" HOME="${HOME:-/tmp}" TMPDIR="${TMPDIR:-/tmp}" LANG="${LANG:-C.UTF-8}")
for v in HTTPS_PROXY HTTP_PROXY NO_PROXY https_proxy http_proxy no_proxy; do
  if [ -n "${!v:-}" ]; then
    scan_env+=("$v=${!v}")
  fi
done
common_flags=(--scanners vuln --quiet --skip-version-check --disable-telemetry --offline-scan --cache-dir "$CACHE_DIR")
cd "$GITHUB_WORKSPACE"
env -i "${scan_env[@]}" "$TRIVY" fs --format json "${common_flags[@]}" \
  --output "$WORK/trivy.raw.json" . \
  || die "The vulnerability scan failed: nothing was sent."
env -i "${scan_env[@]}" "$TRIVY" fs --format cyclonedx --skip-db-update "${common_flags[@]}" \
  --output "$WORK/sbom.raw.json" . \
  || die "The SBOM scan failed: nothing was sent."

# ------------------------------------------------------- 11-12. reduction
jq -c -f "$FILTERS/sbom.jq" < "$WORK/sbom.raw.json" > "$WORK/sbom.json" \
  || die "The SBOM could not be reduced: nothing was sent."
jq -c -f "$FILTERS/trivy.jq" < "$WORK/trivy.raw.json" > "$WORK/trivy.json" \
  || die "The vulnerability report could not be reduced: nothing was sent."
rm -f -- "$WORK/sbom.raw.json" "$WORK/trivy.raw.json"

# ---------------------------------------------- 13. attestations (commit tree)
# Only what is committed at GITHUB_SHA, never the worktree: regular blobs named
# *.json directly under .seetrex/attestations/.
mkdir "$WORK/att"
git -C "$GITHUB_WORKSPACE" ls-tree -z "$GITHUB_SHA" .seetrex/attestations/ > "$WORK/att.tree" \
  || die "The attestations could not be listed from the commit: nothing was sent."
n_att=0
while IFS= read -r -d '' entry; do
  meta="${entry%%$'\t'*}"
  path="${entry#*$'\t'}"
  read -r mode otype oid <<< "$meta"
  case "$mode" in
    100644|100755) ;;
    *) continue ;;
  esac
  [ "$otype" = blob ] || continue
  [[ "$path" =~ ^\.seetrex/attestations/[^/]+\.json$ ]] || continue
  n_att=$((n_att + 1))
  if [ "$n_att" -gt "$MAX_ATTESTATIONS" ]; then
    die "More than $MAX_ATTESTATIONS attestation files are committed in .seetrex/attestations/: nothing was sent."
  fi
  git -C "$GITHUB_WORKSPACE" cat-file blob "$oid" > "$WORK/att/$n_att.json"
  printf '%s' "$path" > "$WORK/att/$n_att.path"
done < "$WORK/att.tree"
: > "$WORK/att.jsonl"
for ((i = 1; i <= n_att; i++)); do
  jq -Rs . "$WORK/att/$i.json" >> "$WORK/att.jsonl"
done
jq -s . "$WORK/att.jsonl" > "$WORK/att.json"

# ------------------------------------------------------------ 14. measure
# build_body <with_trivy|left_out>: body from files only (never argv).
build_body() {
  if [ "$1" = with_trivy ]; then
    jq -cn --rawfile sbom "$WORK/sbom.json" --rawfile trivy "$WORK/trivy.json" \
      --slurpfile att "$WORK/att.json" \
      '{sbom: ($sbom | rtrimstr("\n")), trivy: ($trivy | rtrimstr("\n"))}
       + (if ($att[0] | length) > 0 then {attestations: $att[0]} else {} end)' \
      > "$WORK/body.json"
  else
    jq -cn --rawfile sbom "$WORK/sbom.json" --slurpfile att "$WORK/att.json" \
      '{sbom: ($sbom | rtrimstr("\n")), trivy_left_out: true}
       + (if ($att[0] | length) > 0 then {attestations: $att[0]} else {} end)' \
      > "$WORK/body.json"
  fi
}

jq -cjS . "$WORK/trivy.json" > "$WORK/trivy.canonical"
left_out=false
if [ "$(bytes_of "$WORK/trivy.canonical")" -gt "$CANONICAL_CAP" ]; then
  left_out=true
fi
rm -f -- "$WORK/trivy.canonical"
if [ "$left_out" = false ]; then
  build_body with_trivy
  if [ "$(bytes_of "$WORK/body.json")" -gt "$BODY_CAP" ]; then
    left_out=true
  fi
fi
if [ "$left_out" = true ]; then
  build_body left_out
  if [ "$(bytes_of "$WORK/body.json")" -gt "$BODY_CAP" ]; then
    die "$L_TOO_LARGE"
  fi
fi
jq -n -e -f "$FILTERS/body_check.jq" < "$WORK/body.json" > /dev/null 2>&1 \
  || die "The request body failed its own check: nothing was sent."

# ------------------------------------------------------------ 15. dry run
# Plan §3 step 15: files, sizes, sha256, body keys, counts. dry_run.jq gives
# the body keys and string sizes; the files (as they would be sent), the whole
# body and the two counts are measured here. No token, no POST, no artifact.
dry_file_line() {
  printf -- '- %s: %s bytes, sha256 %s\n' "$1" "$(bytes_of "$2")" "$(sha256_of "$2")"
}

write_dry_run_report() {
  local key i name components vulns
  {
    printf '## Seetrex Compliance (dry run)\n\n'
    jq -r -f "$FILTERS/dry_run.jq" < "$WORK/body.json"
    printf '\nFiles, as they would be sent:\n\n'
    for key in sbom trivy; do
      if jq -e --arg k "$key" 'has($k)' "$WORK/body.json" > /dev/null; then
        jq -j --arg k "$key" '.[$k]' "$WORK/body.json" > "$WORK/dry.part"
        dry_file_line "$key" "$WORK/dry.part"
      fi
    done
    for ((i = 1; i <= n_att; i++)); do
      jq -j --argjson i "$((i - 1))" '.attestations[$i]' "$WORK/body.json" > "$WORK/dry.part"
      name="attestation $i"
      if [[ "$(cat "$WORK/att/$i.path")" =~ ^\.seetrex/attestations/[A-Za-z0-9._-]{1,128}\.json$ ]]; then
        name="$(cat "$WORK/att/$i.path")"
      fi
      dry_file_line "$name" "$WORK/dry.part"
    done
    dry_file_line "request body" "$WORK/body.json"
    components="$(jq '[.components[]? | recurse(.components[]?)] | length' "$WORK/sbom.json")"
    vulns="$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$WORK/trivy.json")"
    printf '\nCounts:\n\n'
    printf -- '- SBOM components (every level): %s\n' "${components%$'\r'}"
    if [ "$left_out" = true ]; then
      printf -- '- vulnerability report entries: %s (the report is left out)\n' "${vulns%$'\r'}"
    else
      printf -- '- vulnerability report entries: %s\n' "${vulns%$'\r'}"
    fi
    printf -- '- attestations: %s\n\n' "$n_att"
  } > "$WORK/dry.md"
  rm -f -- "$WORK/dry.part"
}

if [ "$DRY_RUN" = true ]; then
  # Called plainly so that `set -e` stays in force inside it.
  write_dry_run_report
  cat "$WORK/dry.md"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    cat "$WORK/dry.md" >> "$GITHUB_STEP_SUMMARY"
  fi
  say "Dry run: nothing was sent to Seetrex."
  exit 0
fi

# ------------------------------------------------------- 16-17. send
fetch_token
post_with_retries
if ! { [ "$HTTP" = 200 ] && resp_is_json; }; then
  handle_failure
fi

# ------------------------------------------------- 18. the 200 answer
final_rc=0
if [ "$left_out" = true ]; then
  say "$L_LEFT_OUT"
fi
if jq -r -f "$FILTERS/summary_$SUMMARY.jq" "$WORK/resp" > "$WORK/summary.md" 2> /dev/null; then
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    cat "$WORK/summary.md" >> "$GITHUB_STEP_SUMMARY"
  fi
else
  say "The job summary could not be rendered from Seetrex's answer."
  final_rc=1
fi

# Categories the server did not read, with a fixed text; only plain tokens.
jq -r '.skipped // [] | if type == "array" then .[] | strings else empty end' \
  "$WORK/resp" > "$WORK/skipped" 2> /dev/null || : > "$WORK/skipped"
while IFS= read -r category || [ -n "$category" ]; do
  category="${category%$'\r'}"
  if [[ "$category" =~ ^[a-z_]{1,64}$ ]]; then
    printf 'Seetrex did not read the document of category %s in this push; the obligations that read it are not current.\n' "$category"
  fi
done < "$WORK/skipped"

# The record: only a non-null record of THIS repository is kept, as a file.
if jq -e '.record != null' "$WORK/resp" > /dev/null 2>&1; then
  if jq -e --arg slug "gh-$GITHUB_REPOSITORY_ID" \
    '(.record | type) == "object" and .record.slug == $slug' "$WORK/resp" > /dev/null 2>&1; then
    mkdir -p "$OUT_DIR"
    jq '.record' "$WORK/resp" > "$OUT_DIR/seetrex-record.json"
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      printf 'record=%s\n' "$OUT_DIR/seetrex-record.json" >> "$GITHUB_OUTPUT"
    fi
  else
    say "The record in Seetrex's answer does not belong to this repository: it was not kept."
    final_rc=1
  fi
fi

say "Seetrex recorded this push."
if [ "$(jq -r '.quota | strings' "$WORK/resp" 2> /dev/null || true)" = reached ]; then
  printf '::warning::%s\n' "Seetrex reports that this repository's quota is reached."
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n\n' "Seetrex reports that this repository's quota is reached." >> "$GITHUB_STEP_SUMMARY"
  fi
  if [ "$STRICT" = true ]; then
    final_rc=1
  fi
fi
exit "$final_rc"
