# shellcheck shell=bash
# tests/lib.sh -- shared harness for the Seetrex Compliance Action tests.
# Sourced by tests/run_all.sh before every test file; never executed.
#
# =============================================================================
# INTERFACE (U2 and U3 code against this header; keep it in sync with the code)
# =============================================================================
#
# DECLARING TESTS
#   A test file is tests/test_<area>.sh. Every function in it named
#   test_intent_* (or test_scenario_*) is one test; run_all.sh discovers them
#   with `compgen -A function` after sourcing lib.sh and the file. Top level of
#   a test file: only function definitions and constants (no side effects).
#   A test name must be unique across all files (duplicates fail the run).
#   Each test runs in its own `bash` process, with `set -euo pipefail`, its cwd
#   in a fresh empty $TEST_TMP (deleted afterwards unless KEEP_TMP=1), under a
#   600 s timeout. A test PASSES iff it returns 0 AND made at least one
#   assertion (assert_* or fail); a test with zero assertions FAILS.
#   Assertions `exit 1` on failure: call them in the test's own shell, never
#   inside $(...) or a pipeline. To capture an expected non-zero exit:
#   `rc=0; cmd || rc=$?`.
#
# RUNNING
#   bash tests/run_all.sh            all tests; enforces the floor
#   bash tests/run_all.sh <regex>    only tests whose name matches (bash =~);
#                                    the floor is NOT enforced in this mode
#   KEEP_TMP=1 bash tests/run_all.sh keep every $TEST_TMP for inspection
#   Exit 1 if any test fails, if a test file cannot be sourced, if two tests
#   share a name, if no test ran, or (unfiltered) if the number of discovered
#   tests is below tests/EXPECTED_TEST_COUNT (a single integer, the floor).
#   A count above the floor passes with a notice to raise the floor.
#
# CASE SETUP
#   setup_case
#     Creates $CASE_DIR under $TEST_TMP and, inside it:
#       $ACTION_COPY   copy of the Action (action.yml if present, bin/);
#                      GITHUB_ACTION_PATH points here. Its bin/trivy.pin keeps
#                      the real TRIVY_VERSION, with BOTH sha256 replaced by the
#                      sha256 of this case's fake Trivy tarball.
#       $WS            git repo with one commit (package.json, README.md),
#                      author/committer "Alice <alice@example.invalid>",
#                      branch main; GITHUB_WORKSPACE points here.
#       $SHIM_STATE    shim state and logs (= SEETREX_TEST_SHIM_DIR); NOT
#                      under RUNNER_TEMP.
#       $OUT_DIR       holds $RUN_STDOUT, $RUN_STDERR, $GITHUB_STEP_SUMMARY,
#                      $GITHUB_OUTPUT (all empty files).
#     Scrubs every inherited GITHUB_*, RUNNER_*, ACTIONS_*, INPUT_* variable,
#     then exports a push to main of a private repository:
#       GITHUB_ACTIONS=true GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main
#       GITHUB_REF_NAME=main GITHUB_REF_TYPE=branch GITHUB_SHA=<HEAD of $WS>
#       GITHUB_REPOSITORY=example-org/example-repo GITHUB_REPOSITORY_ID=$TEST_REPO_ID
#       GITHUB_REPOSITORY_OWNER=example-org GITHUB_REPOSITORY_OWNER_ID=$TEST_OWNER_ID
#       GITHUB_ACTOR=alice-actor GITHUB_TRIGGERING_ACTOR=alice-actor
#       GITHUB_SERVER_URL=https://github.com GITHUB_API_URL=https://api.github.com
#       GITHUB_WORKSPACE GITHUB_EVENT_PATH GITHUB_STEP_SUMMARY GITHUB_OUTPUT
#       GITHUB_ACTION_PATH RUNNER_TEMP (empty dir) RUNNER_OS=Linux RUNNER_ARCH=X64
#       ACTIONS_ID_TOKEN_REQUEST_URL=https://token.invalid/x?a=1
#       ACTIONS_ID_TOKEN_REQUEST_TOKEN=$FAKE_REQUEST_TOKEN
#       HOME=$CASE_DIR/home TMPDIR=$CASE_DIR/tmp SEETREX_TEST_SHIM_DIR
#       PATH=<tests/shims>:$PATH
#       GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=$CASE_DIR/gitconfig (identity
#       Alice, autocrlf false, no signing)
#     and writes the event with `make_event private`. Default Trivy fixtures:
#     json = fixtures/common/trivy-report.json (CVE-2099-0001,
#     GHSA-2222-3333-4444, package left-pad-fixture), cyclonedx =
#     fixtures/common/sbom.cdx.json. No API response is queued.
#
#   make_event <kind> [default_branch]      (default_branch defaults to main)
#     Rewrites $GITHUB_EVENT_PATH. kind:
#       private | internal   .repository.private = true (internal: visibility
#                            "internal")
#       public               .repository.private = false
#       missing              no .repository.private key
#       null                 .repository.private = null
#       string               .repository.private = "true" (a string)
#       no-default-branch    private, without .repository.default_branch
#       unreadable           the file is not JSON
#       absent               the file does not exist
#     The event carries identity that must never leave the runner:
#     pusher alice-actor <alice@example.invalid>, sender alice-actor,
#     head_commit author Alice <alice@example.invalid>.
#   set_event_name <name>      exports GITHUB_EVENT_NAME
#   set_ref <ref>              exports GITHUB_REF (+ GITHUB_REF_NAME); does
#                              not rewrite the event
#   commit_file <src> <relpath> [message]
#                              copies <src> to $WS/<relpath>, commits it and
#                              exports the new GITHUB_SHA
#   commit_attestation <src> [name]
#                              commit_file to .seetrex/attestations/<name>
#                              (name defaults to basename of <src>)
#   ws_put <src> <relpath>     copies into the worktree WITHOUT committing
#   write_trivy_pin <version> <sha256_64bit> <sha256_arm64>
#                              rewrites $ACTION_COPY/bin/trivy.pin
#   pin_value <pin_file> <KEY> prints the value of KEY=... (regex, not source)
#   fake_trivy_sha             prints the sha256 of this case's fake tarball
#   set_trivy_fixture <json|cyclonedx> <file>
#                              what the fake trivy writes for that --format;
#                              the token @CWD@ is replaced by its cwd and
#                              @SCANARG@ by its last argument (the scan path)
#   set_trivy_exit <code>      the fake trivy exits <code> without output
#   set_download_file <file>   the shim serves <file> for the Trivy URL
#   set_download_status <code> HTTP status of the Trivy download (default 200)
#   set_token_response <status> <file>   OIDC token endpoint answer (default
#                              200 {"value":"$FAKE_JWT"})
#   set_api_response <status> <body_file> [headers_file]
#                              queues one answer of https://api.seetrex.com/*;
#                              headers_file holds "Name: value" lines, written
#                              by the shim to a `-D <file>` dump after
#                              "HTTP/2 <status>"; answers are served in order
#                              and the last one repeats
#   set_api_transport_error [curl_exit]  queues a transport failure (no
#                              body, write-out 000, exit curl_exit, default 7)
#   reset_logs                 truncates the curl/sleep/tar/trivy logs, the trivy
#                              marker, stdout/stderr, summary and output files
#                              (queued API answers are kept)
#
# RUNNING THE ACTION
#   run_action [input=value ...]
#     Runs ONLY the run.sh step of action.yml, as
#     `bash "$GITHUB_ACTION_PATH/bin/run.sh"` with cwd $GITHUB_WORKSPACE: the
#     date, cache, upload-artifact and cleanup steps are not emulated, and
#     neither is `env -u BASH_ENV` (so a BASH_ENV a test exports reaches
#     run.sh). Inputs are passed as env, as action.yml must map them:
#     name -> INPUT_<NAME upper-cased, '-' -> '_'>, with action.yml defaults
#     INPUT_DRY_RUN=false INPUT_SUMMARY=full INPUT_STRICT=false
#     INPUT_REQUEST_REPIN=false INPUT_REQUEST_CLOSE=false.
#     e.g. `run_action dry-run=true summary=counters`.
#     Sets RUN_RC (exit code; never aborts the test), $RUN_STDOUT,
#     $RUN_STDERR. Outputs accumulate across runs (see reset_logs).
#
# INSPECTING
#   curl_count                 number of curl invocations
#   curl_log                   prints $SHIM_STATE/curl.log
#   curl_urls                  prints the URL of every call, one per line
#   curl_call <n> <field>      prints a field of call n (1-based):
#                              argv | url | method | headers | body | status | exit
#   curl_call_dir <n>          prints the directory of call n
#   api_call_count             calls whose URL starts with https://api.seetrex.com/
#   token_call_count           calls to the OIDC token URL
#   download_call_count        calls to the Trivy release URL
#   sleep_log / sleep_count    the sleep shim's log / number of sleeps
#   tar_count                  number of tar invocations (tests/shims/tar)
#   trivy_ran                  status 0 iff the fake trivy was executed at all
#   trivy_invocations          number of trivy invocations
#   trivy_args <n>             args of invocation n, one per line
#   trivy_cwd <n>              cwd of invocation n
#   trivy_home <n>             value of HOME seen by invocation n
#   trivy_env <n>              env var NAMES seen by invocation n, one per line
#   trivy_files <n>            files under the cwd of invocation n (.git/
#                              excluded), "<relpath> <sha256>", sorted
#   trivy_reads <n>            config/ignore files invocation n would read as
#                              real Trivy does ("config trivy.yaml",
#                              "ignorefile .trivyignore"); empty = none
#   github_output_value <key>  value of key=value in $GITHUB_OUTPUT (single-line)
#
# ASSERTIONS (each counts as one assertion; failure prints and `exit 1`)
#   fail <msg>
#   assert_eq <expected> <actual> [msg]
#   assert_ne <unexpected> <actual> [msg]
#   assert_rc <expected>                    compares with RUN_RC
#   assert_contains <haystack> <needle> [msg]        fixed strings
#   assert_not_contains <haystack> <needle> [msg]
#   assert_file_contains <file> <needle> [msg]       grep -F
#   assert_file_not_contains <file> <needle> [msg]   (missing file = pass)
#   assert_tree_not_contains <dir> <needle> [msg]    grep -rF over a tree
#   assert_file_exists <file> [msg]
#   assert_no_file <path> [msg]
#   assert_json <file> <jq-filter> [msg]    jq -e must succeed
#   assert_line_eq <file> <line> [msg]      some line of <file> equals <line>
#
# SHIM LOG FORMATS (all under $SHIM_STATE)
#   curl.log          one line per call: "<n> <METHOD> <URL> -> <status> exit=<rc>"
#                     (status 000 = transport failure); a shim refusal logs
#                     "<n> SHIM-ERROR <reason>" and exits 2
#   curl/<n>/argv     raw arguments, one per line
#   curl/<n>/url      the URL;  curl/<n>/method  GET unless data or -X
#   curl/<n>/headers  request headers, one per line, `-H @file` expanded
#   curl/<n>/body     request body bytes (`--data-binary @file` expanded;
#                     several data arguments joined with '&')
#   curl/<n>/status   HTTP status served (000 = transport failure)
#   curl/<n>/exit     curl exit code returned
#   curl/<n>/user     only if -u/--user was passed
#   sleep.log         one line per sleep: its arguments
#   tar.log           one line per tar call: its arguments (the shim then
#                     execs the real tar)
#   trivy.log         per invocation: "invocation", "cwd <dir>",
#                     "home <HOME>", one "arg <a>" per argument, one
#                     "env <NAME>" per env var, one "file <relpath> <sha256>"
#                     per file under its cwd (.git/ excluded), "reads config
#                     <f>" / "reads ignorefile <f>" when the file real Trivy
#                     would read from its cwd exists, "end"
#   trivy.ran         exists iff the fake trivy ran (even for --version)
#
# FIXED LINES (verbatim from the plan §1; run.sh must print these exactly)
#   L_PUBLIC L_NOT_PUSH L_NON_DEFAULT L_401 L_LEFT_OUT L_TOO_LARGE
#   L_TRIVY_SHA L_NO_OIDC
#
# CONSTANTS
#   FAKE_JWT FAKE_REQUEST_TOKEN TEST_REPO_ID TEST_OWNER_ID TOKEN_URL
#   SEETREX_PUSH_URL TRIVY_DOWNLOAD_PREFIX TESTS_DIR ACTION_ROOT
#   FIXTURES_COMMON
# =============================================================================

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACTION_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
FIXTURES_COMMON="$TESTS_DIR/fixtures/common"

FAKE_JWT='eyJhbGciOiJub25lIn0.eyJzZWV0cmV4X3Rlc3QiOiJmYWtlX2p3dCJ9.c2VldHJleC1mYWtlLXNpZ25hdHVyZQ'
FAKE_REQUEST_TOKEN='fake-oidc-request-token-7f3a'
TEST_REPO_ID=987654321
TEST_OWNER_ID=123456789
TOKEN_URL='https://token.invalid/x?a=1'
# shellcheck disable=SC2034  # read by the test files that source this one
SEETREX_PUSH_URL='https://api.seetrex.com/v1/action/push'
TRIVY_DOWNLOAD_PREFIX='https://github.com/aquasecurity/trivy/releases/download/'

# shellcheck disable=SC2034  # consumed by the test files
L_PUBLIC='Seetrex Compliance runs on private and internal repositories only. This repository is not private, or its visibility could not be read: nothing was scanned or sent.'
# shellcheck disable=SC2034
L_NOT_PUSH='Seetrex Compliance records push events only: nothing was sent.'
# shellcheck disable=SC2034
L_NON_DEFAULT="This run is not on the repository's default branch: nothing was sent."
# shellcheck disable=SC2034
L_401="Seetrex did not accept this run (401). Either the repository's owner is not admitted yet, or this branch is not the one registered for this repository. If you renamed your default branch, run once with request-repin: true."
# shellcheck disable=SC2034
L_LEFT_OUT='The vulnerability report was too large to send and was left out; the server was told, and the obligations that read it are not current.'
# shellcheck disable=SC2034
L_TOO_LARGE='The SBOM and attestations do not fit in one request even without the vulnerability report: nothing was sent.'
# shellcheck disable=SC2034
L_TRIVY_SHA='The Trivy download does not match its pinned sha256: nothing was scanned or sent.'
# shellcheck disable=SC2034,SC2016  # literal backticks, no expansion wanted
L_NO_OIDC='The workflow lacks `permissions: id-token: write`: nothing was sent.'

# ---------------------------------------------------------------- assertions

_assert_tick() {
  local f="${TEST_TMP:-}"
  if [ -n "$f" ] && [ -d "$f" ]; then
    printf '.' >> "$f/.asserts"
  fi
}

fail() {
  _assert_tick
  printf 'ASSERTION FAILED: %s\n' "$1" >&2
  exit 1
}

assert_eq() {
  _assert_tick
  if [ "$1" != "$2" ]; then
    printf 'ASSERTION FAILED: %s\n  expected: [%s]\n  actual:   [%s]\n' "${3:-assert_eq}" "$1" "$2" >&2
    exit 1
  fi
}

assert_ne() {
  _assert_tick
  if [ "$1" = "$2" ]; then
    printf 'ASSERTION FAILED: %s\n  both are: [%s]\n' "${3:-assert_ne}" "$1" >&2
    exit 1
  fi
}

assert_rc() {
  _assert_tick
  if [ "${RUN_RC:-unset}" != "$1" ]; then
    printf 'ASSERTION FAILED: exit code\n  expected: %s\n  actual:   %s\n' "$1" "${RUN_RC:-unset}" >&2
    _dump_run_output
    exit 1
  fi
}

assert_contains() {
  _assert_tick
  if [[ "$1" != *"$2"* ]]; then
    printf 'ASSERTION FAILED: %s\n  missing: [%s]\n' "${3:-assert_contains}" "$2" >&2
    exit 1
  fi
}

assert_not_contains() {
  _assert_tick
  if [[ "$1" == *"$2"* ]]; then
    printf 'ASSERTION FAILED: %s\n  found: [%s]\n' "${3:-assert_not_contains}" "$2" >&2
    exit 1
  fi
}

assert_file_contains() {
  _assert_tick
  if [ ! -f "$1" ]; then
    printf 'ASSERTION FAILED: %s\n  no such file: %s\n' "${3:-assert_file_contains}" "$1" >&2
    exit 1
  fi
  if ! grep -qaF -e "$2" -- "$1"; then
    printf 'ASSERTION FAILED: %s\n  %s does not contain: [%s]\n' "${3:-assert_file_contains}" "$1" "$2" >&2
    exit 1
  fi
}

assert_file_not_contains() {
  _assert_tick
  if [ -f "$1" ] && grep -qaF -e "$2" -- "$1"; then
    printf 'ASSERTION FAILED: %s\n  %s contains: [%s]\n' "${3:-assert_file_not_contains}" "$1" "$2" >&2
    exit 1
  fi
}

assert_tree_not_contains() {
  _assert_tick
  if [ -d "$1" ] && grep -rqaF -e "$2" -- "$1"; then
    printf 'ASSERTION FAILED: %s\n  found [%s] in:\n' "${3:-assert_tree_not_contains}" "$2" >&2
    grep -rlaF -e "$2" -- "$1" >&2 || true
    exit 1
  fi
}

assert_file_exists() {
  _assert_tick
  if [ ! -f "$1" ]; then
    printf 'ASSERTION FAILED: %s\n  no such file: %s\n' "${2:-assert_file_exists}" "$1" >&2
    exit 1
  fi
}

assert_no_file() {
  _assert_tick
  if [ -e "$1" ]; then
    printf 'ASSERTION FAILED: %s\n  exists: %s\n' "${2:-assert_no_file}" "$1" >&2
    exit 1
  fi
}

assert_json() {
  _assert_tick
  if ! jq -e "$2" "$1" > /dev/null 2>&1; then
    printf 'ASSERTION FAILED: %s\n  jq -e %s %s did not hold\n' "${3:-assert_json}" "$2" "$1" >&2
    exit 1
  fi
}

assert_line_eq() {
  _assert_tick
  local line
  if [ -f "$1" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      if [ "${line%$'\r'}" = "$2" ]; then
        return 0
      fi
    done < "$1"
  fi
  printf 'ASSERTION FAILED: %s\n  no line of %s equals: [%s]\n' "${3:-assert_line_eq}" "$1" "$2" >&2
  exit 1
}

_dump_run_output() {
  if [ -n "${RUN_STDOUT:-}" ] && [ -f "$RUN_STDOUT" ]; then
    printf -- '--- run.sh stdout ---\n' >&2
    cat "$RUN_STDOUT" >&2
  fi
  if [ -n "${RUN_STDERR:-}" ] && [ -f "$RUN_STDERR" ]; then
    printf -- '--- run.sh stderr ---\n' >&2
    cat "$RUN_STDERR" >&2
  fi
}

# ---------------------------------------------------------------- case setup

_sha256_of() {
  local line
  line="$(sha256sum "$1")"
  printf '%s\n' "${line%% *}"
}

pin_value() {
  sed -n "s/^$2=\\([^[:space:]]*\\)\$/\\1/p" "$1"
}

write_trivy_pin() {
  printf 'TRIVY_VERSION=%s\nTRIVY_SHA256_LINUX_64BIT=%s\nTRIVY_SHA256_LINUX_ARM64=%s\n' \
    "$1" "$2" "$3" > "$ACTION_COPY/bin/trivy.pin"
}

fake_trivy_sha() {
  _sha256_of "$SHIM_STATE/trivy.tar.gz"
}

_git() {
  git -C "$WS" "$@"
}

_refresh_sha() {
  local sha
  sha="$(_git rev-parse HEAD)"
  GITHUB_SHA="${sha%$'\r'}"
  export GITHUB_SHA
}

setup_case() {
  if [ -z "${TEST_TMP:-}" ]; then
    TEST_TMP="$(mktemp -d)"
    export TEST_TMP
  fi
  CASE_DIR="$(mktemp -d "$TEST_TMP/case.XXXXXX")"
  ACTION_COPY="$CASE_DIR/action"
  WS="$CASE_DIR/ws"
  SHIM_STATE="$CASE_DIR/shim"
  OUT_DIR="$CASE_DIR/out"
  export CASE_DIR ACTION_COPY WS SHIM_STATE OUT_DIR

  local v
  while IFS= read -r v; do
    case "$v" in
      GITHUB_*|RUNNER_*|ACTIONS_*|INPUT_*) unset "$v" ;;
    esac
  done < <(compgen -e)

  mkdir -p "$ACTION_COPY" "$SHIM_STATE/download" "$SHIM_STATE/token" \
    "$SHIM_STATE/api" "$SHIM_STATE/trivy-fixtures" "$OUT_DIR" \
    "$CASE_DIR/runner_temp" "$CASE_DIR/home" "$CASE_DIR/tmp"

  # Copy of the Action under test.
  if [ -f "$ACTION_ROOT/action.yml" ]; then
    cp "$ACTION_ROOT/action.yml" "$ACTION_COPY/action.yml"
  fi
  if [ -d "$ACTION_ROOT/bin" ]; then
    cp -R "$ACTION_ROOT/bin" "$ACTION_COPY/bin"
  else
    mkdir -p "$ACTION_COPY/bin"
  fi

  # Fake Trivy tarball, served by the curl shim, pinned in the copy.
  local version sha
  version="$(pin_value "$ACTION_ROOT/bin/trivy.pin" TRIVY_VERSION)"
  [ -n "$version" ] || version='0.0.0'
  printf '%s\n' "$version" > "$SHIM_STATE/trivy-version"
  bash "$FIXTURES_COMMON/build-fake-trivy.sh" "$SHIM_STATE" "$SHIM_STATE/trivy.tar.gz"
  cp "$SHIM_STATE/trivy.tar.gz" "$SHIM_STATE/download/file"
  sha="$(fake_trivy_sha)"
  write_trivy_pin "$version" "$sha" "$sha"
  cp "$FIXTURES_COMMON/trivy-report.json" "$SHIM_STATE/trivy-fixtures/json"
  cp "$FIXTURES_COMMON/sbom.cdx.json" "$SHIM_STATE/trivy-fixtures/cyclonedx"

  # OIDC token endpoint.
  printf '%s\n' "https://token.invalid/" > "$SHIM_STATE/token_url_prefix"
  printf '{"value":"%s"}\n' "$FAKE_JWT" > "$SHIM_STATE/token/body"
  printf '0\n' > "$SHIM_STATE/api/queued"

  # Isolated git identity and config.
  printf '[user]\n\tname = Alice\n\temail = alice@example.invalid\n[core]\n\tautocrlf = false\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n' \
    > "$CASE_DIR/gitconfig"
  export GIT_CONFIG_NOSYSTEM=1
  export GIT_CONFIG_GLOBAL="$CASE_DIR/gitconfig"

  mkdir -p "$WS"
  git init -q "$WS"
  _git symbolic-ref HEAD refs/heads/main
  printf '{"name":"fixture-app","version":"1.0.0"}\n' > "$WS/package.json"
  printf 'Fixture repository for tests.\n' > "$WS/README.md"
  _git add -A
  _git commit -q -m "initial fixture commit"
  _refresh_sha

  RUN_STDOUT="$OUT_DIR/stdout"
  RUN_STDERR="$OUT_DIR/stderr"
  : > "$RUN_STDOUT"
  : > "$RUN_STDERR"
  : > "$OUT_DIR/summary.md"
  : > "$OUT_DIR/github_output"
  RUN_RC=""
  export RUN_STDOUT RUN_STDERR

  export GITHUB_ACTIONS=true
  export GITHUB_EVENT_NAME=push
  export GITHUB_REF=refs/heads/main
  export GITHUB_REF_NAME=main
  export GITHUB_REF_TYPE=branch
  export GITHUB_REPOSITORY=example-org/example-repo
  export GITHUB_REPOSITORY_ID="$TEST_REPO_ID"
  export GITHUB_REPOSITORY_OWNER=example-org
  export GITHUB_REPOSITORY_OWNER_ID="$TEST_OWNER_ID"
  export GITHUB_ACTOR=alice-actor
  export GITHUB_TRIGGERING_ACTOR=alice-actor
  export GITHUB_SERVER_URL=https://github.com
  export GITHUB_API_URL=https://api.github.com
  export GITHUB_WORKSPACE="$WS"
  export GITHUB_EVENT_PATH="$CASE_DIR/event.json"
  export GITHUB_STEP_SUMMARY="$OUT_DIR/summary.md"
  export GITHUB_OUTPUT="$OUT_DIR/github_output"
  export GITHUB_ACTION_PATH="$ACTION_COPY"
  export RUNNER_TEMP="$CASE_DIR/runner_temp"
  export RUNNER_OS=Linux
  export RUNNER_ARCH=X64
  export ACTIONS_ID_TOKEN_REQUEST_URL="$TOKEN_URL"
  export ACTIONS_ID_TOKEN_REQUEST_TOKEN="$FAKE_REQUEST_TOKEN"
  export HOME="$CASE_DIR/home"
  export TMPDIR="$CASE_DIR/tmp"
  export SEETREX_TEST_SHIM_DIR="$SHIM_STATE"
  case ":$PATH:" in
    *":$TESTS_DIR/shims:"*) ;;
    *) export PATH="$TESTS_DIR/shims:$PATH" ;;
  esac

  make_event private
}

make_event() {
  local kind="${1:-private}" db="${2:-main}"
  local base
  # shellcheck disable=SC2016  # a jq program: $ref and $sha are jq variables
  base='{
    ref: $ref, after: $sha,
    repository: {
      id: $id, name: "example-repo", full_name: "example-org/example-repo",
      private: true, visibility: "private", default_branch: $db,
      owner: {login: "example-org", id: $oid}
    },
    pusher: {name: "alice-actor", email: "alice@example.invalid"},
    sender: {login: "alice-actor", id: 424242},
    head_commit: {
      id: $sha, message: "initial fixture commit",
      author: {name: "Alice", email: "alice@example.invalid", username: "alice-actor"},
      committer: {name: "Alice", email: "alice@example.invalid", username: "alice-actor"}
    }
  }'
  local mod
  case "$kind" in
    private) mod='.' ;;
    internal) mod='.repository.visibility = "internal"' ;;
    public) mod='.repository.private = false | .repository.visibility = "public"' ;;
    missing) mod='del(.repository.private)' ;;
    null) mod='.repository.private = null' ;;
    string) mod='.repository.private = "true"' ;;
    no-default-branch) mod='del(.repository.default_branch)' ;;
    unreadable)
      printf '{"repository": {"private": true, \n' > "$GITHUB_EVENT_PATH"
      return 0
      ;;
    absent)
      rm -f "$GITHUB_EVENT_PATH"
      return 0
      ;;
    *) fail "make_event: unknown kind '$kind'" ;;
  esac
  jq -n --arg ref "$GITHUB_REF" --arg sha "$GITHUB_SHA" --arg db "$db" \
    --argjson id "$TEST_REPO_ID" --argjson oid "$TEST_OWNER_ID" \
    "$base | $mod" > "$GITHUB_EVENT_PATH"
}

set_event_name() {
  export GITHUB_EVENT_NAME="$1"
}

set_ref() {
  export GITHUB_REF="$1"
  export GITHUB_REF_NAME="${1#refs/*/}"
}

commit_file() {
  local src="$1" rel="$2" msg="${3:-add $2}"
  mkdir -p "$(dirname "$WS/$rel")"
  cp "$src" "$WS/$rel"
  _git add -- "$rel"
  _git commit -q -m "$msg"
  _refresh_sha
}

commit_attestation() {
  local src="$1" name="${2:-}"
  [ -n "$name" ] || name="$(basename "$src")"
  commit_file "$src" ".seetrex/attestations/$name" "add attestation $name"
}

ws_put() {
  mkdir -p "$(dirname "$WS/$2")"
  cp "$1" "$WS/$2"
}

set_trivy_fixture() {
  case "$1" in
    json|cyclonedx) cp "$2" "$SHIM_STATE/trivy-fixtures/$1" ;;
    *) fail "set_trivy_fixture: unknown format '$1'" ;;
  esac
}

set_trivy_exit() {
  printf '%s\n' "$1" > "$SHIM_STATE/trivy-fixtures/exit_code"
}

set_download_file() {
  cp "$1" "$SHIM_STATE/download/file"
}

set_download_status() {
  printf '%s\n' "$1" > "$SHIM_STATE/download/status"
}

set_token_response() {
  printf '%s\n' "$1" > "$SHIM_STATE/token/status"
  cp "$2" "$SHIM_STATE/token/body"
}

_api_enqueue() {
  local n
  n="$(cat "$SHIM_STATE/api/queued")"
  n=$((n + 1))
  printf '%s\n' "$n" > "$SHIM_STATE/api/queued"
  printf '%s\n' "$n"
}

set_api_response() {
  local status="$1" body="$2" headers="${3:-}" n
  [[ "$status" =~ ^[1-5][0-9][0-9]$ ]] || fail "set_api_response: bad status '$status'"
  [ -f "$body" ] || fail "set_api_response: no such body file '$body'"
  n="$(_api_enqueue)"
  printf '%s\n' "$status" > "$SHIM_STATE/api/$n.status"
  cp "$body" "$SHIM_STATE/api/$n.body"
  if [ -n "$headers" ]; then
    cp "$headers" "$SHIM_STATE/api/$n.headers"
  fi
}

set_api_transport_error() {
  local code="${1:-7}" n
  n="$(_api_enqueue)"
  printf '000\n' > "$SHIM_STATE/api/$n.status"
  printf '%s\n' "$code" > "$SHIM_STATE/api/$n.exit"
}

reset_logs() {
  rm -rf "$SHIM_STATE/curl" "$SHIM_STATE/trivy.ran"
  : > "$SHIM_STATE/curl.log"
  : > "$SHIM_STATE/sleep.log"
  : > "$SHIM_STATE/tar.log"
  : > "$SHIM_STATE/trivy.log"
  : > "$RUN_STDOUT"
  : > "$RUN_STDERR"
  : > "$GITHUB_STEP_SUMMARY"
  : > "$GITHUB_OUTPUT"
}

# ---------------------------------------------------------------- running

run_action() {
  local -a envs=(
    INPUT_DRY_RUN=false INPUT_SUMMARY=full INPUT_STRICT=false
    INPUT_REQUEST_REPIN=false INPUT_REQUEST_CLOSE=false
  )
  local kv name val envname
  for kv in "$@"; do
    [[ "$kv" == *=* ]] || fail "run_action: argument '$kv' is not name=value"
    name="${kv%%=*}"
    val="${kv#*=}"
    [[ "$name" =~ ^[a-z][a-z0-9-]*$ ]] || fail "run_action: bad input name '$name'"
    envname="${name^^}"
    envname="INPUT_${envname//-/_}"
    envs+=("$envname=$val")
  done
  RUN_RC=0
  (
    cd "$GITHUB_WORKSPACE"
    exec env "${envs[@]}" bash "$GITHUB_ACTION_PATH/bin/run.sh"
  ) > "$RUN_STDOUT" 2> "$RUN_STDERR" || RUN_RC=$?
}

# ---------------------------------------------------------------- inspecting

curl_count() {
  local c=0
  if [ -f "$SHIM_STATE/curl/count" ]; then
    c="$(cat "$SHIM_STATE/curl/count")"
  fi
  printf '%s\n' "$c"
}

curl_log() {
  if [ -f "$SHIM_STATE/curl.log" ]; then
    cat "$SHIM_STATE/curl.log"
  fi
}

curl_call_dir() {
  printf '%s\n' "$SHIM_STATE/curl/$1"
}

curl_call() {
  local f="$SHIM_STATE/curl/$1/$2"
  if [ -f "$f" ]; then
    cat "$f"
  fi
}

curl_urls() {
  local i c
  c="$(curl_count)"
  for ((i = 1; i <= c; i++)); do
    curl_call "$i" url
  done
}

_count_urls_with_prefix() {
  local i c n=0 u
  c="$(curl_count)"
  for ((i = 1; i <= c; i++)); do
    u="$(curl_call "$i" url)"
    if [ "${u:0:${#1}}" = "$1" ]; then
      n=$((n + 1))
    fi
  done
  printf '%s\n' "$n"
}

api_call_count() {
  _count_urls_with_prefix 'https://api.seetrex.com/'
}

token_call_count() {
  _count_urls_with_prefix 'https://token.invalid/'
}

download_call_count() {
  _count_urls_with_prefix "$TRIVY_DOWNLOAD_PREFIX"
}

sleep_log() {
  if [ -f "$SHIM_STATE/sleep.log" ]; then
    cat "$SHIM_STATE/sleep.log"
  fi
}

sleep_count() {
  local n=0 line
  if [ -f "$SHIM_STATE/sleep.log" ]; then
    while IFS= read -r line; do
      n=$((n + 1))
    done < "$SHIM_STATE/sleep.log"
  fi
  printf '%s\n' "$n"
}

tar_count() {
  local n=0 line
  if [ -f "$SHIM_STATE/tar.log" ]; then
    while IFS= read -r line; do
      n=$((n + 1))
    done < "$SHIM_STATE/tar.log"
  fi
  printf '%s\n' "$n"
}

trivy_ran() {
  [ -f "$SHIM_STATE/trivy.ran" ]
}

trivy_invocations() {
  local n=0 line
  if [ -f "$SHIM_STATE/trivy.log" ]; then
    while IFS= read -r line; do
      if [ "$line" = "invocation" ]; then
        n=$((n + 1))
      fi
    done < "$SHIM_STATE/trivy.log"
  fi
  printf '%s\n' "$n"
}

# Prints the lines of invocation <n> that start with "<prefix> ", prefix removed.
_trivy_field() {
  local want="$1" prefix="$2" n=0 line
  [ -f "$SHIM_STATE/trivy.log" ] || return 0
  while IFS= read -r line; do
    if [ "$line" = "invocation" ]; then
      n=$((n + 1))
      continue
    fi
    if [ "$n" = "$want" ] && [ "${line:0:$((${#prefix} + 1))}" = "$prefix " ]; then
      printf '%s\n' "${line:$((${#prefix} + 1))}"
    fi
  done < "$SHIM_STATE/trivy.log"
}

trivy_args() {
  _trivy_field "$1" arg
}

trivy_cwd() {
  _trivy_field "$1" cwd
}

trivy_home() {
  _trivy_field "$1" home
}

trivy_env() {
  _trivy_field "$1" env
}

trivy_files() {
  _trivy_field "$1" file
}

trivy_reads() {
  _trivy_field "$1" reads
}

github_output_value() {
  sed -n "s/^$1=//p" "$GITHUB_OUTPUT"
}
