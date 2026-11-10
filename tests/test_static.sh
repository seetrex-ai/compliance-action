# shellcheck shell=bash
# Static tests: read the Action's files, never run bin/run.sh. Plus two
# self-tests of the harness (fake Trivy tarball and shims).
#
# The dynamic halves of the identity and api.github.com tests live in
# tests/test_run.sh under the unsuffixed names
# (test_intent_action_never_sends_user_identity,
#  test_intent_action_never_contacts_api_github_com); the static halves here
# carry the suffix __static so the names stay unique.

# The static scans read action.yml and every file under bin/.
# Fails the test if action.yml or bin/run.sh is missing.
_static_action_files() {
  [ -f "$ACTION_ROOT/action.yml" ] || fail "action.yml does not exist yet"
  [ -f "$ACTION_ROOT/bin/run.sh" ] || fail "bin/run.sh does not exist yet"
}

# Asserts that no file among action.yml and bin/** contains <needle>.
_static_assert_absent() {
  local needle="$1" why="$2"
  assert_file_not_contains "$ACTION_ROOT/action.yml" "$needle" "action.yml: $why"
  assert_tree_not_contains "$ACTION_ROOT/bin" "$needle" "bin/: $why"
}

# Checks every `uses:` of a workflow/action YAML file; prints nothing.
# Each must be `<owner>/<repo>[/path]@<40 hex>` (optional trailing comment).
_static_check_uses() {
  local file="$1" total=0 parsed=0 line val
  assert_file_exists "$file"
  # shellcheck disable=SC2094  # $file is only read; basename never opens it
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [[ "$line" == *uses:* ]] || continue
    total=$((total + 1))
    if [[ "$line" =~ ^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*(.*)$ ]]; then
      parsed=$((parsed + 1))
      val="${BASH_REMATCH[2]}"
      val="${val%%#*}"
      val="${val%"${val##*[![:space:]]}"}"
      val="${val#\"}"
      val="${val%\"}"
      val="${val#\'}"
      val="${val%\'}"
      if ! [[ "$val" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$ ]]; then
        fail "$(basename "$file"): 'uses: $val' is not pinned by a 40-hex commit SHA"
      fi
    fi
  done < "$file"
  assert_eq "$total" "$parsed" "$(basename "$file"): every line mentioning uses: is a plain 'uses: <ref>' entry"
  assert_ne 0 "$total" "$(basename "$file"): has at least one uses:"
}

_static_check_trivy_pin() {
  local pin="$ACTION_ROOT/bin/trivy.pin" line n_ver=0 n_64=0 n_arm=0 version=""
  assert_file_exists "$pin" "bin/trivy.pin exists"
  assert_file_not_contains "$pin" $'\r' "bin/trivy.pin has LF line endings"
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ ^TRIVY_VERSION=([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
      n_ver=$((n_ver + 1))
      version="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^TRIVY_SHA256_LINUX_64BIT=[0-9a-f]{64}$ ]]; then
      n_64=$((n_64 + 1))
    elif [[ "$line" =~ ^TRIVY_SHA256_LINUX_ARM64=[0-9a-f]{64}$ ]]; then
      n_arm=$((n_arm + 1))
    else
      fail "bin/trivy.pin: unexpected line [$line]"
    fi
  done < "$pin"
  assert_eq 1 "$n_ver" "bin/trivy.pin: exactly one TRIVY_VERSION=<x.y.z>"
  assert_eq 1 "$n_64" "bin/trivy.pin: exactly one TRIVY_SHA256_LINUX_64BIT=<64 hex>"
  assert_eq 1 "$n_arm" "bin/trivy.pin: exactly one TRIVY_SHA256_LINUX_ARM64=<64 hex>"
  # 0.69.4 is the hijacked release (audit-C-externo.md:106).
  assert_ne 0.69.4 "$version" "bin/trivy.pin: never the hijacked Trivy 0.69.4"
}

test_intent_action_refs_pinned_by_sha() {
  # INTENT: every third-party action the Action or its CI runs is pinned by an
  # immutable commit SHA, and the Trivy binary by version + sha256 (never the
  # hijacked 0.69.4), so a moved tag cannot change what runs.
  # CONTEXT: plan §4 (D1) and the supply-chain audit of 2026-10-30.
  # EXPIRES IF: the Action stops using third-party actions and Trivy.
  _static_check_uses "$ACTION_ROOT/.github/workflows/ci.yml"
  _static_check_trivy_pin
  assert_file_exists "$ACTION_ROOT/action.yml" "action.yml exists"
  _static_check_uses "$ACTION_ROOT/action.yml"
}

test_intent_action_never_contacts_api_github_com__static() {
  # INTENT: the Action talks to github.com only to download Trivy and to the
  # runner's OIDC service; never to the GitHub API (no token, no API URL).
  # CONTEXT: plan §4 extras; static half (the dynamic half reads the curl log).
  # EXPIRES IF: the Action is redesigned to need the GitHub API.
  _static_action_files
  local needle
  for needle in api.github.com github.api_url GITHUB_API_URL \
    GITHUB_GRAPHQL_URL github.graphql_url github.token GITHUB_TOKEN 'secrets.' \
    'gh api'; do
    _static_assert_absent "$needle" "mentions '$needle'"
  done
}

test_intent_action_never_sends_user_identity__static() {
  # INTENT: nothing identifying a person leaves the runner beyond the claims
  # of the OIDC token itself (actor, actor_id, sub, repository_owner,
  # workflow, ref, sha, run_id, event_name...); the Action does not even read
  # the GitHub token, secrets, the actor or the pusher.
  # CONTEXT: plan §4 (identity test); static half.
  # EXPIRES IF: never (privacy promise of the README).
  _static_action_files
  local needle
  for needle in github.token GITHUB_TOKEN 'secrets.' github.actor GITHUB_ACTOR \
    github.triggering_actor GITHUB_TRIGGERING_ACTOR '.pusher' '.sender' \
    'head_commit' 'user.email' 'user.name' '%ae' '%an' '%ce' '%cn' \
    '%aE' '%aN' '%cE' '%cN'; do
    _static_assert_absent "$needle" "mentions '$needle'"
  done
}

test_intent_harness_fake_trivy_is_pinned_served_and_logged() {
  # INTENT: the harness serves a fake Trivy whose sha256 is the one pinned in
  # the case copy, and the fake writes fixtures by --format, honours @CWD@
  # and @SCANARG@, logs argv/cwd/env names and leaves a marker; otherwise
  # every Trivy test of U3 would pass or fail for the wrong reason.
  # CONTEXT: plan §4 (lib.sh, curl shim, fake trivy).
  # EXPIRES IF: the tests stop using a fake Trivy.
  setup_case
  local version url sha rc
  version="$(pin_value "$ACTION_COPY/bin/trivy.pin" TRIVY_VERSION)"
  assert_eq "$(pin_value "$ACTION_ROOT/bin/trivy.pin" TRIVY_VERSION)" "$version" "copy keeps the real version"
  sha="$(fake_trivy_sha)"
  assert_eq "$sha" "$(pin_value "$ACTION_COPY/bin/trivy.pin" TRIVY_SHA256_LINUX_64BIT)" "64bit pin = fake sha"
  assert_eq "$sha" "$(pin_value "$ACTION_COPY/bin/trivy.pin" TRIVY_SHA256_LINUX_ARM64)" "arm64 pin = fake sha"
  assert_ne "$(pin_value "$ACTION_ROOT/bin/trivy.pin" TRIVY_SHA256_LINUX_64BIT)" "$sha" "real pin untouched"

  url="${TRIVY_DOWNLOAD_PREFIX}v${version}/trivy_${version}_Linux-64bit.tar.gz"
  curl -fsSL -o "$RUNNER_TEMP/trivy.tar.gz" "$url"
  assert_eq "$sha" "$(_sha256_of "$RUNNER_TEMP/trivy.tar.gz")" "served tarball matches the pin"
  assert_eq 1 "$(download_call_count)" "one download logged"
  assert_eq "$url" "$(curl_call 1 url)" "download URL logged"
  if trivy_ran; then fail "marker present before any run"; fi

  mkdir -p "$RUNNER_TEMP/trivy-bin"
  tar -xzf "$RUNNER_TEMP/trivy.tar.gz" -C "$RUNNER_TEMP/trivy-bin"
  assert_file_exists "$RUNNER_TEMP/trivy-bin/trivy"

  printf '{"metadata":{"component":{"name":"@CWD@","purl":"@SCANARG@"}}}\n' > "$CASE_DIR/cdx.json"
  set_trivy_fixture cyclonedx "$CASE_DIR/cdx.json"
  (
    cd "$WS" || exit 1
    env -i PATH="$PATH" HOME="$HOME" "$RUNNER_TEMP/trivy-bin/trivy" fs --scanners vuln \
      --format json --quiet --output "$RUNNER_TEMP/out.json" .
    env -i PATH="$PATH" HOME="$HOME" "$RUNNER_TEMP/trivy-bin/trivy" fs \
      --format cyclonedx --output "$RUNNER_TEMP/sbom.json" .
  )
  if ! trivy_ran; then fail "marker absent after a run"; fi
  assert_eq "$(cat "$FIXTURES_COMMON/trivy-report.json")" "$(cat "$RUNNER_TEMP/out.json")" "json fixture written"
  assert_json "$RUNNER_TEMP/sbom.json" ".metadata.component.name == \"$WS\"" "@CWD@ replaced by the cwd"
  assert_json "$RUNNER_TEMP/sbom.json" '.metadata.component.purl == "."' "@SCANARG@ replaced by the path argument"
  assert_eq 2 "$(trivy_invocations)" "two invocations logged"
  assert_eq "$WS" "$(trivy_cwd 1)" "cwd logged"
  assert_eq "fs|--scanners|vuln|--format|json|--quiet|--output|$RUNNER_TEMP/out.json|." \
    "$(trivy_args 1 | tr '\n' '|' | sed 's/|$//')" "argv logged"
  assert_not_contains "$(trivy_env 1)" ACTIONS_ID_TOKEN_REQUEST_TOKEN "env -i honoured in the env log"
  assert_contains "$(trivy_env 1)" PATH "env names logged"

  rc=0
  "$RUNNER_TEMP/trivy-bin/trivy" fs --format sarif . > /dev/null 2>&1 || rc=$?
  assert_eq 2 "$rc" "unsupported format exits 2"
  rc=0
  set_trivy_exit 3
  "$RUNNER_TEMP/trivy-bin/trivy" fs --format json --output "$RUNNER_TEMP/forced.json" . 2> /dev/null || rc=$?
  assert_eq 3 "$rc" "forced exit code"
  assert_no_file "$RUNNER_TEMP/forced.json" "forced exit writes nothing"
  assert_eq "Version: $version" "$("$RUNNER_TEMP/trivy-bin/trivy" --version)" "--version"
}

test_intent_harness_curl_and_sleep_shims_never_reach_the_network() {
  # INTENT: the curl shim answers the OIDC token URL and a queue of API
  # answers, logs headers and body (with @file expanded), and refuses every
  # other host; the sleep shim never waits. Tests stay offline and fast.
  # CONTEXT: plan §4 (no network in tests).
  # EXPIRES IF: the tests stop using shims.
  setup_case
  local rc code hdr body
  assert_eq "$TESTS_DIR/shims/curl" "$(command -v curl)" "curl resolves to the shim"

  hdr="$CASE_DIR/hdr"
  printf 'Authorization: Bearer %s\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" > "$hdr"
  curl -sS -H @"$hdr" -o "$CASE_DIR/tok.json" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https%3A%2F%2Fapi.seetrex.com"
  assert_json "$CASE_DIR/tok.json" ".value == \"$FAKE_JWT\"" "token served"
  assert_eq 1 "$(token_call_count)"
  assert_line_eq "$(curl_call_dir 1)/headers" "Authorization: Bearer $FAKE_REQUEST_TOKEN" "@file header expanded"

  printf '{"error":"unavailable"}\n' > "$CASE_DIR/r503.json"
  printf '{"ok":true}\n' > "$CASE_DIR/r200.json"
  printf 'Retry-After: 3600\n' > "$CASE_DIR/h429"
  set_api_response 503 "$CASE_DIR/r503.json"
  set_api_response 429 "$CASE_DIR/r503.json" "$CASE_DIR/h429"
  set_api_response 200 "$CASE_DIR/r200.json"
  set_api_transport_error 28
  set_api_response 401 "$CASE_DIR/r503.json"
  body="$CASE_DIR/body.json"
  printf '{"sbom":"x"}' > "$body"

  code="$(curl -sS --max-time 60 -H 'Content-Type: application/json' --data-binary @"$body" \
    -o "$CASE_DIR/resp" -w '%{http_code}' "$SEETREX_PUSH_URL")"
  assert_eq 503 "$code"
  assert_eq '{"sbom":"x"}' "$(curl_call 2 body)" "body logged from @file"
  assert_eq POST "$(curl_call 2 method)"
  code="$(curl -sS -D "$CASE_DIR/dump" --data-binary @"$body" -o "$CASE_DIR/resp" -w '%{http_code}' "$SEETREX_PUSH_URL")"
  assert_eq 429 "$code"
  assert_line_eq "$CASE_DIR/dump" 'Retry-After: 3600' "response headers dumped"
  code="$(curl -sS --data-binary @"$body" -o "$CASE_DIR/resp" -w '%{http_code}' "$SEETREX_PUSH_URL")"
  assert_eq 200 "$code"
  assert_eq '{"ok":true}' "$(cat "$CASE_DIR/resp")"
  rc=0
  code="$(curl -sS --data-binary @"$body" -o "$CASE_DIR/resp" -w '%{http_code}' "$SEETREX_PUSH_URL" 2> /dev/null)" || rc=$?
  assert_eq 28 "$rc" "transport error exit code"
  assert_eq 000 "$code" "transport error write-out"
  code="$(curl -sS --data-binary @"$body" -o "$CASE_DIR/resp" -w '%{http_code}' "$SEETREX_PUSH_URL")"
  assert_eq 401 "$code"
  code="$(curl -sS --data-binary @"$body" -o "$CASE_DIR/resp" -w '%{http_code}' "$SEETREX_PUSH_URL")"
  assert_eq 401 "$code" "last answer repeats"
  rc=0
  curl -fsS --data-binary @"$body" -o "$CASE_DIR/resp" "$SEETREX_PUSH_URL" 2> /dev/null || rc=$?
  assert_eq 22 "$rc" "-f turns >=400 into exit 22"
  assert_eq 7 "$(api_call_count)"

  rc=0
  curl -sS https://api.github.com/repos/x 2> /dev/null || rc=$?
  assert_eq 6 "$rc" "unknown host refused"
  assert_file_contains "$SHIM_STATE/curl.log" "GET https://api.github.com/repos/x -> 000 exit=6"
  assert_eq 9 "$(curl_count)"

  sleep 30
  sleep 10
  assert_eq 2 "$(sleep_count)"
  assert_eq $'30\n10' "$(sleep_log)"

  reset_logs
  assert_eq 0 "$(curl_count)" "reset_logs clears curl"
  assert_eq 0 "$(sleep_count)" "reset_logs clears sleep"

  # Fresh case: an empty API queue is a transport failure.
  setup_case
  rc=0
  curl -sS --data-binary @"$body" "$SEETREX_PUSH_URL" > /dev/null 2>&1 || rc=$?
  assert_eq 7 "$rc" "no queued answer = transport error"
}

# _yaml_run_bodies <file> <out>: writes to <out> the command text of every
# `run:` of a workflow/action YAML file: the value of a one-line `run:`, or
# every line of a `run: |` / `run: >` block. Prints the number of run steps.
_yaml_run_bodies() {
  local file="$1" out="$2" line ind=-1 cur val n=0
  : > "$out"
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    if [ "$ind" -ge 0 ]; then
      cur="${line%%[![:space:]]*}"
      if [ -z "${line//[[:space:]]/}" ] || [ "${#cur}" -gt "$ind" ]; then
        printf '%s\n' "$line" >> "$out"
        continue
      fi
      ind=-1
    fi
    if [[ "$line" =~ ^([[:space:]]*)(-[[:space:]]+)?run:[[:space:]]*(.*)$ ]]; then
      n=$((n + 1))
      val="${BASH_REMATCH[3]}"
      cur=$((${#BASH_REMATCH[1]} + ${#BASH_REMATCH[2]}))
      if [[ "$val" =~ ^[\|\>][-+]?$ ]]; then
        ind="$cur"
      else
        printf '%s\n' "$val" >> "$out"
      fi
    fi
  done < "$file"
  printf '%s\n' "$n"
}

# shellcheck disable=SC2016  # literal text of the Action's files
test_intent_hostile_inputs_never_interpolated_in_run__static() {
  # INTENT: no `run:` of action.yml contains a `${{ }}` expression: inputs
  # reach run.sh only as env variables, so a hostile input is data, never
  # shell text the runner pastes into a script.
  # CONTEXT: review B-I4 of D1 (expression injection in composite actions).
  # EXPIRES IF: the Action stops being a composite action.
  _static_action_files
  local n
  n="$(_yaml_run_bodies "$ACTION_ROOT/action.yml" "$TEST_TMP/action-run")"
  assert_ne 0 "$n" "action.yml has run steps"
  assert_file_not_contains "$TEST_TMP/action-run" '${{' "a run: of action.yml interpolates an expression"
  assert_file_not_contains "$TEST_TMP/action-run" 'inputs.' "a run: of action.yml names an input"
}

# shellcheck disable=SC2016  # literal text of the Action's files
test_intent_run_step_drops_bash_env_and_cleans_up__static() {
  # INTENT: the run step starts run.sh with BASH_ENV removed and run.sh turns
  # tracing off as its first statement; the last step removes the output AND
  # the work directories, under `if: always()`, so the Action declares no
  # output naming a file it deletes; the Trivy database cache is keyed per
  # day, not per run (one saved cache a day instead of one per push).
  # CONTEXT: review B-I5, A-M4 and A-M3 of D1; A-I8 and B-M6 of the second
  # review.
  # EXPIRES IF: the steps of action.yml are redesigned.
  _static_action_files
  local line first=""
  _yaml_run_bodies "$ACTION_ROOT/action.yml" "$TEST_TMP/action-run" > /dev/null
  assert_line_eq "$TEST_TMP/action-run" 'env -u BASH_ENV bash "$GITHUB_ACTION_PATH/bin/run.sh"' \
    "run.sh is started without BASH_ENV"
  assert_line_eq "$TEST_TMP/action-run" 'rm -rf -- "$RUNNER_TEMP/seetrex-out" "$RUNNER_TEMP"/seetrex-work.*' \
    "the last step removes the output and work directories"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      '#'*|'') continue ;;
      *) first="$line"; break ;;
    esac
  done < "$ACTION_ROOT/bin/run.sh"
  assert_eq 'set +x' "$first" "the first statement of run.sh turns tracing off"
  # The cleanup step runs whatever happened before it (review B-M6).
  sed -n '/^    - name: Remove the Seetrex output and work directories$/,/^    - /p' \
    "$ACTION_ROOT/action.yml" > "$TEST_TMP/cleanup-step"
  assert_line_eq "$TEST_TMP/cleanup-step" '      if: always()' "the cleanup step runs always"
  # The upload runs even when run.sh failed after writing the record (a
  # summary that could not be rendered, review A-M5 of the third review).
  sed -n '/^    - name: Upload the Seetrex record$/,/^    - /p' \
    "$ACTION_ROOT/action.yml" > "$TEST_TMP/upload-step"
  assert_line_eq "$TEST_TMP/upload-step" "      if: always() && steps.seetrex.outputs.record != ''" \
    "the upload step runs always when there is a record"
  # No `record` output of the Action: the cleanup step deletes the file it
  # would name (review A-I8); the upload step reads the step's own output.
  assert_eq 0 "$(grep -c '^outputs:' "$ACTION_ROOT/action.yml" || true)" "action.yml declares no outputs"
  assert_file_contains "$ACTION_ROOT/action.yml" 'path: ${{ steps.seetrex.outputs.record }}' "the upload reads the step output"
  assert_file_not_contains "$ACTION_ROOT/action.yml" "run_id" "the cache key is not per run"
  assert_file_contains "$ACTION_ROOT/action.yml" \
    'key: seetrex-trivy-db-${{ runner.os }}-${{ runner.arch }}-${{ steps.seetrex-day.outputs.day }}' \
    "the cache key is per day"
}

# shellcheck disable=SC2016  # literal text of the Action's files
test_intent_secrets_stay_private_masked_and_https_only__static() {
  # INTENT: run.sh creates its files 600 (umask 077, and chmod 600 on both
  # header files), masks the request token and the JWT, and every curl
  # ignores .curlrc (-q first) and is https-only; the CI reads the repository
  # only, keeps no credentials, pipes nothing and blocks on the Trivy pin.
  # CONTEXT: review B-M1, B-M4 and B-M6 of D1.
  # EXPIRES IF: the Action stops handling tokens in bash or stops using curl.
  _static_action_files
  local run="$ACTION_ROOT/bin/run.sh" ci="$ACTION_ROOT/.github/workflows/ci.yml"
  local line n_curl=0 n_checkout n_persist n
  assert_line_eq "$run" 'umask 077' "umask 077"
  assert_file_contains "$run" 'chmod 600 "$WORK/token-request.hdr"' "request header file 600"
  assert_file_contains "$run" 'chmod 600 "$WORK/auth.hdr"' "auth header file 600"
  assert_file_contains "$run" "printf '::add-mask::%s\\n' \"\$ACTIONS_ID_TOKEN_REQUEST_TOKEN\"" "request token masked"
  assert_file_contains "$run" "printf '::add-mask::%s\\n' \"\$jwt\"" "JWT masked"
  while IFS= read -r line || [ -n "$line" ]; do
    [[ "$line" =~ (^|[[:space:]\(])curl[[:space:]] ]] || continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    n_curl=$((n_curl + 1))
    assert_contains "$line" "curl -q " "run.sh: -q first: $line"
    assert_contains "$line" "--proto '=https'" "run.sh: https only: $line"
    assert_contains "$line" "--max-time " "run.sh: time limit: $line"
  done < "$run"
  assert_eq 3 "$n_curl" "run.sh has three curl calls"

  assert_line_eq "$ci" 'permissions:' "ci.yml: workflow permissions"
  assert_line_eq "$ci" '  contents: read' "ci.yml: contents: read"
  assert_file_not_contains "$ci" 'write' "ci.yml: no write permission"
  n_checkout="$(grep -c 'uses: actions/checkout@' "$ci" || true)"
  n_persist="$(grep -c 'persist-credentials: false' "$ci" || true)"
  assert_ne 0 "${n_checkout%$'\r'}" "ci.yml: checks out"
  assert_eq "${n_checkout%$'\r'}" "${n_persist%$'\r'}" "ci.yml: every checkout drops the credentials"
  assert_file_not_contains "$ci" 'continue-on-error' "ci.yml: every job blocks"
  n="$(_yaml_run_bodies "$ci" "$TEST_TMP/ci-run")"
  assert_ne 0 "$n" "ci.yml has run steps"
  # A pipe hands the step the exit code of its last command; `||` is no pipe.
  sed 's/||//g' "$TEST_TMP/ci-run" > "$TEST_TMP/ci-run.nor"
  assert_file_not_contains "$TEST_TMP/ci-run.nor" '|' "ci.yml: a run step pipes"
  while IFS= read -r line || [ -n "$line" ]; do
    [[ "$line" =~ (^|[[:space:]\(])curl[[:space:]] ]] || continue
    assert_contains "$line" "curl -q " "ci.yml: -q first: $line"
    assert_contains "$line" "--proto '=https'" "ci.yml: https only: $line"
  done < "$TEST_TMP/ci-run"
}

test_intent_executable_files_keep_their_bit_in_the_index() {
  # INTENT: the files that are run as commands are committed with mode 100755,
  # so a fresh checkout on Linux can execute them: the shims are found on PATH
  # only if executable (without the bit the real curl, sleep and tar would run
  # and reach the network), run.sh and run_all.sh are the documented entry
  # points, and the fake Trivy scripts are the harness's own commands.
  # CONTEXT: D1 debt: the bit lives only in git's index; a commit from a
  # checkout without core.fileMode (Windows) can drop it unnoticed.
  # EXPIRES IF: the listed files are moved or are no longer run as commands.
  # Every file under tests/shims/ is taken from the index, so a new shim is
  # covered without editing this list.
  local f mode out shims=()
  out="$TEST_TMP/ls-files"
  git -C "$ACTION_ROOT" ls-files -s -- bin tests > "$out"
  while IFS= read -r f; do
    shims+=("$f")
  done < <(awk '{ sub(/\r$/, "") } $NF ~ /^tests\/shims\// { print $NF }' "$out")
  assert_ne 0 "${#shims[@]}" "tests/shims/ holds files in the git index"
  for f in bin/run.sh tests/run_all.sh tests/shims/curl tests/shims/sleep tests/shims/tar "${shims[@]}" \
    tests/fixtures/common/build-fake-trivy.sh tests/fixtures/common/fake-trivy.sh; do
    mode="$(awk -v p="$f" '{ sub(/\r$/, "") } $NF == p { print $1 }' "$out")"
    assert_eq 100755 "$mode" "$f is executable in the git index"
  done
}

test_intent_public_texts_avoid_the_closed_list_of_claims() {
  # INTENT: the README and action.yml never carry a claim the service does
  # not make: a compliance verdict on the user ("CRA-ready", "compliant",
  # "non-compliant"), exclusivity ("nobody else", "no one else"), a retention
  # or a publication of results ("retained", "we keep your", "publish if you
  # want", "Trust Center"), or an unqualified offline guarantee ("verifiable
  # offline", "tamper-proof"), nor, since the proposal step, a claim on what
  # the reader is ("verified", "AI-powered", "no model participates", "each
  # fact is signed by a person": a model proposes, a person commits). The
  # list is closed, case insensitive, and read as plain text; a phrase the
  # README needs in a negation ("no badge", "the only credential") is not on
  # it.
  # CONTEXT: external audit E of 2026-11-04 (C1, I1-I5) and plan E2+V2-b §5:
  # the same list guards the presentation script; plan R4 §5 and amendment
  # #334 point 6 for the reader's phrases.
  # EXPIRES IF: the service starts making one of these claims for real, with
  # its measure; then the phrase leaves the list in the same commit.
  _static_action_files
  assert_file_exists "$ACTION_ROOT/README.md" "README.md exists"
  # Both sides are lower-cased with tr instead of grep -i: on some grep builds
  # -i together with -F aborts, and a swallowed abort would read as 0 hits.
  local phrase needle f hits rc
  tr '[:upper:]' '[:lower:]' < "$ACTION_ROOT/README.md" > "$TEST_TMP/readme.lc"
  tr '[:upper:]' '[:lower:]' < "$ACTION_ROOT/action.yml" > "$TEST_TMP/action.lc"
  for phrase in 'CRA-ready' 'CRA ready' 'CRA compliant' 'CRA-compliant' \
    'complies with the CRA' 'compliant with the CRA' 'non-compliant' 'you comply' \
    'nobody else' 'no one else' \
    'is retained' 'are retained' 'we keep your' 'we retain' \
    'publish if you want' 'Trust Center' \
    'verifiable offline' 'tamper-proof' 'tamperproof' \
    'compliant' 'verified' 'AI-powered' \
    'no model participates' 'each fact is signed by a person'; do
    needle="$(printf '%s' "$phrase" | tr '[:upper:]' '[:lower:]')"
    for f in readme action; do
      rc=0
      hits="$(grep -c -F -- "$needle" "$TEST_TMP/$f.lc")" || rc=$?
      [ "$rc" -le 1 ] || fail "$f: grep failed (rc=$rc) on the phrase [$phrase]"
      assert_eq 0 "${hits%$'\r'}" "$f: carries the phrase [$phrase]"
    done
  done
}

test_intent_public_texts_never_name_the_model_provider() {
  # INTENT: no file of this public repository names the model provider or a
  # model of its: the README and the data policy say "an external LLM
  # provider", a category of recipient, never a brand. The names are kept
  # here base64-encoded so that this file does not carry them either; each
  # is matched case insensitively as a substring of every file of the tree.
  # CONTEXT: amendment #334 point 6 (founder, 2026-11-09) and plan R4 §5:
  # "an external LLM provider", without a brand, in README, policy, tests and
  # public comments.
  # EXPIRES IF: the founder decides to name the provider publicly; then the
  # names leave this list in the same commit as the README sentence.
  _static_action_files
  local enc name pat rc hits
  for enc in YW50aHJvcGlj Y2xhdWRl b3B1cw== c29ubmV0 aGFpa3U=; do
    name="$(printf '%s' "$enc" | base64 -d | tr -d '\r')"
    [ -n "$name" ] || fail "a provider name did not decode"
    # [aA][nN]... : case insensitive without grep -i (see the test above).
    pat="$(printf '%s' "$name" | sed 's/./[\U&\L&]/g')"
    [ "$pat" != "$name" ] || fail "the case-insensitive pattern was not built"
    rc=0
    hits="$(grep -r -l -a -E --exclude-dir=.git --exclude=.git -- "$pat" "$ACTION_ROOT")" || rc=$?
    [ "$rc" -le 1 ] || fail "grep failed (rc=$rc) on a provider name"
    assert_eq "" "${hits%$'\r'}" "files naming the model provider or one of its models"
  done
}
