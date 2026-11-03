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
  # INTENT: nothing identifying the person who pushed leaves the runner; the
  # Action does not even read the token, secrets, the actor or the pusher.
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
  # the case copy, and the fake writes fixtures by --format, honours @CWD@,
  # logs argv/cwd/env names and leaves a marker; otherwise every Trivy test of
  # U3 would pass or fail for the wrong reason.
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

  printf '{"metadata":{"component":{"name":"@CWD@"}}}\n' > "$CASE_DIR/cdx.json"
  set_trivy_fixture cyclonedx "$CASE_DIR/cdx.json"
  (
    cd "$WS"
    env -i PATH="$PATH" HOME="$HOME" "$RUNNER_TEMP/trivy-bin/trivy" fs --scanners vuln \
      --format json --quiet --output "$RUNNER_TEMP/out.json" .
    env -i PATH="$PATH" HOME="$HOME" "$RUNNER_TEMP/trivy-bin/trivy" fs \
      --format cyclonedx --output "$RUNNER_TEMP/sbom.json" .
  )
  if ! trivy_ran; then fail "marker absent after a run"; fi
  assert_eq "$(cat "$FIXTURES_COMMON/trivy-report.json")" "$(cat "$RUNNER_TEMP/out.json")" "json fixture written"
  assert_json "$RUNNER_TEMP/sbom.json" ".metadata.component.name == \"$WS\"" "@CWD@ replaced by the cwd"
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
