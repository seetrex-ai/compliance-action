# shellcheck shell=bash
# Dynamic tests of bin/run.sh: each runs the Action against the shims of
# tests/lib.sh (no network). Control requests (repin/close) live in
# tests/test_control.sh.

FIXTURES_RUN="$TESTS_DIR/fixtures/run"

# Number of the last curl call made to api.seetrex.com (empty if none).
_last_api_call() {
  local i c last=""
  c="$(curl_count)"
  for ((i = 1; i <= c; i++)); do
    case "$(curl_call "$i" url)" in
      https://api.seetrex.com/*) last="$i" ;;
    esac
  done
  printf '%s\n' "$last"
}

# Path of the body file of the last API call; fails the test if there is none.
_last_api_body() {
  local n
  n="$(_last_api_call)"
  [ -n "$n" ] || fail "no call to api.seetrex.com was made"
  printf '%s\n' "$(curl_call_dir "$n")/body"
}

# _big_trivy <entries> <out>: a synthetic Trivy report; each entry reduces to
# ~1 KB of canonical JSON (long FixedVersion, few characters to escape).
_big_trivy() {
  jq -n --argjson n "$1" '{
    SchemaVersion: 2,
    Results: [{
      Target: "fixture-lock.json",
      Vulnerabilities: [range(0; $n) | {
        VulnerabilityID: "FIXTURE-\(.)", PkgName: "fixture-pkg", Severity: "LOW",
        PublishedDate: "2099-01-01T00:00:00Z", FixedVersion: ("9." + ("0" * 900))
      }]
    }]
  }' > "$2"
}

# _big_sbom <components> <out>: a synthetic CycloneDX SBOM; each component is
# ~1 KB (long name, few characters to escape).
_big_sbom() {
  jq -n --argjson n "$1" '{
    bomFormat: "CycloneDX", specVersion: "1.6",
    metadata: {component: {"bom-ref": "fixture-root", type: "application", name: "."}},
    components: [range(0; $n) | {
      "bom-ref": "c\(.)", type: "library", version: "1.0.0",
      name: ("fixture-\(.)-" + ("x" * 950))
    }]
  }' > "$2"
}

_file_bytes() {
  local n
  n="$(wc -c < "$1")"
  printf '%s\n' "${n//[[:space:]]/}"
}

# Canonical size (jq -cS, no newline) of a raw report after bin/filters/trivy.jq.
_reduced_trivy_bytes() {
  jq -c -f "$ACTION_COPY/bin/filters/trivy.jq" < "$1" > "$CASE_DIR/reduced.json"
  jq -cjS . "$CASE_DIR/reduced.json" > "$CASE_DIR/reduced.canonical"
  _file_bytes "$CASE_DIR/reduced.canonical"
}

# Compact size (no newline) of a raw SBOM after bin/filters/sbom.jq: a lower
# bound of its string in the body (escaping only adds bytes).
_reduced_sbom_bytes() {
  jq -c -f "$ACTION_COPY/bin/filters/sbom.jq" < "$1" | tr -d '\r\n' > "$CASE_DIR/reduced-sbom.json"
  _file_bytes "$CASE_DIR/reduced-sbom.json"
}

_assert_no_digits() {
  local hit
  hit="$(grep -n '[0-9]' "$1" || true)"
  assert_eq "" "$hit" "$2"
}

_assert_no_record() {
  assert_file_not_contains "$GITHUB_OUTPUT" "record=" "$1: no record output"
  assert_no_file "$RUNNER_TEMP/seetrex-out/seetrex-record.json" "$1: no record file"
}

test_intent_attestations_read_from_commit_tree() {
  # INTENT: only the attestations committed at GITHUB_SHA are sent (regular
  # *.json blobs directly under .seetrex/attestations/), never what sits in the
  # worktree: the server takes the provenance from the token's sha.
  # CONTEXT: plan D1 §1 (provenance = token sha) and §3 step 13.
  # EXPIRES IF: the server reads the attestations from the commit itself.
  setup_case
  local body
  commit_attestation "$FIXTURES_RUN/attestation-a.json" a.json
  commit_file "$FIXTURES_RUN/attestation-b.json" .seetrex/attestations/sub/nested.json
  printf 'not an attestation\n' > "$CASE_DIR/notes.txt"
  commit_file "$CASE_DIR/notes.txt" .seetrex/attestations/notes.txt
  ws_put "$FIXTURES_RUN/attestation-a-modified.json" .seetrex/attestations/a.json
  ws_put "$FIXTURES_RUN/attestation-b.json" .seetrex/attestations/b.json
  make_event private
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 0
  body="$(_last_api_body)"
  assert_json "$body" '.attestations | length == 1' "exactly one attestation sent"
  assert_eq "$(cat "$FIXTURES_RUN/attestation-a.json")" "$(jq -r '.attestations[0]' "$body")" \
    "the attestation is A as committed, byte for byte"
  assert_file_not_contains "$body" "MODIFIED" "the worktree edit of A is not sent"
  assert_file_not_contains "$body" "never committed" "the uncommitted B is not sent"
  assert_file_not_contains "$body" "not an attestation" "non-json files are not sent"

  # More than 32 committed attestations: nothing is sent.
  setup_case
  local i
  for ((i = 1; i <= 33; i++)); do
    commit_attestation "$FIXTURES_RUN/attestation-a.json" "a$i.json"
  done
  make_event private
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 1
  assert_eq 0 "$(api_call_count)" "33 attestations: no POST"
  assert_eq 0 "$(token_call_count)" "33 attestations: no token"
}

test_intent_action_never_sends_user_identity() {
  # INTENT: nothing identifying the person who pushed leaves the runner: no
  # URL, header or body of any request carries the pusher's name, email or
  # login, although the event, git and the environment all hold them.
  # CONTEXT: plan D1 §4 (identity test); dynamic half (static half in
  # test_static.sh).
  # EXPIRES IF: never (privacy promise of the README).
  local run i c needle part
  for run in push repin; do
    setup_case
    commit_attestation "$FIXTURES_RUN/attestation-a.json" a.json
    make_event private
    if [ "$run" = push ]; then
      set_api_response 200 "$FIXTURES_RUN/resp-200.json"
      run_action
    else
      set_api_response 200 "$FIXTURES_RUN/resp-control.json"
      run_action request-repin=true
    fi
    assert_rc 0
    c="$(curl_count)"
    assert_ne 0 "$c" "$run: the run made requests"
    assert_ne 0 "$(api_call_count)" "$run: the run reached Seetrex"
    for ((i = 1; i <= c; i++)); do
      for part in url headers body argv; do
        for needle in alice example.invalid alice-actor; do
          assert_file_not_contains "$(curl_call_dir "$i")/$part" "$needle" \
            "$run: call $i $part carries '$needle'"
        done
      done
    done
  done
}

test_intent_log_of_run_with_findings_has_no_cve_nor_package() {
  # INTENT: the job log and summary never name a finding (CVE/GHSA id or
  # package), and the OIDC token appears nowhere but in its own ::add-mask::
  # command; nothing left in RUNNER_TEMP holds it, and Trivy never sees the
  # runner's token variables.
  # CONTEXT: plan D1 §4; the log of a private repo can be read by more people
  # than its results should reach, and a JWT on disk outlives the step.
  # EXPIRES IF: never.
  setup_case
  local needle mode leftover
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  for mode in full counters dry; do
    reset_logs
    if [ "$mode" = dry ]; then
      run_action dry-run=true
    else
      run_action summary="$mode"
    fi
    assert_rc 0
    for needle in CVE-2099-0001 GHSA-2222-3333-4444 left-pad-fixture; do
      assert_file_not_contains "$RUN_STDOUT" "$needle" "$mode: stdout names a finding"
      assert_file_not_contains "$RUN_STDERR" "$needle" "$mode: stderr names a finding"
      assert_file_not_contains "$GITHUB_STEP_SUMMARY" "$needle" "$mode: summary names a finding"
    done
    sed '/^::add-mask::/d' "$RUN_STDOUT" > "$CASE_DIR/stdout.unmasked"
    for needle in "$FAKE_JWT" "$FAKE_REQUEST_TOKEN"; do
      assert_file_not_contains "$CASE_DIR/stdout.unmasked" "$needle" "$mode: a token outside ::add-mask::"
      assert_file_not_contains "$RUN_STDERR" "$needle" "$mode: a token on stderr"
      assert_file_not_contains "$GITHUB_STEP_SUMMARY" "$needle" "$mode: a token in the summary"
      assert_file_not_contains "$GITHUB_OUTPUT" "$needle" "$mode: a token in the outputs"
      assert_tree_not_contains "$RUNNER_TEMP" "$needle" "$mode: a token left in RUNNER_TEMP"
    done
    leftover="$(compgen -G "$RUNNER_TEMP/seetrex-work.*" || true)"
    assert_eq "" "$leftover" "$mode: the work directory is removed"
    assert_not_contains "$(trivy_env 1)" ACTIONS_ID_TOKEN_REQUEST "$mode: trivy saw the token variables"
    assert_not_contains "$(trivy_env 1)" GITHUB_ "$mode: trivy saw GITHUB_* variables"
  done
  # The non-dry runs did mask the JWT before using it.
  reset_logs
  run_action
  assert_line_eq "$RUN_STDOUT" "::add-mask::$FAKE_JWT" "the JWT is masked"
}

test_intent_public_repo_exits_with_fixed_line_and_no_counts() {
  # INTENT: on a repository that is not provably private (private false,
  # missing, null, a string, unreadable or absent event), the Action prints
  # the fixed line, exits 0, prints no count, contacts nobody and never runs
  # Trivy, in dry-run as well.
  # CONTEXT: plan D1 §3 step 3 (D-R12, H-R16): the summary of a public repo is
  # public.
  # EXPIRES IF: public repositories become a supported target.
  setup_case
  local kind dry
  for kind in public missing null string unreadable absent; do
    for dry in false true; do
      make_event private
      make_event "$kind"
      set_api_response 200 "$FIXTURES_RUN/resp-200.json"
      reset_logs
      run_action dry-run="$dry"
      assert_rc 0
      assert_line_eq "$RUN_STDOUT" "$L_PUBLIC" "$kind/dry=$dry: fixed line"
      _assert_no_digits "$RUN_STDOUT" "$kind/dry=$dry: stdout has digits"
      _assert_no_digits "$GITHUB_STEP_SUMMARY" "$kind/dry=$dry: summary has digits"
      assert_eq 0 "$(curl_count)" "$kind/dry=$dry: no curl"
      if trivy_ran; then fail "$kind/dry=$dry: trivy ran"; fi
      _assert_no_record "$kind/dry=$dry"
    done
  done
}

test_intent_no_artifact_nor_results_without_a_200() {
  # INTENT: without a 200 carrying JSON, the Action keeps no record (no output,
  # no file, so no artifact) and renders no result, even when the error body
  # carries `results` and a `record` of this repository.
  # CONTEXT: plan D1 §3 step 18; an error page or a proxy answer must never be
  # taken for Seetrex's verdict.
  # EXPIRES IF: never.
  local status
  for status in 400 401 403 408 409 413 429 500 503 transport html; do
    setup_case
    case "$status" in
      transport) set_api_transport_error 7 ;;
      html) set_api_response 200 "$FIXTURES_RUN/resp-html.html" ;;
      *) set_api_response "$status" "$FIXTURES_RUN/resp-error-with-results.json" ;;
    esac
    run_action
    assert_ne 0 "$(api_call_count)" "$status: the POST was attempted"
    _assert_no_record "$status"
    assert_file_not_contains "$GITHUB_STEP_SUMMARY" "cra-" "$status: summary renders an obligation"
    assert_file_not_contains "$GITHUB_STEP_SUMMARY" "VIOLATED" "$status: summary renders an outcome"
    assert_file_not_contains "$RUN_STDOUT" "cra-" "$status: log renders an obligation"
    assert_file_not_contains "$RUN_STDOUT" "VIOLATED" "$status: log renders an outcome"
    assert_file_not_contains "$RUN_STDOUT" "Seetrex recorded this push." "$status: claims success"
  done
}

test_intent_summary_counters_keeps_results_out_of_the_summary() {
  # INTENT: with summary: counters, neither the filter nor a full run puts an
  # outcome, an obligation id, the legend, the skipped categories or the scan
  # date into the job summary.
  # CONTEXT: plan D1 §4; README: the summary shows how much the record grew,
  # never a result.
  # EXPIRES IF: the summary modes are redesigned.
  local needle
  local -a needles=(outcome VIOLATED SATISFIED cra- "Fixture legend" skipped vuln_scan scan_created_at 2099-02-28)
  setup_case
  jq -r -f "$ACTION_COPY/bin/filters/summary_counters.jq" "$FIXTURES_RUN/resp-200.json" > "$CASE_DIR/counters.md"
  assert_ne "" "$(cat "$CASE_DIR/counters.md")" "the filter prints something"
  for needle in "${needles[@]}"; do
    assert_file_not_contains "$CASE_DIR/counters.md" "$needle" "filter: '$needle'"
  done
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action summary=counters
  assert_rc 0
  assert_ne "" "$(cat "$GITHUB_STEP_SUMMARY")" "the run writes a summary"
  for needle in "${needles[@]}"; do
    assert_file_not_contains "$GITHUB_STEP_SUMMARY" "$needle" "run: '$needle'"
  done
  assert_file_exists "$RUNNER_TEMP/seetrex-out/seetrex-record.json" "the record is still kept"
}

test_intent_dry_run_contacts_no_seetrex_endpoint_and_no_oidc() {
  # INTENT: dry-run downloads and runs Trivy but asks for no token and sends
  # nothing: the only request is the Trivy download; it even works without
  # the id-token permission, which a real run requires (fixed line).
  # CONTEXT: plan D1 §3 steps 15-16.
  # EXPIRES IF: dry-run is removed.
  setup_case
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action dry-run=true
  assert_rc 0
  assert_eq 1 "$(curl_count)" "one request"
  assert_eq 1 "$(download_call_count)" "it is the Trivy download"
  assert_eq 0 "$(token_call_count)" "no OIDC token"
  assert_eq 0 "$(api_call_count)" "no Seetrex call"
  if ! trivy_ran; then fail "dry-run did not scan"; fi
  # What the report shows (plan §3 step 15): files with size and sha256 as
  # they would be sent, the body keys, and the component and vulnerability
  # counts of the default fixtures (1 component, 2 report entries).
  local sbom_str
  sbom_str="$CASE_DIR/expected-sbom"
  jq -c -f "$ACTION_COPY/bin/filters/sbom.jq" < "$FIXTURES_COMMON/sbom.cdx.json" | tr -d '\r\n' > "$sbom_str"
  assert_line_eq "$RUN_STDOUT" "- sbom: $(_file_bytes "$sbom_str") bytes, sha256 $(sha256sum < "$sbom_str" | cut -d' ' -f1)" \
    "the dry-run report lists the sbom with its size and sha256"
  assert_file_contains "$RUN_STDOUT" "- trivy: " "the dry-run report lists the report file"
  assert_file_contains "$RUN_STDOUT" "- request body: " "the dry-run report lists the body"
  assert_line_eq "$RUN_STDOUT" "Body keys: sbom, trivy" "the dry-run report lists the body keys"
  assert_line_eq "$RUN_STDOUT" "- SBOM components (every level): 1" "component count"
  assert_line_eq "$RUN_STDOUT" "- vulnerability report entries: 2" "vulnerability count"
  assert_file_contains "$GITHUB_STEP_SUMMARY" "Body keys: sbom, trivy" "the report is in the summary too"
  _assert_no_record "dry-run"

  unset ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN
  reset_logs
  run_action dry-run=true
  assert_rc 0
  assert_eq 0 "$(api_call_count)" "no permission, dry-run: no Seetrex call"
  reset_logs
  run_action
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "$L_NO_OIDC" "no permission: fixed line"
  assert_eq 0 "$(api_call_count)" "no permission: no Seetrex call"
  assert_eq 0 "$(token_call_count)" "no permission: no token call"
}

test_intent_non_default_ref_sends_nothing() {
  # INTENT: a push to any branch but the default one (or an event without a
  # default branch, or a non-push event) is not scanned: fixed line, exit 0,
  # no request, Trivy never runs.
  # CONTEXT: plan D1 §3 steps 4-5: the server registers one branch per repo.
  # EXPIRES IF: the server accepts several branches per repository.
  setup_case
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  local dry
  set_ref refs/heads/feature
  for dry in false true; do
    reset_logs
    run_action dry-run="$dry"
    assert_rc 0
    assert_line_eq "$RUN_STDOUT" "$L_NON_DEFAULT" "feature/dry=$dry: fixed line"
    assert_eq 0 "$(curl_count)" "feature/dry=$dry: no curl"
    if trivy_ran; then fail "feature/dry=$dry: trivy ran"; fi
  done

  set_ref refs/heads/main
  make_event no-default-branch
  reset_logs
  run_action
  assert_rc 0
  assert_line_eq "$RUN_STDOUT" "$L_NON_DEFAULT" "no default branch: fixed line"
  assert_eq 0 "$(curl_count)" "no default branch: no curl"
  if trivy_ran; then fail "no default branch: trivy ran"; fi

  make_event private
  set_event_name pull_request
  reset_logs
  run_action
  assert_rc 0
  assert_line_eq "$RUN_STDOUT" "$L_NOT_PUSH" "pull_request: fixed line"
  assert_eq 0 "$(curl_count)" "pull_request: no curl"
}

test_intent_trivy_download_fails_on_wrong_sha256() {
  # INTENT: a Trivy download that does not match the pinned sha256 is never
  # extracted nor run, and nothing is sent; the fixed line says why.
  # CONTEXT: plan D1 §3 step 9; supply-chain audit (hijacked Trivy 0.69.4).
  # EXPIRES IF: the Action stops downloading Trivy.
  setup_case
  local version bad
  version="$(pin_value "$ACTION_COPY/bin/trivy.pin" TRIVY_VERSION)"
  bad="$(printf 'a%.0s' {1..64})"
  write_trivy_pin "$version" "$bad" "$bad"
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "$L_TRIVY_SHA" "altered pin: fixed line"
  assert_eq 1 "$(download_call_count)" "altered pin: downloaded once"
  if trivy_ran; then fail "altered pin: trivy ran"; fi
  assert_eq 0 "$(token_call_count)" "altered pin: no token"
  assert_eq 0 "$(api_call_count)" "altered pin: no POST"

  # Right pin, tampered download.
  setup_case
  printf 'not the pinned tarball\n' > "$CASE_DIR/tampered.tar.gz"
  set_download_file "$CASE_DIR/tampered.tar.gz"
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "$L_TRIVY_SHA" "tampered download: fixed line"
  if trivy_ran; then fail "tampered download: trivy ran"; fi
  assert_eq 0 "$(api_call_count)" "tampered download: no POST"
}

test_intent_body_contains_only_declared_fields() {
  # INTENT: the push body carries only the fields the server declares
  # (deny_unknown_fields): sbom, trivy, attestations, trivy_left_out; the
  # last only as `true` and never with trivy; body_check.jq refuses more.
  # CONTEXT: plan D1 §1 (ActionPushRequest) and §2 (trivy_left_out).
  # EXPIRES IF: the server's request schema changes.
  setup_case
  local body rc
  local allowed='(keys - ["sbom","trivy","attestations","trivy_left_out"]) == []'
  commit_attestation "$FIXTURES_RUN/attestation-a.json" a.json
  make_event private
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 0
  body="$(_last_api_body)"
  assert_json "$body" "$allowed" "only declared keys"
  assert_json "$body" '(.sbom | type) == "string" and (.trivy | type) == "string"' "documents are strings"
  assert_json "$body" '(.attestations | type) == "array" and all(.attestations[]; type == "string")' "attestations are strings"
  assert_json "$body" 'has("trivy_left_out") | not' "no trivy_left_out when the report is sent"
  rc=0
  jq -n -e -f "$ACTION_COPY/bin/filters/body_check.jq" < "$body" > /dev/null 2>&1 || rc=$?
  assert_eq 0 "$rc" "body_check accepts the real body"

  jq -c '. + {extra: 1}' "$body" > "$CASE_DIR/extra.json"
  rc=0
  jq -n -e -f "$ACTION_COPY/bin/filters/body_check.jq" < "$CASE_DIR/extra.json" > /dev/null 2>&1 || rc=$?
  assert_ne 0 "$rc" "body_check refuses an extra key"
  jq -c '. + {trivy_left_out: true}' "$body" > "$CASE_DIR/both.json"
  rc=0
  jq -n -e -f "$ACTION_COPY/bin/filters/body_check.jq" < "$CASE_DIR/both.json" > /dev/null 2>&1 || rc=$?
  assert_ne 0 "$rc" "body_check refuses trivy with trivy_left_out"
  jq -c 'del(.trivy) + {trivy_left_out: false}' "$body" > "$CASE_DIR/false.json"
  rc=0
  jq -n -e -f "$ACTION_COPY/bin/filters/body_check.jq" < "$CASE_DIR/false.json" > /dev/null 2>&1 || rc=$?
  assert_ne 0 "$rc" "body_check refuses trivy_left_out: false"

  # Left out: trivy_left_out is true and trivy is absent.
  setup_case
  _big_trivy 1200 "$CASE_DIR/big-trivy.json"
  set_trivy_fixture json "$CASE_DIR/big-trivy.json"
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 0
  body="$(_last_api_body)"
  assert_json "$body" "$allowed" "left out: only declared keys"
  assert_json "$body" '.trivy_left_out == true and (has("trivy") | not)' "left out: flag true, no trivy"
}

test_intent_scan_that_does_not_fit_is_left_out_before_sending() {
  # INTENT: the Action measures before sending: (a) a reduced report whose
  # canonical form exceeds 1 MiB, or (b) a body over 3 MiB, is sent without the
  # report and with trivy_left_out: true (fixed line); (c) if even that does
  # not fit, nothing is sent.
  # CONTEXT: plan D1 §2 (A4 C-1: an oversize scan never mints a verdict) and
  # §3 step 14; the server caps the body at 3,145,728 bytes.
  # EXPIRES IF: the server's caps change.
  local body size

  # (a) canonical report over 1 MiB.
  setup_case
  _big_trivy 1200 "$CASE_DIR/big-trivy.json"
  size="$(_reduced_trivy_bytes "$CASE_DIR/big-trivy.json")"
  [ "$size" -gt 1048576 ] || fail "(a) fixture too small: $size"
  set_trivy_fixture json "$CASE_DIR/big-trivy.json"
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 0
  body="$(_last_api_body)"
  assert_json "$body" '.trivy_left_out == true and (has("trivy") | not) and (.sbom | type) == "string"' "(a) left out"
  assert_line_eq "$RUN_STDOUT" "$L_LEFT_OUT" "(a) fixed line"

  # (b) report under 1 MiB, but the body would exceed 3 MiB with it.
  setup_case
  _big_trivy 880 "$CASE_DIR/trivy-b.json"
  size="$(_reduced_trivy_bytes "$CASE_DIR/trivy-b.json")"
  [ "$size" -le 1048576 ] || fail "(b) report must fit its own cap: $size"
  _big_sbom 2400 "$CASE_DIR/sbom-b.json"
  # Measured with the real filters: the two reduced documents together
  # exceed the body cap (a lower bound of the body with the report), while
  # the SBOM alone leaves room for escaping and the attestations list.
  local sbom_size
  sbom_size="$(_reduced_sbom_bytes "$CASE_DIR/sbom-b.json")"
  [ $((sbom_size + size)) -gt 3145728 ] || fail "(b) with the report the body would fit: $sbom_size + $size"
  [ "$sbom_size" -le 2621440 ] || fail "(b) the SBOM alone is too close to the cap: $sbom_size"
  set_trivy_fixture json "$CASE_DIR/trivy-b.json"
  set_trivy_fixture cyclonedx "$CASE_DIR/sbom-b.json"
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 0
  body="$(_last_api_body)"
  assert_json "$body" '.trivy_left_out == true and (has("trivy") | not) and (.sbom | type) == "string"' "(b) left out"
  size="$(_file_bytes "$body")"
  [ "$size" -le 3145728 ] || fail "(b) body over the cap: $size"
  assert_ne 0 "$size" "(b) body measured"
  assert_line_eq "$RUN_STDOUT" "$L_LEFT_OUT" "(b) fixed line"

  # (c) the SBOM alone does not fit.
  setup_case
  _big_sbom 3400 "$CASE_DIR/sbom-c.json"
  sbom_size="$(_reduced_sbom_bytes "$CASE_DIR/sbom-c.json")"
  [ "$sbom_size" -gt 3145728 ] || fail "(c) the reduced SBOM alone fits: $sbom_size"
  set_trivy_fixture cyclonedx "$CASE_DIR/sbom-c.json"
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "$L_TOO_LARGE" "(c) fixed line"
  assert_eq 0 "$(api_call_count)" "(c) no POST"
  assert_eq 0 "$(token_call_count)" "(c) no token"
}

test_intent_sbom_subject_name_does_not_depend_on_workdir() {
  # INTENT: Trivy scans `.` from the workspace, so the runner's path never
  # names the subject; two workspaces at different paths send byte-identical
  # sbom strings.
  # CONTEXT: plan D1 §3 step 10 (finding 4 of M1): real Trivy names the SBOM
  # subject (metadata.component.name) after its path argument. The fake Trivy
  # models that: @SCANARG@ in the fixture becomes its path argument, so a run
  # that scanned "$GITHUB_WORKSPACE" instead of `.` would send the path.
  # EXPIRES IF: the Action stops scanning the workspace with Trivy.
  local first_ws case n args
  jq '.metadata.component.name = "@SCANARG@"' "$FIXTURES_COMMON/sbom.cdx.json" \
    > "$TEST_TMP/sbom-scanarg.cdx.json"
  for case in 1 2; do
    setup_case
    if [ "$case" = 1 ]; then
      first_ws="$WS"
    else
      assert_ne "$first_ws" "$WS" "two different workspaces"
    fi
    set_trivy_fixture cyclonedx "$TEST_TMP/sbom-scanarg.cdx.json"
    set_api_response 200 "$FIXTURES_RUN/resp-200.json"
    run_action
    assert_rc 0
    jq -j '.sbom' "$(_last_api_body)" > "$TEST_TMP/sbom-$case"
    assert_json "$TEST_TMP/sbom-$case" '.metadata.component.name == "."' \
      "case $case: the subject is named after the path argument ."
    assert_file_not_contains "$TEST_TMP/sbom-$case" "$WS" "case $case: the workspace path is in the sbom"
    for n in 1 2; do
      args="$(trivy_args "$n")"
      assert_eq "." "$(printf '%s\n' "$args" | tail -n 1)" "case $case, scan $n: the path argument is ."
      assert_not_contains "$args" "$WS" "case $case, scan $n: the workspace path is not an argument"
      assert_eq "$WS" "$(trivy_cwd "$n")" "case $case, scan $n: runs in the workspace"
    done
  done
  assert_eq "$(sha256sum < "$TEST_TMP/sbom-1")" "$(sha256sum < "$TEST_TMP/sbom-2")" \
    "byte-identical sbom from both workspaces"
}

test_intent_401_on_default_ref_prints_the_fixed_line() {
  # INTENT: a 401 (owner not admitted, or branch not the registered one) ends
  # with the single fixed line and exit 1, without retrying.
  # CONTEXT: plan D1 §1 (D-R18: one line for both cases).
  # EXPIRES IF: the server distinguishes the two causes.
  setup_case
  set_api_response 401 "$FIXTURES_RUN/resp-401.json"
  run_action
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "$L_401" "fixed line"
  assert_eq 1 "$(api_call_count)" "one POST"
  assert_eq 0 "$(sleep_count)" "no retry"
  _assert_no_record "401"
}

test_intent_large_record_goes_through_files_only() {
  # INTENT: a record of ~900 KB is handled from files only (never argv, whose
  # per-argument limit is far below that): it is kept byte-equivalent to the
  # answer's .record and announced through GITHUB_OUTPUT.
  # CONTEXT: plan D1 §1 (record up to ~880 KB) and §3 step 18.
  # EXPIRES IF: the record stops travelling in the push answer.
  setup_case
  local path i c
  jq '.record.padding = ("p" * 900000)' "$FIXTURES_RUN/resp-200.json" > "$CASE_DIR/resp-big.json"
  set_api_response 200 "$CASE_DIR/resp-big.json"
  run_action
  assert_rc 0
  path="$(github_output_value record)"
  assert_eq "$RUNNER_TEMP/seetrex-out/seetrex-record.json" "$path" "record output"
  assert_file_exists "$path"
  jq -S . "$path" > "$CASE_DIR/got.json"
  jq -S .record "$CASE_DIR/resp-big.json" > "$CASE_DIR/want.json"
  assert_eq "$(sha256sum < "$CASE_DIR/want.json")" "$(sha256sum < "$CASE_DIR/got.json")" "record kept intact"
  c="$(curl_count)"
  for ((i = 1; i <= c; i++)); do
    [ "$(_file_bytes "$(curl_call_dir "$i")/argv")" -lt 8192 ] || fail "call $i has a large argv"
  done
  assert_ne 0 "$c" "requests were made"

  # A record of another repository is not kept.
  setup_case
  jq '.record.slug = "gh-1"' "$FIXTURES_RUN/resp-200.json" > "$CASE_DIR/resp-other.json"
  set_api_response 200 "$CASE_DIR/resp-other.json"
  run_action
  assert_rc 1
  _assert_no_record "foreign record"
}

# _retry_case <expected api calls> <expected sleep log> <expected rc> [inputs...]
# Runs the Action with the answers queued by the caller.
_retry_case() {
  local calls="$1" sleeps="$2" want_rc="$3"
  shift 3
  run_action "$@"
  assert_eq "$calls" "$(api_call_count)" "api calls"
  assert_eq "$sleeps" "$(sleep_log | tr '\n' ' ' | sed 's/ $//')" "waits"
  assert_rc "$want_rc"
}

test_intent_retries_with_backoff_only_when_the_server_asks() {
  # INTENT: the POST is retried (at most 3 attempts, waiting 10 s then 30 s)
  # only on 503, 429 rate_limited, 408, 5xx, a non-JSON answer or a transport
  # failure; never on new_repository_budget_reached or a 4xx verdict. Our own
  # outage or a quota only warns, unless strict.
  # CONTEXT: plan D1 §3 steps 17 and 19 (D-R12).
  # EXPIRES IF: the server's idempotency (action_router.rs:319-326) goes away.
  setup_case
  set_api_response 503 "$FIXTURES_RUN/resp-503.json"
  set_api_response 503 "$FIXTURES_RUN/resp-503.json"
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  _retry_case 3 "10 30" 0
  assert_file_exists "$RUNNER_TEMP/seetrex-out/seetrex-record.json" "503,503,200: kept"

  setup_case
  set_api_response 200 "$FIXTURES_RUN/resp-html.html"
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  _retry_case 2 "10" 0

  local s
  for s in 408 500 502 503; do
    setup_case
    set_api_response "$s" "$FIXTURES_RUN/resp-503.json"
    _retry_case 3 "10 30" 0
    assert_file_contains "$RUN_STDOUT" "::warning::" "$s: warns"
  done

  setup_case
  set_api_response 429 "$FIXTURES_RUN/resp-429-rate.json"
  _retry_case 3 "10 30" 0
  setup_case
  set_api_response 429 "$FIXTURES_RUN/resp-429-rate.json"
  _retry_case 3 "10 30" 1 strict=true

  setup_case
  set_api_transport_error 7
  _retry_case 3 "10 30" 0
  setup_case
  set_api_transport_error 28
  _retry_case 3 "10 30" 1 strict=true

  setup_case
  printf 'Retry-After: 3600\n' > "$CASE_DIR/h429"
  set_api_response 429 "$FIXTURES_RUN/resp-429-budget.json" "$CASE_DIR/h429"
  _retry_case 1 "" 0
  setup_case
  set_api_response 429 "$FIXTURES_RUN/resp-429-budget.json"
  _retry_case 1 "" 1 strict=true

  for s in 400 401 403 409 413; do
    setup_case
    set_api_response "$s" "$FIXTURES_RUN/resp-401.json"
    _retry_case 1 "" 1
  done

  # quota: reached on a 200: kept, warned, green unless strict.
  setup_case
  jq '.quota = "reached"' "$FIXTURES_RUN/resp-200.json" > "$CASE_DIR/quota.json"
  set_api_response 200 "$CASE_DIR/quota.json"
  _retry_case 1 "" 0
  assert_file_contains "$RUN_STDOUT" "::warning::" "quota: warns"
  setup_case
  jq '.quota = "reached"' "$FIXTURES_RUN/resp-200.json" > "$CASE_DIR/quota.json"
  set_api_response 200 "$CASE_DIR/quota.json"
  _retry_case 1 "" 1 strict=true
}

test_intent_action_never_contacts_api_github_com() {
  # INTENT: every request goes to the Trivy release download, the runner's
  # OIDC token service or Seetrex's push route; never to the GitHub API.
  # CONTEXT: plan D1 §4 extras; dynamic half (static half in test_static.sh).
  # EXPIRES IF: the Action is redesigned to need the GitHub API.
  local run url
  for run in push dry repin close; do
    setup_case
    commit_attestation "$FIXTURES_RUN/attestation-a.json" a.json
    make_event private
    case "$run" in
      push) set_api_response 200 "$FIXTURES_RUN/resp-200.json"; run_action ;;
      dry) run_action dry-run=true ;;
      repin) set_api_response 200 "$FIXTURES_RUN/resp-control.json"; run_action request-repin=true ;;
      close) set_api_response 200 "$FIXTURES_RUN/resp-control.json"; run_action request-close=true ;;
    esac
    assert_rc 0
    assert_ne 0 "$(curl_count)" "$run: requests were made"
    while IFS= read -r url; do
      case "$url" in
        "$TRIVY_DOWNLOAD_PREFIX"*|https://token.invalid/*|"$SEETREX_PUSH_URL") ;;
        *) fail "$run: unexpected request to $url" ;;
      esac
    done < <(curl_urls)
    assert_not_contains "$(curl_log)" "api.github.com" "$run: GitHub API contacted"
  done
}
