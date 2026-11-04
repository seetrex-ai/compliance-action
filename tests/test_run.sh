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

_sha() {
  local line
  line="$(sha256sum < "$1")"
  printf '%s
' "${line%% *}"
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

# No tar call and nothing extracted anywhere under RUNNER_TEMP.
_assert_nothing_extracted() {
  local found
  assert_eq 0 "$(tar_count)" "$1: tar was called"
  found="$(find "$RUNNER_TEMP" \( -name trivy -o -name trivy-bin -o -name LICENSE \) -print)"
  assert_eq "" "$found" "$1: something was extracted"
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
  # The Action still succeeds with a modified worktree, and Trivy scanned
  # the commit: A as committed, no trace of the uncommitted B.
  local n
  for n in 1 2; do
    trivy_files "$n" > "$CASE_DIR/files-$n"
    assert_line_eq "$CASE_DIR/files-$n" ".seetrex/attestations/a.json $(_sha "$FIXTURES_RUN/attestation-a.json")"       "scan $n: A as committed"
    assert_file_not_contains "$CASE_DIR/files-$n" ".seetrex/attestations/b.json" "scan $n: the uncommitted B"
  done

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

  # Exactly 32 (one commit): all are sent (review A-M4).
  setup_case
  mkdir -p "$WS/.seetrex/attestations"
  for ((i = 1; i <= 32; i++)); do
    cp "$FIXTURES_RUN/attestation-a.json" "$WS/.seetrex/attestations/a$i.json"
  done
  git -C "$WS" add -A
  git -C "$WS" commit -q -m "32 attestations"
  GITHUB_SHA="$(git -C "$WS" rev-parse HEAD | tr -d '\r')"
  export GITHUB_SHA
  make_event private
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 0
  assert_json "$(_last_api_body)" '.attestations | length == 32' "32 attestations: all sent"

  # A pretty-printed attestation (several lines) travels as one string, byte
  # for byte (review A-I4 of the third review): sha256 of the committed file
  # = sha256 of the string sent (jq on Windows writes CRLF; the fixture has
  # no CR, so CRs are dropped before hashing).
  setup_case
  commit_attestation "$FIXTURES_RUN/attestation-pretty.json" pretty.json
  make_event private
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 0
  body="$(_last_api_body)"
  assert_json "$body" '.attestations | length == 1' "pretty: one attestation"
  jq -j '.attestations[0]' "$body" > "$CASE_DIR/sent.raw"
  tr -d '\r' < "$CASE_DIR/sent.raw" > "$CASE_DIR/sent.json"
  assert_eq "$(_sha "$FIXTURES_RUN/attestation-pretty.json")" "$(_sha "$CASE_DIR/sent.json")" \
    "pretty: the string sent is the committed file, byte for byte"
}

test_intent_action_never_sends_user_identity() {
  # INTENT: nothing identifying a person leaves the runner beyond the claims
  # of the OIDC token itself (which GitHub fills with actor, actor_id, sub,
  # repository_owner, workflow, ref, sha, run_id, event_name...): no URL,
  # header, argument or body the Action builds carries the pusher's name,
  # email or login, although the event, git and the environment all hold them.
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
  assert_line_eq "$RUN_STDOUT" "::add-mask::$FAKE_REQUEST_TOKEN" "the request token is masked"
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
  # CONTEXT: plan D1 §4; README: the summary shows only how many obligations
  # are in each status, never a result.
  # EXPIRES IF: the summary modes are redesigned.
  local needle
  local -a needles=(outcome VIOLATED SATISFIED cra- "kept as history" "The engine" skipped vuln_scan scan_created_at 2099-02-28)
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

  # Components nested two levels deep are counted at every level (review
  # A-M6): 2 at the top, 2 under the first, 1 under that one's first.
  setup_case
  set_trivy_fixture cyclonedx "$FIXTURES_RUN/sbom-nested-levels.cdx.json"
  run_action dry-run=true
  assert_rc 0
  assert_line_eq "$RUN_STDOUT" "- SBOM components (every level): 5" "nested component count"
}

test_intent_dry_run_counts_an_sbom_with_malformed_components_without_failing() {
  # INTENT: a dry run whose SBOM has, in a `components` list, an entry that
  # is not an object (an array, a string), or a `components` that is not a
  # list, still exits 0 and describes the body: the component count becomes a
  # fixed text instead of a number (no crash, no silent miscount).
  # CONTEXT: D1 debt: the count crashed with a jq error (exit 5) on an array
  # entry, a shape Trivy does not generate; a real run would send that SBOM
  # (the server refuses it), so the dry run must describe it, as dry_run.jq
  # does with values of unexpected types.
  # EXPIRES IF: the dry-run report stops counting SBOM components.
  local shape label
  for shape in array string object; do
    setup_case
    case "$shape" in
      array) jq -n '{bomFormat: "CycloneDX", specVersion: "1.6",
               components: [{name: "fixture-a"}, [{name: "fixture-b"}]]}' > "$CASE_DIR/sbom.json" ;;
      string) jq -n '{bomFormat: "CycloneDX", specVersion: "1.6",
               components: [{name: "fixture-a", components: ["fixture-b"]}]}' > "$CASE_DIR/sbom.json" ;;
      object) jq -n '{bomFormat: "CycloneDX", specVersion: "1.6",
               components: {name: "fixture-a"}}' > "$CASE_DIR/sbom.json" ;;
    esac
    set_trivy_fixture cyclonedx "$CASE_DIR/sbom.json"
    label="components with a non-component $shape"
    run_action dry-run=true
    assert_rc 0
    assert_line_eq "$RUN_STDOUT" "- SBOM components (every level): (not counted: an entry of components is not a component)" \
      "$label: fixed count text"
    assert_line_eq "$RUN_STDOUT" "- vulnerability report entries: 2" "$label: the other count"
    assert_file_contains "$RUN_STDOUT" "- sbom: " "$label: the sbom file is listed"
    assert_line_eq "$RUN_STDOUT" "Dry run: nothing was sent to Seetrex." "$label: dry-run line"
    assert_eq 0 "$(api_call_count)" "$label: no Seetrex call"
  done
}

test_intent_trivy_cache_dir_is_the_path_action_yml_caches() {
  # INTENT: both scans use as --cache-dir the very directory the cache step of
  # action.yml saves and restores, so the database downloaded by one push is
  # the one the next push finds.
  # CONTEXT: review A-I3 of the third review: nothing tied the two values.
  # EXPIRES IF: the Action stops caching the Trivy database.
  local path n
  path="$(sed -n '/^    - name: Cache the Trivy vulnerability database$/,/^    - /s/^        path: //p' \
    "$ACTION_ROOT/action.yml")"
  path="${path%$'\r'}"
  assert_eq '${{ runner.temp }}/seetrex-trivy-cache' "$path" "action.yml caches a directory under runner.temp"
  setup_case
  run_action dry-run=true
  assert_rc 0
  for n in 1 2; do
    trivy_args "$n" > "$CASE_DIR/args-$n"
    assert_eq "${path//'${{ runner.temp }}'/$RUNNER_TEMP}" \
      "$(sed -n '/^--cache-dir$/{n;p;}' "$CASE_DIR/args-$n")" "scan $n: --cache-dir is the cached path"
  done
}

test_intent_token_service_failures_send_nothing() {
  # INTENT: an answer of the runner's token service that is not a 200 with a
  # JWT-shaped `value` (a 500, a value that is not a JWT, a value with a
  # newline) stops the run with a fixed line before anything is posted.
  # CONTEXT: review A-I5 of the third review; a value with a newline would
  # otherwise inject a header line into the request.
  # EXPIRES IF: the Action stops using the runner's OIDC token.
  local kind
  setup_case
  printf '{"value":"not-a-jwt"}\n' > "$CASE_DIR/token-plain"
  jq -n --arg v "$FAKE_JWT" '{value: ($v + "\nX-Injected: 1")}' > "$CASE_DIR/token-newline"
  printf '{"value":"%s"}\n' "$FAKE_JWT" > "$CASE_DIR/token-500"
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  for kind in plain newline 500; do
    if [ "$kind" = 500 ]; then
      set_token_response 500 "$CASE_DIR/token-$kind"
    else
      set_token_response 200 "$CASE_DIR/token-$kind"
    fi
    reset_logs
    run_action
    assert_rc 1
    assert_line_eq "$RUN_STDOUT" "The OIDC token could not be obtained from the runner: nothing was sent." "$kind: fixed line"
    assert_eq 1 "$(token_call_count)" "$kind: one token request"
    assert_eq 0 "$(api_call_count)" "$kind: no POST"
  done
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
  # extracted (no tar call, no extracted file) nor run, and nothing is sent;
  # the fixed line says why.
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
  _assert_nothing_extracted "altered pin"
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
  _assert_nothing_extracted "tampered download"
  if trivy_ran; then fail "tampered download: trivy ran"; fi
  assert_eq 0 "$(api_call_count)" "tampered download: no POST"

  # Sanity of the tar shim: a matching download is extracted exactly once.
  setup_case
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 0
  assert_eq 1 "$(tar_count)" "matching download: one tar call"
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

  # Left out: trivy_left_out is true and trivy is absent; the attestations
  # still travel.
  setup_case
  commit_attestation "$FIXTURES_RUN/attestation-a.json" a.json
  make_event private
  _big_trivy 1200 "$CASE_DIR/big-trivy.json"
  set_trivy_fixture json "$CASE_DIR/big-trivy.json"
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 0
  body="$(_last_api_body)"
  assert_json "$body" "$allowed" "left out: only declared keys"
  assert_json "$body" '.trivy_left_out == true and (has("trivy") | not)' "left out: flag true, no trivy"
  assert_json "$body" '.attestations | length == 1' "left out: the attestation is sent"
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
  # INTENT: Trivy scans `.` from the commit's tree, so the runner's path
  # never names the subject; two workspaces at different paths send byte-identical
  # sbom strings.
  # CONTEXT: plan D1 §3 step 10 (finding 4 of M1): real Trivy names the SBOM
  # subject (metadata.component.name) after its path argument. The fake Trivy
  # models that: @SCANARG@ in the fixture becomes its path argument, so a run
  # that scanned "$GITHUB_WORKSPACE" instead of `.` would send the path.
  # EXPIRES IF: the Action stops scanning the commit with Trivy.
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
      case "$(trivy_cwd "$n")" in
        "$RUNNER_TEMP"/seetrex-work.*/tree) assert_eq ok ok ;;
        *) fail "case $case, scan $n: not run in the commit's tree: [$(trivy_cwd "$n")]" ;;
      esac
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

# The retry policy (plan D1 §3 steps 17 and 19, D-R12): the POST is retried
# (at most 3 attempts, waiting 10 s then 30 s) only on 503, 429 rate_limited,
# 408, 5xx, a non-JSON answer or a transport failure; never on
# new_repository_budget_reached or a 4xx verdict. Our own outage or a quota
# only warns, unless strict. Split in three tests (review A-M3) so that none
# runs for minutes alone.

test_intent_retries_with_backoff_on_outages_and_non_json() {
  # INTENT: 503, 408, 5xx and a 200 that is not JSON are retried with the
  # 10 s / 30 s backoff; an outage that outlasts the retries only warns.
  # CONTEXT: see the retry policy above.
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
}

test_intent_retries_on_rate_and_transport_but_never_on_budget() {
  # INTENT: a 429 rate_limited and a transport failure are retried; a 429
  # new_repository_budget_reached is not (even with a Retry-After); all of
  # them warn, and fail the job only with strict.
  # CONTEXT: see the retry policy above.
  # EXPIRES IF: the server's idempotency (action_router.rs:319-326) goes away.
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
}

test_intent_no_retry_on_a_verdict_and_quota_only_warns() {
  # INTENT: a 4xx verdict (400, 400 repository_not_supported, 401, 403, 409,
  # 413) is never retried and fails the job, strict or not; a 200 reporting
  # the quota reached is kept and only warns, unless strict.
  # CONTEXT: see the retry policy above; review A-I4 of D1:
  # repository_not_supported is a verdict, not our outage.
  # EXPIRES IF: the server's idempotency (action_router.rs:319-326) goes away.
  local s
  for s in 400 401 403 409 413; do
    setup_case
    set_api_response "$s" "$FIXTURES_RUN/resp-401.json"
    _retry_case 1 "" 1
  done

  setup_case
  printf '{"error":"repository_not_supported"}\n' > "$CASE_DIR/not-supported.json"
  set_api_response 400 "$CASE_DIR/not-supported.json"
  _retry_case 1 "" 1
  assert_line_eq "$RUN_STDOUT" "Seetrex does not support this repository (400): nothing was recorded." \
    "repository_not_supported: fixed line"
  assert_file_not_contains "$RUN_STDOUT" "::warning::" "repository_not_supported: not a warning"

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

# Number of the first curl call whose URL starts with <prefix> (empty if none).
_first_call_with_prefix() {
  local i c
  c="$(curl_count)"
  for ((i = 1; i <= c; i++)); do
    case "$(curl_call "$i" url)" in
      "$1"*)
        printf '%s\n' "$i"
        return 0
        ;;
    esac
  done
}

# _assert_call_bounded <n> <what> <seconds>: call <n> was made with `-q`
# first, `--max-time <seconds>` (that exact value, once) and `--proto =https`.
_assert_call_bounded() {
  local n="$1" what="$2" want="$3" argv prev="" line first="" max="" proto=0
  argv="$(curl_call_dir "$n")/argv"
  assert_file_exists "$argv" "$what: argv logged"
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [ -n "$first" ] || first="$line"
    if [ "$prev" = --max-time ]; then
      max="$max[$line]"
    fi
    if [ "$prev" = --proto ] && [ "$line" = '=https' ]; then
      proto=1
    fi
    prev="$line"
  done < "$argv"
  assert_eq -q "$first" "$what: -q is the first argument (no .curlrc)"
  assert_eq "[$want]" "$max" "$what: --max-time $want"
  assert_eq 1 "$proto" "$what: --proto =https"
}

test_intent_requests_are_authenticated_and_bounded() {
  # INTENT: the token is asked for with the request token and the audience
  # https://api.seetrex.com appended to the runner's URL with the right
  # separator; the push carries exactly `Authorization: Bearer <jwt>`; every
  # request ignores .curlrc, is https-only and has a time limit.
  # CONTEXT: review A-I1 of D1: authentication was never asserted, so a wrong
  # audience, a missing header or an unbounded request went unseen.
  # EXPIRES IF: the Action stops using the runner's OIDC token or curl.
  local tok api dl
  setup_case
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 0
  tok="$(_first_call_with_prefix https://token.invalid/)"
  api="$(_first_call_with_prefix https://api.seetrex.com/)"
  dl="$(_first_call_with_prefix "$TRIVY_DOWNLOAD_PREFIX")"
  assert_ne "" "$tok" "a token call was made"
  assert_ne "" "$api" "a push was made"
  assert_ne "" "$dl" "a download was made"
  assert_eq "https://token.invalid/x?a=1&audience=https%3A%2F%2Fapi.seetrex.com" \
    "$(curl_call "$tok" url)" "token URL: runner URL + '&' + audience"
  assert_line_eq "$(curl_call_dir "$tok")/headers" "Authorization: Bearer $FAKE_REQUEST_TOKEN" \
    "the token call carries the request token"
  assert_file_not_contains "$(curl_call_dir "$tok")/headers" "$FAKE_JWT" "no JWT on the token call"
  assert_eq "$SEETREX_PUSH_URL" "$(curl_call "$api" url)" "push URL"
  assert_eq POST "$(curl_call "$api" method)" "push method"
  assert_line_eq "$(curl_call_dir "$api")/headers" "Authorization: Bearer $FAKE_JWT" \
    "the push carries the JWT"
  assert_line_eq "$(curl_call_dir "$api")/headers" "Content-Type: application/json" "push content type"
  assert_file_not_contains "$(curl_call_dir "$api")/headers" "$FAKE_REQUEST_TOKEN" \
    "no request token on the push"
  _assert_call_bounded "$dl" "download" 300
  _assert_call_bounded "$tok" "token" 30
  _assert_call_bounded "$api" "push" 60
  # Neither token is ever an argument of a process (argv is readable by
  # every process of the runner): both travel in 600 header files.
  local i c
  c="$(curl_count)"
  for ((i = 1; i <= c; i++)); do
    assert_file_not_contains "$(curl_call_dir "$i")/argv" "$FAKE_REQUEST_TOKEN" "call $i: request token on argv"
    assert_file_not_contains "$(curl_call_dir "$i")/argv" "$FAKE_JWT" "call $i: JWT on argv"
  done

  # A runner URL without a query string takes '?'.
  setup_case
  export ACTIONS_ID_TOKEN_REQUEST_URL='https://token.invalid/y'
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 0
  tok="$(_first_call_with_prefix https://token.invalid/)"
  assert_eq "https://token.invalid/y?audience=https%3A%2F%2Fapi.seetrex.com" \
    "$(curl_call "$tok" url)" "token URL: runner URL + '?' + audience"

  # A runner token URL that is not https: fixed line, the token is never
  # asked for and nothing is sent (push: only the Trivy download ran;
  # control request: no request at all).
  local line="The runner's OIDC token URL is not https: nothing was sent."
  setup_case
  export ACTIONS_ID_TOKEN_REQUEST_URL='http://token.invalid/x?a=1'
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "$line" "http token URL: fixed line"
  assert_eq 1 "$(curl_count)" "http token URL: only the Trivy download"
  assert_eq 1 "$(download_call_count)" "http token URL: the one request is the download"
  reset_logs
  set_api_response 200 "$FIXTURES_RUN/resp-control.json"
  run_action request-repin=true
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "$line" "http token URL, repin: fixed line"
  assert_eq 0 "$(curl_count)" "http token URL, repin: no request"
}

test_intent_symlinked_attestation_is_never_sent() {
  # INTENT: a symlink committed under .seetrex/attestations/ (mode 120000) is
  # never sent: neither its target path nor what it points at; only the
  # regular attestation files are.
  # CONTEXT: review A-I2 of D1: a link's blob is its target path, and a link
  # could point outside the attestation directory.
  # EXPIRES IF: the server reads the attestations from the commit itself.
  local oid mode body
  setup_case
  commit_attestation "$FIXTURES_RUN/attestation-a.json" a.json
  oid="$(printf '%s' '../../outside-target-7c1.json' | git -C "$WS" hash-object -w --stdin)"
  oid="${oid%$'\r'}"
  git -C "$WS" update-index --add --cacheinfo "120000,$oid,.seetrex/attestations/link.json"
  git -C "$WS" commit -q -m "add a symlinked attestation"
  _refresh_sha
  mode="$(git -C "$WS" ls-tree HEAD .seetrex/attestations/link.json)"
  assert_eq 120000 "${mode%% *}" "the fixture commits a symlink"
  make_event private
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 0
  body="$(_last_api_body)"
  assert_json "$body" '.attestations | length == 1' "only the regular attestation is sent"
  assert_eq "$(cat "$FIXTURES_RUN/attestation-a.json")" "$(jq -r '.attestations[0]' "$body")" \
    "the attestation sent is A"
  assert_file_not_contains "$body" "outside-target-7c1" "the link target is not sent"
}

test_intent_scanned_tree_is_the_commit_of_the_run() {
  # INTENT: Trivy scans exactly the tree of GITHUB_SHA, materialised with a
  # private index: not a file modified in the worktree, not an untracked file,
  # not a staged-but-uncommitted file, not a later commit checked out as HEAD;
  # the user's worktree and index are left as they were.
  # CONTEXT: review I-7 of D1 (controller's decision): the token attests
  # GITHUB_SHA, so the scan must be of that commit and nothing else; it
  # replaces the HEAD == GITHUB_SHA refusal of A-I3, which a commit-tree scan
  # makes moot.
  # EXPIRES IF: the server scans the commit itself.
  local old n dry
  setup_case
  printf 'committed content
' > "$CASE_DIR/app.js"
  commit_file "$CASE_DIR/app.js" src/app.js
  old="$GITHUB_SHA"
  printf 'later commit
' > "$CASE_DIR/later.txt"
  commit_file "$CASE_DIR/later.txt" later.txt
  export GITHUB_SHA="$old"
  printf 'modified in the worktree
' > "$WS/src/app.js"
  printf 'untracked
' > "$WS/untracked.txt"
  printf 'staged only
' > "$WS/staged.txt"
  git -C "$WS" add staged.txt
  make_event private
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  for dry in false true; do
    reset_logs
    run_action dry-run="$dry"
    assert_rc 0
    assert_eq 2 "$(trivy_invocations)" "dry=$dry: two scans"
    for n in 1 2; do
      trivy_files "$n" > "$CASE_DIR/files-$n"
      assert_line_eq "$CASE_DIR/files-$n" "src/app.js $(_sha "$CASE_DIR/app.js")"         "dry=$dry, scan $n: src/app.js as committed"
      assert_line_eq "$CASE_DIR/files-$n" "package.json $(git -C "$WS" show "$old:package.json" | sha256sum | cut -d' ' -f1)"         "dry=$dry, scan $n: package.json of the commit"
      for f in later.txt untracked.txt staged.txt; do
        assert_file_not_contains "$CASE_DIR/files-$n" "$f" "dry=$dry, scan $n: scanned $f"
      done
    done
  done
  assert_eq "modified in the worktree" "$(cat "$WS/src/app.js")" "the worktree is untouched"
  local cached
  cached="$(git -C "$WS" diff --cached --name-only)"
  assert_eq staged.txt "${cached%$'\r'}" "the user's index is untouched"

  # A commit that is not in the workspace's repository: nothing runs.
  setup_case
  export GITHUB_SHA=0123456789abcdef0123456789abcdef01234567
  make_event private
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "The commit of this run is not checked out in the workspace (run actions/checkout first): nothing was scanned or sent."     "unknown commit: fixed line"
  assert_eq 0 "$(curl_count)" "unknown commit: no request"
  if trivy_ran; then fail "unknown commit: trivy ran"; fi

  # (a) Attributes and checkout conversions from outside the commit (an
  # untracked .gitattributes, $GIT_DIR/info/attributes, core.attributesFile,
  # core.autocrlf, core.eol) change nothing: each file is its committed blob.
  local f
  setup_case
  printf 'line one\nline two\n' > "$CASE_DIR/lf.txt"
  for f in src/app.js docs/notes.txt docs/guide.md data/plain.cfg; do
    commit_file "$CASE_DIR/lf.txt" "$f"
  done
  printf '*.js eol=crlf\n*.txt working-tree-encoding=UTF-16\n' > "$WS/.gitattributes"
  mkdir -p "$WS/.git/info"
  printf '*.md eol=crlf\n' > "$WS/.git/info/attributes"
  printf '*.cfg eol=crlf\n' > "$CASE_DIR/attributes"
  git -C "$WS" config core.attributesFile "$CASE_DIR/attributes"
  git -C "$WS" config core.autocrlf true
  git -C "$WS" config core.eol crlf
  make_event private
  run_action dry-run=true
  assert_rc 0
  for n in 1 2; do
    trivy_files "$n" > "$CASE_DIR/files-$n"
    for f in src/app.js docs/notes.txt docs/guide.md data/plain.cfg; do
      assert_line_eq "$CASE_DIR/files-$n" "$f $(_sha "$CASE_DIR/lf.txt")" "attributes, scan $n: $f as committed"
    done
    assert_file_not_contains "$CASE_DIR/files-$n" ".gitattributes" "attributes, scan $n: the untracked .gitattributes"
  done

  # (b) `git replace` of the commit, then of its blobs: the scan and the
  # attestation sent are still those of GITHUB_SHA.
  local x y
  setup_case
  printf 'committed content\n' > "$CASE_DIR/app.js"
  commit_attestation "$FIXTURES_RUN/attestation-a.json" a.json
  commit_file "$CASE_DIR/app.js" src/app.js
  x="$GITHUB_SHA"
  printf 'replacement content\n' > "$CASE_DIR/other.js"
  commit_attestation "$FIXTURES_RUN/attestation-b.json" a.json
  commit_file "$CASE_DIR/other.js" src/app.js
  y="$GITHUB_SHA"
  export GITHUB_SHA="$x"
  make_event private
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  git -C "$WS" replace "$x" "$y"
  for what in commit blobs; do
    if [ "$what" = blobs ]; then
      git -C "$WS" replace -d "$x" > /dev/null
      git -C "$WS" replace "$(git -C "$WS" rev-parse "$x:src/app.js" | tr -d '\r')" \
        "$(git -C "$WS" rev-parse "$y:src/app.js" | tr -d '\r')"
      git -C "$WS" replace "$(git -C "$WS" rev-parse "$x:.seetrex/attestations/a.json" | tr -d '\r')" \
        "$(git -C "$WS" rev-parse "$y:.seetrex/attestations/a.json" | tr -d '\r')"
    fi
    reset_logs
    run_action
    assert_rc 0
    for n in 1 2; do
      trivy_files "$n" > "$CASE_DIR/files-$n"
      assert_line_eq "$CASE_DIR/files-$n" "src/app.js $(_sha "$CASE_DIR/app.js")" "replace $what, scan $n: src/app.js of GITHUB_SHA"
    done
    assert_json "$(_last_api_body)" '.attestations | length == 1' "replace $what: one attestation"
    assert_eq "$(cat "$FIXTURES_RUN/attestation-a.json")" "$(jq -r '.attestations[0]' "$(_last_api_body)")" \
      "replace $what: the attestation of GITHUB_SHA"
  done

  # (c) A committed filter=lfs attribute with a configured filter, and (d) an
  # executable file and a nested directory: every file is written from its
  # blob (the LFS pointer as committed, no filter runs); symbolic links are
  # not materialised.
  local ptr
  setup_case
  printf '*.bin filter=lfs diff=lfs merge=lfs -text\n' > "$CASE_DIR/gitattributes"
  commit_file "$CASE_DIR/gitattributes" .gitattributes
  printf 'version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize 12\n' \
    "$(printf 'fixture blob' | sha256sum | cut -d' ' -f1)" > "$CASE_DIR/pointer"
  commit_file "$CASE_DIR/pointer" assets/blob.bin
  printf '#!/bin/sh\necho fixture\n' > "$CASE_DIR/tool.sh"
  commit_file "$CASE_DIR/tool.sh" tools/tool.sh
  git -C "$WS" update-index --chmod=+x tools/tool.sh
  git -C "$WS" commit -q -m "tool is executable"
  printf 'deep\n' > "$CASE_DIR/deep.txt"
  commit_file "$CASE_DIR/deep.txt" a/b/c/deep.txt
  ptr="$(git -C "$WS" hash-object -w "$CASE_DIR/deep.txt" | tr -d '\r')"
  git -C "$WS" update-index --add --cacheinfo "120000,$ptr,link-to-deep"
  git -C "$WS" commit -q -m "a symbolic link"
  GITHUB_SHA="$(git -C "$WS" rev-parse HEAD | tr -d '\r')"
  export GITHUB_SHA
  printf '#!/bin/sh\n: > "%s"\necho SMUDGED\n' "$CASE_DIR/smudge.marker" > "$CASE_DIR/smudge.sh"
  git -C "$WS" config filter.lfs.smudge "sh '$CASE_DIR/smudge.sh'"
  git -C "$WS" config filter.lfs.required true
  make_event private
  run_action dry-run=true
  assert_rc 0
  for n in 1 2; do
    trivy_files "$n" > "$CASE_DIR/files-$n"
    assert_line_eq "$CASE_DIR/files-$n" "assets/blob.bin $(_sha "$CASE_DIR/pointer")" "lfs, scan $n: the pointer as committed"
    assert_line_eq "$CASE_DIR/files-$n" "tools/tool.sh $(_sha "$CASE_DIR/tool.sh")" "scan $n: the executable file"
    assert_line_eq "$CASE_DIR/files-$n" "a/b/c/deep.txt $(_sha "$CASE_DIR/deep.txt")" "scan $n: the nested file"
    assert_file_not_contains "$CASE_DIR/files-$n" "link-to-deep" "scan $n: the symbolic link is not materialised"
  done
  assert_no_file "$CASE_DIR/smudge.marker" "lfs: the smudge filter ran"

  # (e) A crafted tree whose path climbs out of the scanned directory: refused
  # before anything is written outside it or scanned.
  local blob inner outer top
  setup_case
  blob="$(printf 'evil\n' | git -C "$WS" hash-object -w --stdin | tr -d '\r')"
  inner="$(printf '100644 blob %s\tevil-7d2\n' "$blob" | git -C "$WS" mktree | tr -d '\r')"
  outer="$(printf '040000 tree %s\t..\n' "$inner" | git -C "$WS" mktree | tr -d '\r')"
  top="$(printf '040000 tree %s\t..\n' "$outer" | git -C "$WS" mktree | tr -d '\r')"
  GITHUB_SHA="$(git -C "$WS" commit-tree -m crafted "$top" | tr -d '\r')"
  export GITHUB_SHA
  make_event private
  run_action dry-run=true
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "The commit of this run could not be read from the workspace: nothing was scanned or sent." \
    "crafted path: fixed line"
  if trivy_ran; then fail "crafted path: trivy ran"; fi
  assert_eq "" "$(find "$CASE_DIR" -name evil-7d2 -print)" "crafted path: a file was written outside the tree"
}

# _literal_tree <mode> <name> <oid>: writes a one-entry tree object to $WS
# without any check (`git mktree` refuses a name with a slash) and prints its
# id. The entry is the raw `<mode> <name>\0<20-byte oid>` of the tree format.
_literal_tree() {
  local mode="$1" name="$2" oid="$3" esc="" i
  for ((i = 0; i < ${#oid}; i += 2)); do
    esc+="\\x${oid:i:2}"
  done
  # shellcheck disable=SC2059  # the format is the escaped oid on purpose
  { printf '%s %s\0' "$mode" "$name"; printf "$esc"; } \
    | git -C "$WS" hash-object -t tree --literally -w --stdin | tr -d '\r'
}

# _run_crafted_tree <tree> <label>: commits <tree> as GITHUB_SHA, runs a dry
# run and asserts the path rule refused it: exit 1, the fixed line, no
# request, and Trivy never invoked at all (trivy_ran false). That last check
# is what measures "the crafted file never reaches Trivy": no invocation, no
# scan of any tree. A file written under the scanned tree cannot be looked
# for after the run: run.sh deletes its work directory on exit.
_run_crafted_tree() {
  local tree="$1" label="$2"
  GITHUB_SHA="$(git -C "$WS" commit-tree -m crafted "$tree" | tr -d '\r')"
  export GITHUB_SHA
  make_event private
  reset_logs
  run_action dry-run=true
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "The commit of this run could not be read from the workspace: nothing was scanned or sent." \
    "$label: fixed line"
  if trivy_ran; then fail "$label: trivy ran"; fi
  assert_eq 0 "$(curl_count)" "$label: no request"
}

test_intent_scanned_tree_refuses_a_dot_component() {
  # INTENT: a commit whose tree has an entry named `.`, at the root (`./x`) or
  # below it (`sub/./x`), is refused before anything is written or scanned,
  # like a `..` component.
  # CONTEXT: D1 debt: of the five path rules of run.sh (`.`, `..`, `.git`,
  # empty component, absolute) only `..` had a test. git never checks such a
  # path out; a crafted commit can still carry it.
  # EXPIRES IF: the Action stops materialising the commit's tree itself.
  local blob inner dot top
  setup_case
  blob="$(printf 'dot\n' | git -C "$WS" hash-object -w --stdin | tr -d '\r')"
  inner="$(printf '100644 blob %s\tdot-4e1\n' "$blob" | git -C "$WS" mktree | tr -d '\r')"
  dot="$(printf '040000 tree %s\t.\n' "$inner" | git -C "$WS" mktree | tr -d '\r')"
  _run_crafted_tree "$dot" "dot component"
  top="$(printf '040000 tree %s\tsub-4e1\n' "$dot" | git -C "$WS" mktree | tr -d '\r')"
  _run_crafted_tree "$top" "nested dot component"
}

test_intent_scanned_tree_refuses_a_dot_git_component() {
  # INTENT: a commit whose tree has a `.git` entry, in any case (`.git`,
  # `.GiT`), at the root or below it (`sub/.git/x`), is refused before
  # anything is written or scanned: no file of a crafted commit lands in a
  # `.git` directory of the scanned tree.
  # CONTEXT: D1 debt (see test_intent_scanned_tree_refuses_a_dot_component);
  # the rule lower-cases the path because case-insensitive filesystems treat
  # `.GiT` as `.git`.
  # EXPIRES IF: the Action stops materialising the commit's tree itself.
  local blob inner git_dir top name
  for name in .git .GiT; do
    setup_case
    blob="$(printf 'git\n' | git -C "$WS" hash-object -w --stdin | tr -d '\r')"
    inner="$(printf '100644 blob %s\tconfig-5b3\n' "$blob" | git -C "$WS" mktree | tr -d '\r')"
    git_dir="$(printf '040000 tree %s\t%s\n' "$inner" "$name" | git -C "$WS" mktree | tr -d '\r')"
    _run_crafted_tree "$git_dir" "$name component"
    top="$(printf '040000 tree %s\tsub-5b3\n' "$git_dir" | git -C "$WS" mktree | tr -d '\r')"
    _run_crafted_tree "$top" "nested $name component"
  done
}

test_intent_scanned_tree_refuses_an_empty_component() {
  # INTENT: a path with an empty component (`a//b`, from an entry name that
  # carries the slashes) is refused before anything is written or scanned.
  # A tree entry whose whole name is empty never reaches the rule: git itself
  # refuses to list it ("empty filename in tree entry"), and the run stops on
  # the same fixed line.
  # CONTEXT: D1 debt (see test_intent_scanned_tree_refuses_a_dot_component).
  # EXPIRES IF: the Action stops materialising the commit's tree itself.
  local blob
  setup_case
  blob="$(printf 'empty\n' | git -C "$WS" hash-object -w --stdin | tr -d '\r')"
  _run_crafted_tree "$(_literal_tree 100644 'dir-6c4//empty-6c4' "$blob")" "empty component"
  _run_crafted_tree "$(_literal_tree 100644 '' "$blob")" "empty name"
}

test_intent_scanned_tree_refuses_an_absolute_path() {
  # INTENT: an absolute path (`/x`, from an entry name that starts with a
  # slash) is refused before anything is written or scanned.
  # CONTEXT: D1 debt (see test_intent_scanned_tree_refuses_a_dot_component).
  # EXPIRES IF: the Action stops materialising the commit's tree itself.
  local blob
  setup_case
  blob="$(printf 'abs\n' | git -C "$WS" hash-object -w --stdin | tr -d '\r')"
  _run_crafted_tree "$(_literal_tree 100644 '/abs-7f5' "$blob")" "absolute path"
}

test_intent_partial_clone_fails_closed_without_fetching() {
  # INTENT: a blob of GITHUB_SHA missing from a partial clone is never fetched
  # from the repository's remote: the run stops with a fixed line, scans and
  # sends nothing. A partial clone that holds every blob of the commit (no
  # sparse checkout) is scanned as usual, as the README says.
  # CONTEXT: review A-M3 of D1 (checkout with `filter: blob:none` and a
  # sparse checkout); the README lists every network destination of a run.
  # EXPIRES IF: the Action fetches the commit itself.
  setup_case
  printf 'nested\n' > "$CASE_DIR/nested.txt"
  commit_file "$CASE_DIR/nested.txt" src/nested.txt
  git -C "$WS" config uploadpack.allowFilter true
  git clone -q --filter=blob:none --sparse "file://$WS" "$CASE_DIR/partial" 2> /dev/null
  export GITHUB_WORKSPACE="$CASE_DIR/partial"
  make_event private
  run_action dry-run=true
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "The commit of this run could not be read from the workspace: nothing was scanned or sent." \
    "partial clone: fixed line"
  if trivy_ran; then fail "partial clone: trivy ran"; fi
  assert_eq 0 "$(curl_count)" "partial clone: no request"

  # The same partial clone without sparse checkout: checking out the commit
  # brought every blob of its tree, so nothing is missing and the commit is
  # scanned as usual (README: "already holds all of its files").
  rm -rf "$CASE_DIR/partial"
  git clone -q --filter=blob:none "file://$WS" "$CASE_DIR/partial" 2> /dev/null
  reset_logs
  run_action dry-run=true
  assert_rc 0
  assert_eq 2 "$(trivy_invocations)" "partial clone, not sparse: two scans"
  trivy_files 1 > "$CASE_DIR/files-1"
  assert_line_eq "$CASE_DIR/files-1" "src/nested.txt $(_sha "$CASE_DIR/nested.txt")" \
    "partial clone, not sparse: the nested file is scanned"
}

test_intent_trivy_runs_offline_without_telemetry_and_with_an_empty_home() {
  # INTENT: both Trivy scans run with --scanners vuln, --skip-version-check,
  # --disable-telemetry and --offline-scan, with `--config ''` and
  # `--ignorefile ''`, and with HOME set to an empty directory of the run (not
  # the runner's home), so Trivy calls no one but its database mirror and
  # reads no user configuration: not the runner's, and not a trivy.yaml or
  # .trivyignore committed in the scanned repository.
  # CONTEXT: review B-I3 and B-M4 of D1; review C-1 (measured with Trivy
  # 0.76.1: a committed trivy.yaml, read from Trivy's cwd, redirected the
  # database download to a planted registry); README: network destinations.
  # EXPIRES IF: the Action stops running Trivy.
  local n flag home
  setup_case
  printf 'db:
  repository: registry.invalid/planted-db
' > "$CASE_DIR/trivy.yaml"
  commit_file "$CASE_DIR/trivy.yaml" trivy.yaml
  printf 'CVE-2099-0001
' > "$CASE_DIR/trivyignore"
  commit_file "$CASE_DIR/trivyignore" .trivyignore
  make_event private
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 0
  assert_eq 2 "$(trivy_invocations)" "two scans"
  for n in 1 2; do
    trivy_args "$n" > "$CASE_DIR/args-$n"
    for flag in --skip-version-check --disable-telemetry --offline-scan; do
      assert_line_eq "$CASE_DIR/args-$n" "$flag" "scan $n: $flag"
    done
    assert_eq vuln "$(sed -n '/^--scanners$/{n;p;}' "$CASE_DIR/args-$n")" "scan $n: --scanners vuln"
    for flag in --config --ignorefile; do
      assert_eq 1 "$(grep -c -x -e "$flag" "$CASE_DIR/args-$n" || true)" "scan $n: $flag given once"
      assert_eq "[]" "[$(sed -n "/^$flag\$/{n;p;}" "$CASE_DIR/args-$n")]" "scan $n: $flag ''"
    done
    trivy_files "$n" > "$CASE_DIR/files-$n"
    assert_file_contains "$CASE_DIR/files-$n" "trivy.yaml " "scan $n: the committed trivy.yaml is in the scanned tree"
    assert_file_contains "$CASE_DIR/files-$n" ".trivyignore " "scan $n: the committed .trivyignore is in the scanned tree"
    assert_eq "" "$(trivy_reads "$n")" "scan $n: Trivy reads a config or ignore file"
    home="$(trivy_home "$n")"
    assert_ne "$HOME" "$home" "scan $n: not the runner's HOME"
    case "$home" in
      "$RUNNER_TEMP"/seetrex-work.*/home) assert_eq ok ok ;;
      *) fail "scan $n: HOME is not the run's empty directory: [$home]" ;;
    esac
    # Exactly the four variables run.sh passes (review B-I2 of the third
    # review: the second scan's env was not checked).
    assert_eq "HOME LANG PATH TMPDIR" "$(_trivy_env_names "$n")" "scan $n: environment"
  done
  # Only the first scan downloads the database: real Trivy 0.76.1 refuses
  # --skip-db-update on a first run with an empty cache (review A-I2).
  assert_eq 0 "$(grep -c -x -e --skip-db-update "$CASE_DIR/args-1" || true)" "scan 1: no --skip-db-update"
  assert_eq 1 "$(grep -c -x -e --skip-db-update "$CASE_DIR/args-2" || true)" "scan 2: --skip-db-update"

  # Proxy variables reach both scans only when they are set.
  reset_logs
  HTTPS_PROXY=http://proxy.invalid:3128 no_proxy=example.invalid run_action
  assert_rc 0
  for n in 1 2; do
    assert_eq "HOME HTTPS_PROXY LANG PATH TMPDIR no_proxy" "$(_trivy_env_names "$n")" "proxies set, scan $n: environment"
  done
}

# Names of the env variables invocation <n> of trivy saw, sorted, on one line,
# without those the shell running the fake trivy adds itself (bash: PWD,
# SHLVL, _, OLDPWD; the MSYS runtime of Git for Windows: MSYSTEM, SYSTEMROOT,
# WINDIR).
_trivy_env_names() {
  local name out=""
  while IFS= read -r name; do
    case "$name" in
      PWD|SHLVL|_|OLDPWD|MSYSTEM|SYSTEMROOT|WINDIR) ;;
      *) out="$out $name" ;;
    esac
  done < <(trivy_env "$1" | LC_ALL=C sort)
  printf '%s\n' "${out# }"
}

# _hostile_input_case <input> <fixed line>: every hostile value of <input> is
# refused before anything runs, and never echoed.
_hostile_input_case() {
  local input="$1" line="$2" v
  # shellcheck disable=SC2016  # literal hostile values, never expanded
  local -a values=(
    'full$(touch "$TEST_TMP/pwned")'
    '../../x'
    $'true\nfoo=bar'
    '`id`'
    "'; echo x"
    'TRUE'
  )
  setup_case
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  for v in "${values[@]}"; do
    reset_logs
    run_action "$input=$v"
    assert_rc 1
    assert_line_eq "$RUN_STDOUT" "$line" "$input=[$v]: fixed line"
    assert_eq 0 "$(curl_count)" "$input=[$v]: no request"
    if trivy_ran; then fail "$input=[$v]: trivy ran"; fi
    if [[ "$v" == *$'\n'* ]]; then
      assert_file_not_contains "$RUN_STDOUT" "foo=bar" "$input: value echoed on stdout"
      assert_file_not_contains "$RUN_STDERR" "foo=bar" "$input: value echoed on stderr"
      assert_file_not_contains "$GITHUB_STEP_SUMMARY" "foo=bar" "$input: value echoed in the summary"
      assert_file_not_contains "$GITHUB_OUTPUT" "foo=bar" "$input: value in the outputs"
    else
      assert_file_not_contains "$RUN_STDOUT" "$v" "$input=[$v]: echoed on stdout"
      assert_file_not_contains "$RUN_STDERR" "$v" "$input=[$v]: echoed on stderr"
      assert_file_not_contains "$GITHUB_STEP_SUMMARY" "$v" "$input=[$v]: echoed in the summary"
    fi
    assert_no_file "$TEST_TMP/pwned" "$input=[$v]: a command ran"
  done
}

test_intent_hostile_inputs_dry_run() {
  # INTENT: a dry-run value other than true/false (command substitution,
  # path, newline, backticks, quote, other case) stops the run: exit 1,
  # fixed line, no request, no scan, the value never echoed or executed.
  # CONTEXT: review B-I4 of D1; inputs reach run.sh only as env variables.
  # EXPIRES IF: the input is removed.
  _hostile_input_case dry-run "Input dry-run must be true or false: nothing was sent."
}

test_intent_hostile_inputs_summary() {
  # INTENT: a summary value other than full/counters stops the run (see
  # test_intent_hostile_inputs_dry_run); the value never selects a file.
  # CONTEXT: review B-I4 of D1: run.sh builds bin/filters/summary_<value>.jq.
  # EXPIRES IF: the input is removed.
  _hostile_input_case summary "Input summary must be full or counters: nothing was sent."
}

test_intent_hostile_inputs_strict() {
  # INTENT: as test_intent_hostile_inputs_dry_run, for strict.
  # CONTEXT: review B-I4 of D1.
  # EXPIRES IF: the input is removed.
  _hostile_input_case strict "Input strict must be true or false: nothing was sent."
}

test_intent_hostile_inputs_request_repin() {
  # INTENT: as test_intent_hostile_inputs_dry_run, for request-repin.
  # CONTEXT: review B-I4 of D1.
  # EXPIRES IF: the input is removed.
  _hostile_input_case request-repin "Input request-repin must be true or false: nothing was sent."
}

test_intent_hostile_inputs_request_close() {
  # INTENT: as test_intent_hostile_inputs_dry_run, for request-close.
  # CONTEXT: review B-I4 of D1.
  # EXPIRES IF: the input is removed.
  _hostile_input_case request-close "Input request-close must be true or false: nothing was sent."
}

test_intent_tokens_never_traced_even_with_bash_env_xtrace() {
  # INTENT: a BASH_ENV that turns on `set -x` (or SHELLOPTS=xtrace) does not
  # make run.sh print the request token or the JWT: run.sh turns tracing off
  # as its first statement (and action.yml unsets BASH_ENV).
  # CONTEXT: review B-I5 of D1: GitHub masks only after ::add-mask::, and an
  # xtrace line of the printf that writes the header file would leak it.
  # EXPIRES IF: the Action stops handling tokens in bash.
  local needle
  setup_case
  # The shims are bash too: tracing them would log what the test harness
  # itself handles, so the hook leaves them alone.
  # shellcheck disable=SC2016  # literal $0, expanded by the traced bash
  printf 'case "$0" in */shims/*) ;; *) set -x ;; esac\n' > "$CASE_DIR/bash_env"
  printf 'probe_marker=traced\n' > "$CASE_DIR/probe.sh"
  BASH_ENV="$CASE_DIR/bash_env" bash "$CASE_DIR/probe.sh" 2> "$CASE_DIR/probe.err"
  assert_file_contains "$CASE_DIR/probe.err" "probe_marker=traced" "sanity: the BASH_ENV file turns tracing on"
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  export BASH_ENV="$CASE_DIR/bash_env"
  run_action
  unset BASH_ENV
  assert_rc 0
  assert_eq 1 "$(api_call_count)" "the push was sent"
  sed '/^::add-mask::/d' "$RUN_STDOUT" > "$CASE_DIR/stdout.unmasked"
  for needle in "$FAKE_JWT" "$FAKE_REQUEST_TOKEN"; do
    assert_file_not_contains "$RUN_STDERR" "$needle" "a token traced on stderr"
    assert_file_not_contains "$CASE_DIR/stdout.unmasked" "$needle" "a token on stdout"
  done
}

test_intent_skipped_categories_are_echoed_only_as_plain_tokens() {
  # INTENT: a `skipped` value of a 200 answer is named in the log only if it
  # is a plain lower-case token as a whole string; a workflow command, a value
  # with a newline (which `jq -r` would split into two plain tokens), markup
  # or anything else never reaches the log or the job summary.
  # CONTEXT: review A-I2 and B-M4 of D1: the answer is data, and a value
  # like "::warning::x" or "a\nb" printed raw becomes a runner command or a
  # forged line.
  # EXPIRES IF: the Action stops echoing skipped categories.
  local v
  setup_case
  jq '.skipped = ["::warning::x", "a\nb", "<b>", "Bad Value", "vuln_scan"]' \
    "$FIXTURES_RUN/resp-200.json" > "$CASE_DIR/resp-skipped.json"
  set_api_response 200 "$CASE_DIR/resp-skipped.json"
  run_action
  assert_rc 0
  assert_line_eq "$RUN_STDOUT" "Seetrex did not read the document of category vuln_scan in this push; the obligations that read it are not current." \
    "a well-formed category is named"
  for v in "::warning::x" "category a " "category b " "<b>" "Bad Value"; do
    assert_file_not_contains "$RUN_STDOUT" "$v" "stdout carries [$v]"
    assert_file_not_contains "$GITHUB_STEP_SUMMARY" "$v" "summary carries [$v]"
  done
  assert_file_not_contains "$GITHUB_STEP_SUMMARY" '`a`' "summary names a split token"
  assert_file_not_contains "$GITHUB_STEP_SUMMARY" '`b`' "summary names a split token"
}

test_intent_a_400_message_is_shown_only_when_plain() {
  # INTENT: on a 400 the server's `message` is shown after the fixed line only
  # when it is short plain text; anything else (a workflow command, markup)
  # is dropped, and the run fails either way.
  # CONTEXT: review A-I3 of D1: the message is server data printed into the
  # log and the job summary.
  # EXPIRES IF: the server stops sending a message with a 400.
  local fixed="Seetrex rejected the request as malformed (400): nothing was recorded."
  setup_case
  printf '{"error":"bad_request","message":"sbom is not json"}\n' > "$CASE_DIR/400-plain.json"
  set_api_response 400 "$CASE_DIR/400-plain.json"
  run_action
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "$fixed" "plain: fixed line"
  assert_line_eq "$RUN_STDOUT" "Seetrex said: sbom is not json" "plain: the message is shown"
  assert_file_contains "$GITHUB_STEP_SUMMARY" "Seetrex said: sbom is not json" "plain: in the summary"

  setup_case
  printf '{"error":"bad_request","message":"::warning::<x>"}\n' > "$CASE_DIR/400-hostile.json"
  set_api_response 400 "$CASE_DIR/400-hostile.json"
  run_action
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "$fixed" "hostile: fixed line"
  assert_file_not_contains "$RUN_STDOUT" "Seetrex said" "hostile: no message line"
  assert_file_not_contains "$RUN_STDOUT" "::warning::" "hostile: no workflow command"
  assert_file_not_contains "$GITHUB_STEP_SUMMARY" "<x>" "hostile: no markup in the summary"
}

test_intent_body_that_fails_its_own_check_is_never_sent() {
  # INTENT: run.sh checks the body with bin/filters/body_check.jq before
  # asking for a token: a body the check refuses stops the run with exit 1,
  # no token request and no POST.
  # CONTEXT: review A-I6 of D1: no test made the check fail, so a run.sh
  # that skipped it would have passed.
  # EXPIRES IF: the server's request schema check moves out of the Action.
  setup_case
  printf '# always refuses\nfalse\n' > "$ACTION_COPY/bin/filters/body_check.jq"
  set_api_response 200 "$FIXTURES_RUN/resp-200.json"
  run_action
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "The request body failed its own check: nothing was sent." "fixed line"
  assert_eq 0 "$(token_call_count)" "no token request"
  assert_eq 0 "$(api_call_count)" "no POST"
}

test_intent_dry_run_names_an_attestation_only_by_a_plain_path() {
  # INTENT: the dry-run report names an attestation by its path only when the
  # file name is plain ([A-Za-z0-9._-]); any other name (here one with a
  # space) is shown as "attestation <n>".
  # CONTEXT: review B-M5 of D1: the file name is repository data printed into
  # the log and the job summary.
  # EXPIRES IF: the dry-run report stops listing attestations.
  setup_case
  commit_attestation "$FIXTURES_RUN/attestation-a.json" "a b.json"
  make_event private
  run_action dry-run=true
  assert_rc 0
  assert_file_contains "$RUN_STDOUT" "- attestation 1: " "the fallback name"
  assert_file_not_contains "$RUN_STDOUT" "a b.json" "the raw name on stdout"
  assert_file_not_contains "$GITHUB_STEP_SUMMARY" "a b.json" "the raw name in the summary"
  assert_line_eq "$RUN_STDOUT" "- attestations: 1" "the attestation is counted"
}
