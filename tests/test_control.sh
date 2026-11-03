# shellcheck shell=bash
# Dynamic tests of the control requests of bin/run.sh (request-repin,
# request-close): no scan, a literal one-field body, default branch only.

FIXTURES_CONTROL="$TESTS_DIR/fixtures/run"

# Body of the only API call of the run; fails unless exactly one was made.
_control_body() {
  local i c n=""
  c="$(curl_count)"
  for ((i = 1; i <= c; i++)); do
    case "$(curl_call "$i" url)" in
      https://api.seetrex.com/*)
        [ -z "$n" ] || fail "more than one call to api.seetrex.com"
        n="$i"
        ;;
    esac
  done
  [ -n "$n" ] || fail "no call to api.seetrex.com"
  curl_call "$n" body
}

test_intent_repin_request_only_from_default_ref_and_only_when_asked() {
  # INTENT: a repin request is sent only when the input asks for it and only
  # from the default branch, as the literal body {"repin":true} with no scan;
  # without the input a push never carries `repin`.
  # CONTEXT: plan D1 §1 (control = only {"repin":true}) and §3 step 8;
  # L_401 tells the user to run once with request-repin: true.
  # EXPIRES IF: the server drops the repin control.
  local body

  # Without the input: an ordinary push, no repin key.
  setup_case
  set_api_response 200 "$FIXTURES_CONTROL/resp-200.json"
  run_action
  assert_rc 0
  body="$(_control_body)"
  printf '%s' "$body" > "$CASE_DIR/push-body.json"
  assert_json "$CASE_DIR/push-body.json" '(has("repin") | not) and (has("close") | not)' "no control field in a push"

  # From a side branch: nothing at all.
  setup_case
  set_api_response 200 "$FIXTURES_CONTROL/resp-control.json"
  set_ref refs/heads/feature
  run_action request-repin=true
  assert_rc 0
  assert_line_eq "$RUN_STDOUT" "$L_NON_DEFAULT" "side branch: fixed line"
  assert_eq 0 "$(curl_count)" "side branch: no curl"
  if trivy_ran; then fail "side branch: trivy ran"; fi

  # From the default branch: exactly {"repin":true}, no scan.
  setup_case
  set_api_response 200 "$FIXTURES_CONTROL/resp-control.json"
  run_action request-repin=true
  assert_rc 0
  assert_eq '{"repin":true}' "$(_control_body)" "exact body"
  assert_eq 0 "$(download_call_count)" "no Trivy download"
  if trivy_ran; then fail "repin: trivy ran"; fi
  assert_line_eq "$RUN_STDOUT" "Seetrex accepted the repin request." "accepted line"
  assert_file_not_contains "$GITHUB_OUTPUT" "record=" "no record from a control request"

  # Dry-run only describes it.
  setup_case
  set_api_response 200 "$FIXTURES_CONTROL/resp-control.json"
  run_action request-repin=true dry-run=true
  assert_rc 0
  assert_eq 0 "$(curl_count)" "dry-run repin: no curl"

  # Both controls at once: refused before anything.
  setup_case
  set_api_response 200 "$FIXTURES_CONTROL/resp-control.json"
  run_action request-repin=true request-close=true
  assert_rc 1
  assert_eq 0 "$(curl_count)" "repin+close: no curl"

  # A refused repin keeps the exit table (401 -> fixed line, exit 1).
  setup_case
  set_api_response 401 "$FIXTURES_CONTROL/resp-401.json"
  run_action request-repin=true
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "$L_401" "refused repin: fixed line"
}

test_intent_close_request_sends_only_the_close_field_and_no_documents() {
  # INTENT: a close request is the literal body {"close":true}: no SBOM, no
  # report, no attestation, and Trivy is neither downloaded nor run.
  # CONTEXT: plan D1 §1 (control = only {"close":true}) and §3 step 8.
  # EXPIRES IF: the server drops the close control.
  setup_case
  commit_attestation "$FIXTURES_CONTROL/attestation-a.json" a.json
  make_event private
  set_api_response 200 "$FIXTURES_CONTROL/resp-control.json"
  run_action request-close=true
  assert_rc 0
  assert_eq '{"close":true}' "$(_control_body)" "exact body"
  assert_eq 0 "$(download_call_count)" "no Trivy download"
  if trivy_ran; then fail "close: trivy ran"; fi
  assert_eq 1 "$(token_call_count)" "one token request"
  assert_line_eq "$RUN_STDOUT" "Seetrex accepted the close request." "accepted line"
}
