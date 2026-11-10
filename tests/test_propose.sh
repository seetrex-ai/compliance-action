# shellcheck shell=bash
# Dynamic tests of the proposal step (bin/propose.sh through bin/run.sh,
# plan R4 section 2, amendment #334): the opt-in, the dry run, the job log,
# what leaves the runner, the closed list of documents, the rehydration of
# citations, the artifact and the exit table. The detectors themselves are
# tested in tests/test_detect.sh.

FIXTURES_PROPOSE="$TESTS_DIR/fixtures/propose"
SEETREX_PROPOSE_URL='https://api.seetrex.com/v1/action/propose'
CONTRACT_FIXTURES="$TESTS_DIR/fixtures/contract"

# _commit_tree <dir>: copies a fixture tree into the workspace, commits it in
# one commit and points GITHUB_SHA and the event at it.
_commit_tree() {
  cp -R "$1/." "$WS/"
  git -C "$WS" add -A
  git -C "$WS" commit -q -m "fixture tree"
  _refresh_sha
  make_event private
}

# _lines_sha <file> <start> <end>: the contract's line-range hash, computed
# independently of propose.sh.
_lines_sha() {
  local text line
  text="$(sed -n "$2,$3p" "$1" | sed 's/\r$//')"
  line="$(printf '%s' "$text" | sha256sum)"
  printf '%s\n' "${line%% *}"
}

_sha() {
  local line
  line="$(sha256sum < "$1")"
  printf '%s\n' "${line%% *}"
}

_file_bytes() {
  local n
  n="$(wc -c < "$1")"
  printf '%s\n' "${n//[[:space:]]/}"
}

# _done_response <out> [bad]: the 200 {status: done} answer of the fixture
# template with every quote_sha256 filled from the fixture tree, except the
# dependabot citation, whose hash never matches. With `bad`, no hash matches.
_done_response() {
  local t="$FIXTURES_PROPOSE/tree" bad='0000000000000000000000000000000000000000000000000000000000000bad'
  local c3 s3 s56 s5 r3
  c3="$(_lines_sha "$t/CONTRIBUTING.md" 3 3)"
  s3="$(_lines_sha "$t/SECURITY.md" 3 3)"
  s56="$(_lines_sha "$t/SECURITY.md" 5 6)"
  s5="$(_lines_sha "$t/SECURITY.md" 5 5)"
  r3="$(_lines_sha "$t/README.md" 3 3)"
  if [ "${2:-}" = bad ]; then
    c3="$bad"; s3="$bad"; s56="$bad"; s5="$bad"; r3="$bad"
  fi
  sed -e "s/@SHA_CONTRIB3@/$c3/" -e "s/@SHA_DEPENDABOT3@/$bad/" -e "s/@SHA_SEC3@/$s3/" \
    -e "s/@SHA_SEC5_6@/$s56/" -e "s/@SHA_SEC5@/$s5/" -e "s/@SHA_README3@/$r3/" \
    "$FIXTURES_PROPOSE/propose-done.template.json" > "$1"
  assert_file_not_contains "$1" '@SHA_' "every placeholder of the template was filled"
}

# Numbers of the curl calls to the propose route, one per line.
_propose_calls() {
  local i c
  c="$(curl_count)"
  for ((i = 1; i <= c; i++)); do
    if [ "$(curl_call "$i" url)" = "$SEETREX_PROPOSE_URL" ]; then
      printf '%s\n' "$i"
    fi
  done
}

_propose_call_count() {
  local n=0 i
  for i in $(_propose_calls); do
    n=$((n + 1))
  done
  printf '%s\n' "$n"
}

# Body file of the first call to the propose route; fails if there is none.
_first_propose_body() {
  local n
  n="$(_propose_calls | head -n 1)"
  [ -n "$n" ] || fail "no call to the propose route was made"
  printf '%s\n' "$(curl_call_dir "$n")/body"
}

_push_call_count() {
  local n=0 i c
  c="$(curl_count)"
  for ((i = 1; i <= c; i++)); do
    if [ "$(curl_call "$i" url)" = "$SEETREX_PUSH_URL" ]; then
      n=$((n + 1))
    fi
  done
  printf '%s\n' "$n"
}

_assert_record_kept() {
  assert_file_exists "$RUNNER_TEMP/seetrex-out/seetrex-record.json" "$1: the record file"
  assert_file_contains "$GITHUB_OUTPUT" "record=$RUNNER_TEMP/seetrex-out/seetrex-record.json" "$1: the record output"
  assert_line_eq "$RUN_STDOUT" "Seetrex recorded this push." "$1: the push was recorded"
}

# A live proposal run over the fixture tree: push 200, then the queued
# propose answers (202, 202, 200 done) unless the caller queued its own.
_live_case() {
  setup_case
  _commit_tree "$FIXTURES_PROPOSE/tree"
  set_api_response 200 "$FIXTURES_PROPOSE/push-200.json"
}

_queue_done() {
  _done_response "$CASE_DIR/done.json" "${1:-}"
  set_api_response 202 "$FIXTURES_PROPOSE/propose-202.json"
  set_api_response 202 "$FIXTURES_PROPOSE/propose-202.json"
  set_api_response 200 "$CASE_DIR/done.json"
}

test_intent_reader_action_sends_nothing_when_propose_is_off() {
  # INTENT: without propose: true nothing of the proposal step runs: one call
  # to Seetrex (the push), no detector line in the log, no proposals artifact
  # or output, the push body as before; and both inputs are off by default,
  # in action.yml and in run.sh's fallback, so a user who updates the Action
  # sends exactly what the README describes today.
  # CONTEXT: plan R4 section 2.2 (README:94-117 promises what leaves the
  # runner; the detectors change it, so they are opt-in).
  # EXPIRES IF: the proposal step becomes the default, with the README
  # rewritten in the same commit.
  local block
  setup_case
  _commit_tree "$FIXTURES_PROPOSE/tree"
  set_api_response 200 "$FIXTURES_PROPOSE/push-200.json"
  run_action
  assert_rc 0
  assert_eq 1 "$(api_call_count)" "one call to Seetrex: the push"
  assert_eq 0 "$(_propose_call_count)" "no call to the propose route"
  assert_eq 1 "$(token_call_count)" "one token"
  assert_file_not_contains "$RUN_STDOUT" "propos" "nothing about proposals in the log"
  assert_file_not_contains "$RUN_STDOUT" "Facts the detectors" "no detector output"
  assert_file_not_contains "$GITHUB_OUTPUT" "proposals=" "no proposals output"
  assert_no_file "$RUNNER_TEMP/seetrex-out/seetrex-proposals" "no proposals directory"
  _assert_record_kept "propose off"
  # action.yml: both inputs declared, both 'false' by default.
  for block in propose propose-with-model; do
    sed -n "/^  $block:\$/,/^  [a-z-]*:\$/p" "$ACTION_ROOT/action.yml" > "$TEST_TMP/input-$block"
    assert_line_eq "$TEST_TMP/input-$block" "    default: 'false'" "action.yml: $block defaults to 'false'"
  done
  assert_file_contains "$ACTION_ROOT/action.yml" 'INPUT_PROPOSE: ${{ inputs.propose }}' "action.yml maps propose"
  assert_file_contains "$ACTION_ROOT/action.yml" 'INPUT_PROPOSE_WITH_MODEL: ${{ inputs.propose-with-model }}' \
    "action.yml maps propose-with-model"
  assert_line_eq "$ACTION_ROOT/bin/run.sh" 'PROPOSE="${INPUT_PROPOSE:-false}"' "run.sh falls back to false"
  assert_line_eq "$ACTION_ROOT/bin/run.sh" 'WITH_MODEL="${INPUT_PROPOSE_WITH_MODEL:-false}"' "run.sh falls back to false (model)"

  # propose-with-model without propose: refused before anything runs.
  setup_case
  set_api_response 200 "$FIXTURES_PROPOSE/push-200.json"
  run_action propose-with-model=true
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "Input propose-with-model needs propose: true as well: nothing was sent." "fixed line"
  assert_eq 0 "$(curl_count)" "no request at all"
  if trivy_ran; then fail "propose-with-model alone: trivy ran"; fi

  # Hostile values of the two inputs are refused like the other inputs.
  setup_case
  set_api_response 200 "$FIXTURES_PROPOSE/push-200.json"
  run_action propose=TRUE
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "Input propose must be true or false: nothing was sent." "propose=TRUE refused"
  assert_eq 0 "$(curl_count)" "propose=TRUE: no request"
  reset_logs
  run_action propose=true propose-with-model=yes
  assert_rc 1
  assert_line_eq "$RUN_STDOUT" "Input propose-with-model must be true or false: nothing was sent." "with-model=yes refused"
  assert_eq 0 "$(curl_count)" "with-model=yes: no request"
}

test_intent_reader_action_dry_run_lists_files_and_sends_nothing() {
  # INTENT: dry-run with propose and propose-with-model lists every fact
  # (id, path:lines, hash) and every document that would be sent (path,
  # bytes, sha256), and makes no request at all beyond the Trivy download: no
  # token, no push, no proposal.
  # CONTEXT: plan R4 section 2.2 (test mode) and E2 14 step 4.
  # EXPIRES IF: dry-run is removed.
  local t="$FIXTURES_PROPOSE/tree" d
  setup_case
  _commit_tree "$t"
  set_api_response 200 "$FIXTURES_PROPOSE/push-200.json"
  run_action dry-run=true propose=true propose-with-model=true
  assert_rc 0
  assert_eq 1 "$(curl_count)" "one request: the Trivy download"
  assert_eq 1 "$(download_call_count)" "it is the Trivy download"
  assert_eq 0 "$(token_call_count)" "no token"
  assert_eq 0 "$(api_call_count)" "no Seetrex call"
  assert_line_eq "$RUN_STDOUT" "- security_policy_file: SECURITY.md:3-3, sha256 $(_lines_sha "$t/SECURITY.md" 3 3)" "a fact line"
  assert_line_eq "$RUN_STDOUT" "- security_analyzer_step: .github/workflows/codeql.yml:12-12, sha256 $(_lines_sha "$t/.github/workflows/codeql.yml" 12 12)" \
    "an analyzer fact line"
  for d in README.md SECURITY.md CONTRIBUTING.md docs/threat-model.md; do
    assert_line_eq "$RUN_STDOUT" "- $d: $(_file_bytes "$t/$d") bytes, sha256 $(_sha "$t/$d")" "document line: $d"
  done
  assert_file_not_contains "$RUN_STDOUT" "- src/main.rs" "code is not a document"
  assert_file_not_contains "$RUN_STDOUT" "- docs/security-notes.md" "a file off the list is not a document"
  assert_line_eq "$RUN_STDOUT" "Dry run: a proposal request with 10 facts and 4 documents would be sent to Seetrex after the push. Nothing was sent." \
    "the dry-run proposal line"
  assert_line_eq "$RUN_STDOUT" "Dry run: nothing was sent to Seetrex." "the push dry-run line"
  assert_file_contains "$GITHUB_STEP_SUMMARY" "would be sent to Seetrex after the push" "the proposal line is in the summary"
  assert_file_not_contains "$GITHUB_OUTPUT" "proposals=" "no artifact"
  # Never text: no line of any file in the log.
  assert_file_not_contains "$RUN_STDOUT" "Reporting a Vulnerability" "a heading in the log"
  assert_file_not_contains "$RUN_STDOUT" "security@example.invalid" "an address in the log"
  assert_file_not_contains "$RUN_STDOUT" "Secure by default" "a README line in the log"

  # Without propose-with-model: facts only, no document line.
  reset_logs
  run_action dry-run=true propose=true
  assert_rc 0
  assert_eq 0 "$(api_call_count)" "facts only: no Seetrex call"
  assert_file_not_contains "$RUN_STDOUT" "Documents for the reader" "facts only: no document list"
  assert_line_eq "$RUN_STDOUT" "Dry run: a proposal request with 10 facts and 0 documents would be sent to Seetrex after the push. Nothing was sent." \
    "facts only: the line says 0 documents"
}

test_intent_job_log_lists_every_document_before_sending() {
  # INTENT: with propose-with-model, the job log lists every document exactly
  # as it is sent (path, bytes, sha256), and the list is written before the
  # token is requested: when the token service fails, the list is already in
  # the log and nothing was sent. Listed = sent (E2 14 criterion c).
  # CONTEXT: plan R4 section 2.2 (log of files, molde dry_file_line).
  # EXPIRES IF: the documents stop leaving the runner.
  local t="$FIXTURES_PROPOSE/tree" body d n_body
  _live_case
  _queue_done
  run_action propose=true propose-with-model=true
  assert_rc 0
  body="$(_first_propose_body)"
  n_body="$(jq '.start.documents | length' "$body" | tr -d '\r')"
  assert_eq 4 "$n_body" "four documents in the request"
  for d in README.md SECURITY.md CONTRIBUTING.md docs/threat-model.md; do
    assert_line_eq "$RUN_STDOUT" "- $d: $(_file_bytes "$t/$d") bytes, sha256 $(_sha "$t/$d")" "listed: $d"
    assert_json "$body" "[.start.documents[] | select(.path == \"$d\")] | length == 1 and (.[0].bytes == $(_file_bytes "$t/$d")) and (.[0].sha256 == \"$(_sha "$t/$d")\")" \
      "sent as listed: $d"
    assert_eq "$(cat "$t/$d")" "$(jq -r --arg p "$d" '.start.documents[] | select(.path == $p) | .text' "$body" | tr -d '\r')" "sent whole: $d"
  done
  assert_json "$body" '[.start.documents[].path] | sort == ["CONTRIBUTING.md", "README.md", "SECURITY.md", "docs/threat-model.md"]' \
    "no document beyond the listed four"
  assert_line_eq "$RUN_STDOUT" "Requesting proposals from Seetrex for 5 categories, with 10 facts and 4 documents." "the request line"

  # Token service down: the list is in the log, nothing was requested.
  _live_case
  printf '{"message":"nope"}\n' > "$CASE_DIR/tok500.json"
  set_token_response 500 "$CASE_DIR/tok500.json"
  run_action propose=true propose-with-model=true
  assert_rc 1
  assert_eq 0 "$(api_call_count)" "token down: no call to Seetrex at all"
  assert_eq 0 "$(_propose_call_count)" "token down: no proposal request"
  # The push itself failed on the token (fixed line of run.sh), before the
  # proposal step: the listing happens only after a recorded push.
  assert_line_eq "$RUN_STDOUT" "The OIDC token could not be obtained from the runner: nothing was sent." "push: token line"
  assert_file_not_contains "$RUN_STDOUT" "Documents for the reader" "no proposal step without a recorded push"

  # The reader is unreachable: push recorded, the request attempted once and
  # failed. ORDER, measured in the log: every document line comes before the
  # request line (printed just before the token for the proposal is asked
  # for), which comes before the warning that only the failed POST prints;
  # the POST itself was made, and carried exactly the listed documents.
  local n_doc n_req n_warn
  _live_case
  set_api_transport_error 7
  run_action propose=true propose-with-model=true
  assert_rc 0
  _assert_record_kept "reader unreachable"
  tr -d '\r' < "$RUN_STDOUT" > "$CASE_DIR/stdout.lf"
  n_req="$(grep -n -x -F -e "Requesting proposals from Seetrex for 5 categories, with 10 facts and 4 documents." "$CASE_DIR/stdout.lf" | cut -d: -f1)"
  n_warn="$(grep -n -x -F -e "::warning::Seetrex could not be reached for the proposal: no proposal; the record of this push is not affected." "$CASE_DIR/stdout.lf" | cut -d: -f1)"
  assert_ne "" "$n_req" "unreachable: the request line"
  assert_ne "" "$n_warn" "unreachable: the warning of the failed POST"
  for d in README.md SECURITY.md CONTRIBUTING.md docs/threat-model.md; do
    n_doc="$(grep -n -x -F -e "- $d: $(_file_bytes "$t/$d") bytes, sha256 $(_sha "$t/$d")" "$CASE_DIR/stdout.lf" | cut -d: -f1)"
    assert_ne "" "$n_doc" "unreachable: listed $d"
    if [ "$n_doc" -ge "$n_req" ]; then fail "$d is listed (line $n_doc) after the request line (line $n_req)"; fi
  done
  if [ "$n_req" -ge "$n_warn" ]; then fail "the request line (line $n_req) comes after the POST's warning (line $n_warn)"; fi
  assert_eq 1 "$(_propose_call_count)" "unreachable: the POST was made once"
  assert_json "$(_first_propose_body)" '[.start.documents[].path] | sort == ["CONTRIBUTING.md", "README.md", "SECURITY.md", "docs/threat-model.md"]' \
    "unreachable: the POST carried exactly the listed documents"
}

test_intent_detectors_never_send_text() {
  # INTENT: with propose alone, the proposal request carries the categories
  # and the facts (id, path, line_start, line_end, line_sha256) and nothing
  # else: no documents key, no line of any file, no heading, address, command
  # or package; the facts are those of the commit tree.
  # CONTEXT: plan R4 section 2.1 (data table: facts leave the runner, text
  # only with propose-with-model, code never).
  # EXPIRES IF: the contract adds a field to a fact.
  local t="$FIXTURES_PROPOSE/tree" body s
  _live_case
  _queue_done
  run_action propose=true
  assert_rc 0
  body="$(_first_propose_body)"
  assert_json "$body" 'keys == ["start", "version"] and .version == 1' "top-level keys"
  assert_json "$body" '.start | keys == ["categories", "facts", "scan"]' "start: categories, facts and the scan counts only, no documents"
  assert_json "$body" '.start.categories | sort == ["cvd_disclosure_report", "secure_config_report", "secure_design_report", "security_updates_policy", "third_party_components_report"]' \
    "the not_documented categories of the push answer"
  assert_json "$body" '[.start.facts[] | keys] | all(. == ["id", "line_end", "line_sha256", "line_start", "path"])' \
    "a fact has exactly five fields"
  assert_json "$body" '.start.facts | length == 10' "the ten facts of the fixture tree"
  assert_json "$body" "[.start.facts[] | select(.id == \"security_policy_file\")] == [{id: \"security_policy_file\", path: \"SECURITY.md\", line_start: 3, line_end: 3, line_sha256: \"$(_lines_sha "$t/SECURITY.md" 3 3)\"}]" \
    "the SECURITY.md heading fact, by hash"
  for s in 'Reporting a Vulnerability' 'security@example.invalid' 'codeql-action' 'package-ecosystem' 'Threat model' \
    'fn main' 'Secure by default' 'maintainers' 'Dependencies are reviewed'; do
    assert_file_not_contains "$body" "$s" "the request carries [$s]"
    assert_file_not_contains "$RUN_STDOUT" "$s" "the log carries [$s]"
    assert_file_not_contains "$GITHUB_STEP_SUMMARY" "$s" "the summary carries [$s]"
  done
  assert_file_not_contains "$body" '"text"' "no text field anywhere in the request"
  # The push body did not change either (call 3: download, token, push).
  assert_eq 1 "$(_push_call_count)" "one push"
  assert_json "$(curl_call_dir 3)/body" 'keys == ["sbom", "trivy"]' "the push body is the usual one"
}

test_intent_model_list_is_fixed_names_only() {
  # INTENT: the documents sent with propose-with-model are only files whose
  # repository path is on the closed list of exact names of the contract:
  # never source code, a workflow, dependabot.yml, a lockfile, a file with a
  # similar name or a file in another directory; the list in propose.sh is
  # the contract's.
  # CONTEXT: reader contract 1 (model_document_path); amendment #334 (text
  # documents of fixed name, never code).
  # EXPIRES IF: the contract changes its list (then this one changes with it).
  local body p list_line
  _live_case
  printf 'docs: content\n' > "$CASE_DIR/f"
  commit_file "$CASE_DIR/f" README.md.bak
  commit_file "$CASE_DIR/f" docs/README.md
  commit_file "$CASE_DIR/f" SECURITY.txt
  commit_file "$CASE_DIR/f" package-lock.json
  commit_file "$CASE_DIR/f" SUPPORT.md
  make_event private
  _queue_done
  run_action propose=true propose-with-model=true
  assert_rc 0
  body="$(_first_propose_body)"
  assert_json "$body" '[.start.documents[].path] | sort == ["CONTRIBUTING.md", "README.md", "SECURITY.md", "SUPPORT.md", "docs/threat-model.md"]' \
    "exactly the listed names that exist"
  for p in README.md.bak docs/README.md SECURITY.txt package-lock.json src/main.rs docs/security-notes.md \
    .github/workflows/codeql.yml .github/dependabot.yml package.json CODEOWNERS .well-known/security.txt; do
    assert_json "$body" "[.start.documents[] | select(.path == \"$p\")] | length == 0" "never sent: $p"
  done
  assert_file_not_contains "$body" 'fn main' "no code in the request"
  assert_file_not_contains "$body" 'package-ecosystem' "no dependabot.yml in the request"
  assert_file_not_contains "$ACTION_ROOT/bin/propose.sh" 'find "$TREE"' "no search of the tree for documents"
  # The list propose.sh reads is the contract's (the copy of the schema in
  # tests/fixtures/contract), in its order; propose.sh has no list of its own.
  assert_eq "$(jq -c '."$defs".model_document_path.enum' "$CONTRACT_FIXTURES/propose-request.schema.json" | tr -d '\r')" \
    "$(jq -c '.model_documents' "$ACTION_ROOT/bin/contract/reader-contract-1.json" | tr -d '\r')" "the runtime list is the contract's"
  assert_file_not_contains "$ACTION_ROOT/bin/propose.sh" 'CHANGELOG.md' "no list of names of its own in propose.sh"
  # Files of the contract's list are sent (PRIVACY.md, .github/THREAT_MODEL.md);
  # CHANGELOG.md, off the list, is not.
  _live_case
  printf 'docs: privacy\n' > "$CASE_DIR/p"
  commit_file "$CASE_DIR/p" PRIVACY.md
  commit_file "$CASE_DIR/p" .github/THREAT_MODEL.md
  commit_file "$CASE_DIR/p" CHANGELOG.md
  make_event private
  _queue_done
  run_action propose=true propose-with-model=true
  assert_rc 0
  body="$(_first_propose_body)"
  assert_json "$body" '[.start.documents[].path] | sort == [".github/THREAT_MODEL.md", "CONTRIBUTING.md", "PRIVACY.md", "README.md", "SECURITY.md", "docs/threat-model.md"]' \
    "PRIVACY.md and .github/THREAT_MODEL.md are sent, CHANGELOG.md is not"
  assert_file_not_contains "$RUN_STDOUT" "- CHANGELOG.md" "CHANGELOG.md is not even listed"
}

test_intent_runner_drops_citation_whose_hash_mismatches() {
  # INTENT: every citation of the answer is rehydrated from the local file of
  # the commit and its quote_sha256 compared; a citation that does not match
  # is dropped and its field is false in the proposed envelope, the review
  # says "not found" for it, and a category left with no cited true is
  # delivered as nothing found. A matching citation is kept with its quote
  # rehydrated locally in the review.
  # CONTEXT: plan R4 section 2.1 (third check of the citation) and section 1
  # (zero cited true = nothing found).
  # EXPIRES IF: the server returns the quote itself (it never does: no text).
  local art t="$FIXTURES_PROPOSE/tree"
  _live_case
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  _queue_done
  run_action propose=true propose-with-model=true
  assert_rc 0
  assert_file_exists "$art/third_party_components_report.json" "tpc: ready envelope"
  assert_json "$art/third_party_components_report.json" '.payload.due_diligence.process_documented == true' \
    "tpc: the matching citation keeps its true"
  assert_json "$art/third_party_components_report.json" '.payload.due_diligence.applies_to_open_source == false' \
    "tpc: the mismatching citation's field is false"
  assert_json "$art/third_party_components_report.json" \
    '.schema == "seetrex.attestation.v2" and .category == "third_party_components_report" and .attested_via == "reader+person"' \
    "tpc: envelope header"
  assert_file_contains "$art/third_party_components_report.review.md" '- `due_diligence.process_documented` = true: `CONTRIBUTING.md:3-3`' \
    "tpc review: the kept citation with its locator"
  assert_file_contains "$art/third_party_components_report.review.md" '    Dependencies are reviewed before they are added; see docs/DEPENDENCIES.md.' \
    "tpc review: the quote rehydrated from the local file"
  assert_file_contains "$art/third_party_components_report.review.md" '- `due_diligence.applies_to_open_source` = false: not found' \
    "tpc review: the dropped citation is not found"
  assert_file_not_contains "$art/third_party_components_report.review.md" 'package-ecosystem' "tpc review: no quote for a dropped citation"
  # Three matching citations, one spanning two lines.
  assert_json "$art/cvd_disclosure_report.json" '.payload.cvd_policy.in_place == true and .payload.vulnerability_information_sharing.reporting_contact_address_provided == true and .payload.vulnerability_information_sharing.measures_in_place == true' \
    "cvd: the three citations kept"
  assert_file_contains "$art/cvd_disclosure_report.review.md" '    We acknowledge reports within 5 working days.' "cvd review: second line of the quote"
  # Summary: only paths and lines; citations, never "facts".
  assert_file_contains "$GITHUB_STEP_SUMMARY" '| `cra-art13-third-party-components` | `third_party_components_report` | proposal ready (1 citation: CONTRIBUTING.md:3-3) |' \
    "summary: tpc with one citation"
  assert_file_contains "$GITHUB_STEP_SUMMARY" '| `cra-annex1p2-cvd-disclosure` | `cvd_disclosure_report` | proposal ready (3 citations: SECURITY.md:3-3, SECURITY.md:5-5, SECURITY.md:5-6) |' \
    "summary: cvd with three citations"
  assert_file_contains "$GITHUB_STEP_SUMMARY" '| `cra-annex1-secure-design` | `secure_design_report` | nothing found |' "summary: nothing found"
  assert_file_not_contains "$GITHUB_STEP_SUMMARY" 'fact cited' "summary: no citation is called a fact"
  assert_file_not_contains "$GITHUB_STEP_SUMMARY" 'facts cited' "summary: no citations are called facts"
  assert_file_not_contains "$GITHUB_STEP_SUMMARY" 'Dependencies are reviewed' "summary: no quote"
  assert_line_eq "$RUN_STDOUT" "Seetrex proposed attestations for review: 5 citations kept, 1 dropped (not verified against this commit), 7 files in the seetrex-proposals artifact." \
    "the closing line counts kept and dropped"
  assert_file_contains "$GITHUB_OUTPUT" "proposals=$art" "the artifact output"
  # The unrequested category of the answer is ignored.
  assert_no_file "$art/user_information_report.json.pending" "an unrequested category writes nothing"
  assert_no_file "$art/user_information_report.review.md" "an unrequested category writes no review"

  # Every hash wrong: no envelope is delivered, every proposal is nothing found.
  _live_case
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  _queue_done bad
  run_action propose=true propose-with-model=true
  assert_rc 0
  assert_no_file "$art/third_party_components_report.json" "all bad: no tpc envelope"
  assert_no_file "$art/cvd_disclosure_report.json" "all bad: no cvd envelope"
  assert_no_file "$art/secure_config_report.json.pending" "all bad: no pending envelope"
  assert_file_contains "$GITHUB_STEP_SUMMARY" '| `cra-art13-third-party-components` | `third_party_components_report` | nothing found |' \
    "all bad: tpc nothing found"
  assert_line_eq "$RUN_STDOUT" "Seetrex proposed attestations for review: 0 citations kept, 6 dropped (not verified against this commit), 1 files in the seetrex-proposals artifact." \
    "all bad: counts"
  _assert_record_kept "all bad"

  # A citation past the end of the file, and one whose file does not exist.
  _live_case
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  _done_response "$CASE_DIR/done.json"
  jq '.proposals.cvd_disclosure_report.citations[2].line_start = 400 | .proposals.cvd_disclosure_report.citations[2].line_end = 400
      | .proposals.cvd_disclosure_report.citations[0].path = "docs/MISSING.md"
      | .proposals.cvd_disclosure_report.citations[1].line_start = 400 | .proposals.cvd_disclosure_report.citations[1].line_end = 400' \
    "$CASE_DIR/done.json" > "$CASE_DIR/done2.json"
  set_api_response 200 "$CASE_DIR/done2.json"
  run_action propose=true propose-with-model=true
  assert_rc 0
  assert_no_file "$art/cvd_disclosure_report.json" "out of range and missing file: cvd nothing found"
  assert_eq 1 "$(_propose_call_count)" "a 200 done at once is not polled"
  assert_eq 0 "$(sleep_count)" "no wait without a 202"
  if [ ! -f "$t/SECURITY.md" ]; then fail "fixture tree moved"; fi
}

test_intent_pending_proposal_is_not_a_json_attestation() {
  # INTENT: a needs_person proposal is written as <category>.json.pending
  # (never <category>.json), its review lists the pending fields as "decide
  # yourself", and if a person commits the .pending file as it is under
  # .seetrex/attestations/ the Action does not send it: only *.json is read.
  # CONTEXT: plan R4 section 2.6 (a .pending is not ingested by mistake;
  # run.sh:473 reads *.json only).
  # EXPIRES IF: the attestation reader of run.sh changes its glob.
  local art review
  _live_case
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  _queue_done
  run_action propose=true propose-with-model=true
  assert_rc 0
  assert_file_exists "$art/secure_config_report.json.pending" "needs_person: .json.pending"
  assert_no_file "$art/secure_config_report.json" "needs_person: no .json"
  assert_json "$art/secure_config_report.json.pending" \
    '.schema == "seetrex.attestation.v2" and .attested_via == "reader+person" and .payload.secure_configuration.secure_by_default == true and .payload.secure_configuration.tailor_made_agreement == false' \
    "the pending envelope"
  review="$art/secure_config_report.review.md"
  assert_file_contains "$review" '- `security_updates_capability.auto_updates.applicable`: decide yourself (proposed as true, the value that exempts nothing)' \
    "review: a pending field with its fixed value"
  assert_file_contains "$review" '- `secure_configuration.secure_by_default` = true: `README.md:3-3`' "review: the cited true"
  assert_file_contains "$review" '    Secure by default: every option ships closed.' "review: the quote"
  assert_file_contains "$review" '- `security_updates_capability.updates_mechanism` = false: not found' "review: a false"
  assert_file_not_contains "$review" '- `secure_configuration.tailor_made_agreement` = false: not found' "review: a pending field is not 'not found'"
  assert_file_contains "$GITHUB_STEP_SUMMARY" '| `cra-annex1-secure-config-updates` | `secure_config_report` | needs a person (8 fields to decide; 1 citation: README.md:3-3) |' \
    "summary: needs a person"
  # security_updates_policy: never an envelope, a review of its fields.
  assert_no_file "$art/security_updates_policy.json" "sup: no envelope"
  assert_no_file "$art/security_updates_policy.json.pending" "sup: no pending envelope"
  assert_file_contains "$art/security_updates_policy.review.md" '- `policy.support_period_end_at`: decide yourself' "sup review"
  assert_file_contains "$GITHUB_STEP_SUMMARY" '| `cra-art13-security-updates` | `security_updates_policy` | needs a person (9 fields to decide; no citation) |' \
    "summary: sup"

  # Committed as it is, the .pending file is not an attestation (a copy: the
  # next run removes the artifact directory first).
  cp "$art/secure_config_report.json.pending" "$CASE_DIR/pending.json"
  commit_attestation "$CASE_DIR/pending.json" secure_config_report.json.pending
  make_event private
  reset_logs
  set_api_response 200 "$FIXTURES_PROPOSE/push-200.json"
  run_action
  assert_rc 0
  assert_json "$(curl_call_dir 3)/body" 'has("attestations") | not' "a .json.pending under .seetrex/attestations/ is not sent"
  # Renamed to .json, it is.
  commit_attestation "$CASE_DIR/pending.json" secure_config_report.json
  make_event private
  reset_logs
  run_action
  assert_rc 0
  assert_json "$(curl_call_dir 3)/body" '.attestations | length == 1' "renamed to .json, the person's decision is sent"
}

test_intent_credential_pattern_file_is_not_sent() {
  # INTENT: a document of the fixed list whose text matches a credential
  # pattern (a private key block, a password assignment) is left out of the
  # request, the log says so by path and pattern name only, and no byte of it
  # reaches the body; the other documents still go.
  # CONTEXT: plan R4 section 2.1 step 3 (credential filter in the runner, the
  # reader filters again).
  # EXPIRES IF: the filter moves to the server only.
  local body
  _live_case
  commit_file "$FIXTURES_PROPOSE/key-SECURITY.md" SECURITY.md
  commit_file "$FIXTURES_PROPOSE/password-README.md" README.md
  make_event private
  _queue_done
  run_action propose=true propose-with-model=true
  assert_rc 0
  body="$(_first_propose_body)"
  assert_json "$body" '[.start.documents[].path] | sort == ["CONTRIBUTING.md", "docs/threat-model.md"]' "the two clean documents only"
  assert_file_not_contains "$body" 'PRIVATE KEY' "no key block in the request"
  assert_file_not_contains "$body" 'MIIEfixture' "no key bytes in the request"
  assert_file_not_contains "$body" 'hunter2' "no password in the request"
  assert_line_eq "$RUN_STDOUT" "- SECURITY.md: left out (a line looks like a credential: private_key_block)" "the log names the file left out"
  assert_line_eq "$RUN_STDOUT" "- README.md: left out (a line looks like a credential: assignment_of_secret)" "the log names the second file left out"
  assert_file_not_contains "$RUN_STDOUT" 'hunter2' "no password in the log"
  assert_file_not_contains "$RUN_STDOUT" 'PRIVATE KEY' "no key marker in the log"
  assert_file_not_contains "$GITHUB_STEP_SUMMARY" 'hunter2' "no password in the summary"
  # (the replaced SECURITY.md has no Supported Versions heading: 9 facts)
  assert_line_eq "$RUN_STDOUT" "Requesting proposals from Seetrex for 5 categories, with 9 facts and 2 documents." "two documents counted"

  # An empty document and one over the cap are left out too.
  _live_case
  : > "$CASE_DIR/empty"
  commit_file "$CASE_DIR/empty" PRIVACY.md
  head -c 70000 /dev/zero | tr '\0' 'x' > "$CASE_DIR/big"
  commit_file "$CASE_DIR/big" SUPPORT.md
  make_event private
  _queue_done
  run_action propose=true propose-with-model=true
  assert_rc 0
  body="$(_first_propose_body)"
  assert_json "$body" '[.start.documents[].path] | sort == ["CONTRIBUTING.md", "README.md", "SECURITY.md", "docs/threat-model.md"]' \
    "empty and oversize documents are not sent"
  assert_line_eq "$RUN_STDOUT" "- PRIVACY.md: left out (empty)" "empty: said"
  assert_line_eq "$RUN_STDOUT" "- SUPPORT.md: left out (70000 bytes, over the 64 KiB cap)" "oversize: said"
}

test_intent_propose_failure_never_fails_the_record() {
  # INTENT: whatever the reader does (unavailable, rate limit, refusal,
  # non-JSON, a ticket never finished, an unreadable answer), the push stays
  # recorded (record file, output, line) and the job is green with a warning;
  # with strict the job fails but the record is still written. The proposal
  # polls with a fresh token and growing waits, and gives up.
  # CONTEXT: plan R4 section 3 (R4-4: a reader failure is a warning, never a
  # failed record, except strict) and section 2.4 (tickets, new token each
  # poll).
  # EXPIRES IF: the proposal step is folded into the push request.
  local strict want i
  for strict in false true; do
    _live_case
    set_api_response 503 "$FIXTURES_PROPOSE/propose-503.json"
    run_action propose=true strict="$strict"
    want=0
    [ "$strict" = false ] || want=1
    assert_rc "$want"
    _assert_record_kept "strict=$strict, 503"
    assert_line_eq "$RUN_STDOUT" "::warning::Seetrex's reader is unavailable (503): no proposal; the record of this push is not affected." \
      "strict=$strict: the warning"
    assert_eq 1 "$(_propose_call_count)" "strict=$strict: one proposal request, no retry"
    assert_eq 2 "$(token_call_count)" "strict=$strict: one token for the push, one for the proposal"
    assert_no_file "$RUNNER_TEMP/seetrex-out/seetrex-proposals" "strict=$strict: no artifact"
    assert_file_not_contains "$GITHUB_OUTPUT" "proposals=" "strict=$strict: no proposals output"
  done

  # A 401 and a non-JSON 200: warnings, green.
  _live_case
  printf '{"error":"unauthorized"}\n' > "$CASE_DIR/r401.json"
  set_api_response 401 "$CASE_DIR/r401.json"
  run_action propose=true
  assert_rc 0
  _assert_record_kept "401"
  assert_line_eq "$RUN_STDOUT" "::warning::Seetrex did not accept the proposal request (401): no proposal; the record of this push is not affected." "401 warning"
  _live_case
  set_api_response 200 "$TESTS_DIR/fixtures/run/resp-html.html"
  run_action propose=true
  assert_rc 0
  _assert_record_kept "html"
  assert_line_eq "$RUN_STDOUT" "::warning::Seetrex answered the proposal request with something this version cannot read: no proposal; the record of this push is not affected." \
    "non-JSON warning"

  # A ticket that never finishes: polls with a fresh token each time and
  # growing waits, then gives up with a warning.
  _live_case
  set_api_response 202 "$FIXTURES_PROPOSE/propose-202.json"
  run_action propose=true
  assert_rc 0
  _assert_record_kept "ticket"
  # The 10-minute budget of waits binds before the 40 polls: 5 + 10 + 20 +
  # 18 x 30 = 575 s, and one more wait would pass 600 s.
  assert_eq 22 "$(_propose_call_count)" "the start and twenty-one polls"
  assert_eq 23 "$(token_call_count)" "a fresh token for the push and for each of the 22 proposal requests"
  assert_eq 21 "$(sleep_count)" "twenty-one waits"
  assert_eq $'5\n10\n20\n30\n30' "$(sleep_log | head -n 5)" "backoff 5, 10, 20, 30, 30..."
  assert_eq 575 "$(sleep_log | awk '{ s += $1 } END { print s }')" "575 s of waits in all, under the 600 s cap"
  assert_line_eq "$RUN_STDOUT" "::warning::Seetrex's reader did not finish in time: no proposal; the record of this push is not affected." "gave up"
  for i in $(_propose_calls | tail -n +2); do
    assert_eq '{"version":1,"ticket":"Qm9vdHN0cmFwVGlja2V0MDAwMDAwMDAwMDAwMDAwMA"}' "$(curl_call "$i" body)" "poll $i carries the ticket only"
    assert_line_eq "$(curl_call_dir "$i")/headers" "Authorization: Bearer $FAKE_JWT" "poll $i is authenticated"
  done
  grep -F -e "$FAKE_JWT" "$RUN_STDOUT" | grep -v -F -e "::add-mask::$FAKE_JWT" > "$CASE_DIR/jwt-lines" || true
  assert_eq "" "$(cat "$CASE_DIR/jwt-lines")" "the JWT reaches the log only as an add-mask line"

  # The happy path polls twice, then writes the artifact; the record first.
  _live_case
  _queue_done
  run_action propose=true strict=true
  assert_rc 0
  _assert_record_kept "done"
  assert_eq 3 "$(_propose_call_count)" "start plus two polls"
  assert_eq $'5\n10' "$(sleep_log)" "two waits"
  assert_eq 4 "$(token_call_count)" "four tokens"
  assert_json "$(curl_call_dir 3)/body" 'keys == ["sbom", "trivy"]' "the push body is a push"
  assert_json "$(_first_propose_body)" '.start.categories | length == 5' "the start request"
}

# ------------------------------------------------ reader contract 1 (R4-4 r2)

# _validate <schema name> <$defs entry or ""> <doc>: the errors of <doc>
# against the copy of the contract in tests/fixtures/contract ("[]" = valid).
_validate() {
  jq -c -n --slurpfile schema "$CONTRACT_FIXTURES/$1.schema.json" --slurpfile doc "$3" --arg def "$2" \
    -f "$CONTRACT_FIXTURES/validate.jq" | tr -d '\r'
}

# _sent_trivy_sha <push body>: SHA-256 of the `trivy` string of a push body,
# decoded byte for byte (base64, so no newline is added on the way).
_sent_trivy_sha() {
  local line
  line="$(jq -r '.trivy | @base64' "$1" | tr -d '\r\n' | base64 -d | sha256sum)"
  printf '%s\n' "${line%% *}"
}

# _push_with_mlr <out>: the push answer with monitoring-lifecycle not_documented.
_push_with_mlr() {
  jq '(.results.obligations[] | select(.ruleset_id == "cra-annex1-monitoring-lifecycle"))
      |= {ruleset_id, status: "not_documented"}' "$FIXTURES_PROPOSE/push-200.json" > "$1"
}

# _mlr_response <out> <finding_count> <scanned_packages> <report_sha256>: a
# done answer whose only proposal is monitoring_lifecycle_report with one
# scan citation carrying those values.
_mlr_response() {
  jq -n --argjson f "$2" --argjson p "$3" --arg sha "$4" '{version: 1, status: "done", proposals: {
    monitoring_lifecycle_report: {state: "needs_person",
      citations: [{field: "market_availability.no_known_exploitable_vulnerabilities", value: true,
                   source: "vuln_scan", finding_count: $f, scanned_packages: $p, report_sha256: $sha}],
      pending_fields: ["data_lifecycle.transfer_applicable", "data_lifecycle.secure_transfer"]}}}' > "$1"
}

test_intent_propose_request_follows_the_contract() {
  # INTENT: the proposal request is valid against propose-request.schema.json
  # of the contract in force (copied in tests/fixtures/contract, read by a
  # validator of its own keywords): start only carries the keys of the
  # schema, every document path is in its enum, and start.scan carries the
  # scan of the push: finding_count of the reduced report, scanned_packages
  # (library components of the SBOM of the same push) and report_sha256 equal
  # to the SHA-256 of exactly the `trivy` string the push sent. A poll is
  # valid too. The dry run shows the same scan.
  # CONTEXT: R4-4 review round 1 (the branch was written on an older
  # contract; a pretty-printed report made report_sha256 never match).
  # EXPIRES IF: the contract changes version.
  local body push sha start_keys
  _live_case
  # The SBOM carries an `application` component next to the library, nested
  # under it: scanned_packages counts the library only.
  jq '.components[0].components = [{"bom-ref": "fixture-app", type: "application", name: "fixture-app"}]' \
    "$FIXTURES_COMMON/sbom.cdx.json" > "$CASE_DIR/sbom-app.json"
  set_trivy_fixture cyclonedx "$CASE_DIR/sbom-app.json"
  _queue_done
  run_action propose=true propose-with-model=true
  assert_rc 0
  assert_json "$(curl_call_dir 3)/body" '[.sbom | fromjson | .components | .. | objects | select(has("bom-ref")) | .type] | sort == ["application", "library"]' \
    "the push sent the SBOM with an application and a library"
  body="$(_first_propose_body)"
  assert_eq '[]' "$(_validate propose-request '' "$body")" "the start request is valid against the contract"
  start_keys="$(jq -c '."$defs".start.properties | keys' "$CONTRACT_FIXTURES/propose-request.schema.json" | tr -d '\r')"
  assert_json "$body" "(.start | keys) - $start_keys == []" "start has only keys of the schema"
  assert_json "$body" "[.start.documents[].path] - $(jq -c '."$defs".model_document_path.enum' "$CONTRACT_FIXTURES/propose-request.schema.json" | tr -d '\r') == []" \
    "every document path is in the contract's enum"
  assert_json "$body" '.start.scan | keys == ["finding_count", "report_sha256", "scanned_packages"]' "the scan carrier"
  push="$(curl_call_dir 3)/body"
  assert_json "$push" 'keys == ["sbom", "trivy"]' "call 3 is the push"
  sha="$(_sent_trivy_sha "$push")"
  assert_json "$body" ".start.scan.report_sha256 == \"$sha\"" "report_sha256 is the hash of the trivy string the push sent"
  assert_json "$body" ".start.scan.finding_count == $(jq '.trivy | fromjson | [.Results[]?.Vulnerabilities[]?] | length' "$push" | tr -d '\r')" \
    "finding_count is the number of entries of the report sent"
  assert_json "$body" '.start.scan.finding_count == 2 and .start.scan.scanned_packages == 1' "the fixture: 2 findings over 1 library"
  # A poll is valid against the contract too.
  printf '%s' "$(curl_call "$(_propose_calls | sed -n 2p)" body)" > "$CASE_DIR/poll.json"
  assert_eq '[]' "$(_validate propose-request '' "$CASE_DIR/poll.json")" "the poll is valid against the contract"

  # The dry run lists the same scan.
  reset_logs
  run_action dry-run=true propose=true
  assert_rc 0
  assert_line_eq "$RUN_STDOUT" "Scan of the push: 2 findings over 1 packages, report sha256 $sha" "the dry run shows the scan"
}

test_intent_scan_citation_kept_only_when_it_matches_the_sent_scan() {
  # INTENT: the scanner-backed true of monitoring_lifecycle_report is kept
  # only when its finding_count, scanned_packages and report_sha256 are the
  # values this run sent, with zero findings over at least one package;
  # otherwise it is dropped and the category is nothing found.
  # CONTEXT: plan R4 section 1 (the one D field of the scanner) and R4-4
  # review round 1 (the citation was dropped always).
  # EXPIRES IF: the scanner field leaves the contract.
  local art sha
  setup_case
  _commit_tree "$FIXTURES_PROPOSE/tree"
  set_trivy_fixture json "$FIXTURES_PROPOSE/trivy-clean.json"
  _push_with_mlr "$CASE_DIR/push.json"
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  run_action dry-run=true propose=true
  assert_rc 0
  sha="$(sed -n 's/^Scan of the push: 0 findings over 1 packages, report sha256 \([0-9a-f]\{64\}\)\r\{0,1\}$/\1/p' "$RUN_STDOUT")"
  assert_ne "" "$sha" "the clean scan: 0 findings over 1 package"
  # Kept.
  reset_logs
  set_api_response 200 "$CASE_DIR/push.json"
  _mlr_response "$CASE_DIR/done.json" 0 1 "$sha"
  set_api_response 200 "$CASE_DIR/done.json"
  run_action propose=true
  assert_rc 0
  assert_eq "$sha" "$(_sent_trivy_sha "$(curl_call_dir 3)/body")" "the dry run's hash is the push's"
  assert_json "$art/monitoring_lifecycle_report.json.pending" \
    '.payload.market_availability.no_known_exploitable_vulnerabilities == true and .payload.data_lifecycle.transfer_applicable == true and .payload.data_lifecycle.secure_transfer == false' \
    "kept: the scanner true, pending fields at their fixed values"
  assert_file_contains "$art/monitoring_lifecycle_report.review.md" \
    "- \`market_availability.no_known_exploitable_vulnerabilities\` = true: the vulnerability scan of this push has 0 findings over 1 packages (report sha256 $sha)." \
    "kept: the review says what the scan was"
  # Dropped: another hash, another package count, a scan with findings.
  local variant
  for variant in sha packages; do
    reset_logs
    set_api_response 200 "$CASE_DIR/push.json"
    if [ "$variant" = sha ]; then
      _mlr_response "$CASE_DIR/done.json" 0 1 "$(printf '%s' "$sha" | tr '0-9a-f' '1-9a-f0')"
    else
      _mlr_response "$CASE_DIR/done.json" 0 2 "$sha"
    fi
    set_api_response 200 "$CASE_DIR/done.json"
    run_action propose=true
    assert_rc 0
    assert_no_file "$art/monitoring_lifecycle_report.json.pending" "another $variant: dropped"
    assert_line_eq "$RUN_STDOUT" "Seetrex proposed attestations for review: 0 citations kept, 1 dropped (not verified against this commit), 0 files in the seetrex-proposals artifact." \
      "another $variant: counted as dropped"
  done
  setup_case
  _commit_tree "$FIXTURES_PROPOSE/tree"
  _push_with_mlr "$CASE_DIR/push.json"
  set_api_response 200 "$CASE_DIR/push.json"
  _mlr_response "$CASE_DIR/done.json" 0 1 "$sha"
  set_api_response 200 "$CASE_DIR/done.json"
  run_action propose=true
  assert_rc 0
  assert_json "$(_first_propose_body)" '.start.scan.finding_count == 2' "the default fixture has findings"
  assert_no_file "$RUNNER_TEMP/seetrex-out/seetrex-proposals/monitoring_lifecycle_report.json.pending" "a scan with findings: dropped"
}

test_intent_proposal_is_rebuilt_from_kept_citations() {
  # INTENT: the envelope delivered is rebuilt from the contract, never copied
  # from the answer: exactly the leaves of the category's template, a free
  # leaf true only when ONE kept citation names it (an uncited true of the
  # answer is false), a pending leaf at the contract's fixed value, a key the
  # answer added absent; the .json and the review say the same thing leaf by
  # leaf; two citations for one field reject the category whole, with a
  # warning. Each delivered envelope is valid against envelope_<category> of
  # the contract.
  # CONTEXT: R4-4 review round 1 (an uncited true survived in the .json
  # while the review said "not found"; payload keys reached the review).
  # EXPIRES IF: the answer stops carrying envelopes (then nothing is copied).
  local art f cat leaf v review
  _live_case
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  _queue_done
  run_action propose=true propose-with-model=true
  assert_rc 0
  assert_json "$art/third_party_components_report.json" '.payload.component_vulnerabilities.fix_sharing_commitment == false' \
    "an uncited true of the answer is false"
  assert_file_contains "$art/third_party_components_report.review.md" '- `component_vulnerabilities.fix_sharing_commitment` = false: not found' \
    "and the review says so"
  assert_file_not_contains "$art/third_party_components_report.json" 'injected' "a key the answer added is not in the envelope"
  assert_file_not_contains "$art/third_party_components_report.review.md" 'injected' "nor in the review"
  for f in "$art"/*.json "$art"/*.json.pending; do
    cat="$(jq -r .category "$f" | tr -d '\r')"
    assert_eq '[]' "$(_validate propose-response "envelope_$cat" "$f")" "$cat: valid against envelope_$cat"
    assert_eq "$(jq -c '[.payload | paths(type == "boolean") | join(".")] | sort' "$CONTRACT_FIXTURES/templates/$cat.json" | tr -d '\r')" \
      "$(jq -c '[.payload | paths(type == "boolean") | join(".")] | sort' "$f" | tr -d '\r')" "$cat: exactly the leaves of the template"
    review="$art/$cat.review.md"
    while IFS=$'\t' read -r leaf v; do
      v="${v%$'\r'}"
      if [ "$v" = true ]; then
        if jq -e --arg l "$leaf" --arg c "$cat" '.categories[$c].leaves[$l] == null' \
          "$ACTION_ROOT/bin/contract/reader-contract-1.json" > /dev/null; then
          assert_file_contains "$review" "- \`$leaf\` = true: " "$cat: true in the .json, true in the review: $leaf"
        fi
      else
        assert_file_not_contains "$review" "- \`$leaf\` = true: " "$cat: false in the .json, not true in the review: $leaf"
      fi
    done < <(jq -r '.payload | paths(type == "boolean") as $p | "\($p | join("."))\t\(getpath($p))"' "$f")
  done

  # Two citations for one field: the category is rejected whole.
  _live_case
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  _done_response "$CASE_DIR/done.json"
  jq '.proposals.cvd_disclosure_report.citations += [.proposals.cvd_disclosure_report.citations[0]]' "$CASE_DIR/done.json" > "$CASE_DIR/dup.json"
  set_api_response 200 "$CASE_DIR/dup.json"
  run_action propose=true propose-with-model=true
  assert_rc 0
  assert_no_file "$art/cvd_disclosure_report.json" "duplicate field: no envelope"
  assert_no_file "$art/cvd_disclosure_report.review.md" "duplicate field: no review"
  assert_line_eq "$RUN_STDOUT" "::warning::Seetrex's proposal for cvd_disclosure_report cites one field twice: that category was left out." \
    "duplicate field: the warning"
  assert_file_contains "$GITHUB_STEP_SUMMARY" '| `cra-annex1p2-cvd-disclosure` | `cvd_disclosure_report` | rejected (one field cited twice) |' \
    "duplicate field: the summary"
  assert_file_exists "$art/third_party_components_report.json" "the other categories are delivered"
}

test_intent_security_updates_policy_is_never_an_envelope() {
  # INTENT: security_updates_policy is never proposed: whatever state and
  # envelope the answer gives it, the artifact holds only its review.md (its
  # fields, to decide by hand), never a .json or a .json.pending.
  # CONTEXT: plan R4 section 1 (N x9, never proposed) and R4-4 review round 1.
  # EXPIRES IF: the contract starts proposing this category.
  local art state
  for state in ready needs_person nothing_found; do
    _live_case
    art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
    _done_response "$CASE_DIR/done.json"
    jq --arg s "$state" '.proposals.security_updates_policy = {state: $s,
        envelope: {schema: "seetrex.attestation.v2", category: "security_updates_policy", attested_via: "reader+person",
                   payload: {policy: {updates_free_of_charge: true}}},
        citations: [{field: "policy.updates_free_of_charge", value: true, path: "SECURITY.md", line_start: 3, line_end: 3,
                     quote_sha256: .proposals.cvd_disclosure_report.citations[0].quote_sha256}]}' \
      "$CASE_DIR/done.json" > "$CASE_DIR/sup.json"
    set_api_response 200 "$CASE_DIR/sup.json"
    run_action propose=true propose-with-model=true
    assert_rc 0
    assert_no_file "$art/security_updates_policy.json" "$state: no .json"
    assert_no_file "$art/security_updates_policy.json.pending" "$state: no .json.pending"
    assert_file_contains "$art/security_updates_policy.review.md" '- `policy.updates_free_of_charge`: decide yourself' "$state: only the review"
  done
}

test_intent_citations_only_to_sent_documents_or_facts() {
  # INTENT: a layer-M citation is kept only when it names a document of the
  # closed list that this run sent, a layer-D citation only when it is
  # exactly {path, line_start, line_end} of a fact this run sent; a citation
  # of source code, a workflow, a file off the list, a line no detector cited
  # or a document not sent is dropped even when its hash matches.
  # CONTEXT: R4-4 review round 1; contract 1 (model_line_citation: a
  # document of the list; line_citation: where the detector found it).
  # EXPIRES IF: the contract lets the model cite other files.
  local art t="$FIXTURES_PROPOSE/tree"
  _live_case
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  jq -n --arg main "$(_lines_sha "$t/src/main.rs" 1 1)" --arg wf "$(_lines_sha "$t/.github/workflows/codeql.yml" 12 12)" \
    --arg notes "$(_lines_sha "$t/docs/security-notes.md" 1 1)" --arg c4 "$(_lines_sha "$t/CONTRIBUTING.md" 4 4)" \
    --arg c3 "$(_lines_sha "$t/CONTRIBUTING.md" 3 3)" --arg s3 "$(_lines_sha "$t/SECURITY.md" 3 3)" \
    --arg s56 "$(_lines_sha "$t/SECURITY.md" 5 6)" '
    def c($f; $p; $a; $b; $h): {field: $f, value: true, path: $p, line_start: $a, line_end: $b, quote_sha256: $h};
    {version: 1, status: "done", proposals: {
      third_party_components_report: {state: "ready", citations: [
        c("due_diligence.process_documented"; "src/main.rs"; 1; 1; $main),
        c("component_vulnerabilities.upstream_reporting_defined"; ".github/workflows/codeql.yml"; 12; 12; $wf),
        c("component_vulnerabilities.remediation_per_annex1_part2"; "docs/security-notes.md"; 1; 1; $notes),
        c("component_vulnerabilities.fix_sharing_commitment"; "CONTRIBUTING.md"; 4; 4; $c4),
        c("due_diligence.applies_to_open_source"; "CONTRIBUTING.md"; 3; 3; $c3)]},
      cvd_disclosure_report: {state: "ready", citations: [
        c("cvd_policy.in_place"; "SECURITY.md"; 3; 3; $s3),
        c("vulnerability_information_sharing.reporting_contact_address_provided"; "SECURITY.md"; 5; 6; $s56)]}}}' \
    > "$CASE_DIR/done.json"
  set_api_response 200 "$CASE_DIR/done.json"
  run_action propose=true propose-with-model=true
  assert_rc 0
  assert_json "$art/third_party_components_report.json" \
    '.payload == {due_diligence: {process_documented: false, applies_to_open_source: false},
                  component_vulnerabilities: {upstream_reporting_defined: false, remediation_per_annex1_part2: false, fix_sharing_commitment: true}}' \
    "tpc: only the citation of a sent document survives (code, workflow, off-list file, non-fact line dropped)"
  assert_json "$art/cvd_disclosure_report.json" \
    '.payload.cvd_policy.in_place == true and .payload.vulnerability_information_sharing.reporting_contact_address_provided == false' \
    "cvd: the exact fact is kept, a range that is not a fact is dropped"
  assert_line_eq "$RUN_STDOUT" "Seetrex proposed attestations for review: 2 citations kept, 5 dropped (not verified against this commit), 4 files in the seetrex-proposals artifact." \
    "two kept, five dropped"

  # Facts only (no documents sent): a layer-M citation of README.md is dropped.
  _live_case
  _queue_done
  run_action propose=true
  assert_rc 0
  assert_no_file "$RUNNER_TEMP/seetrex-out/seetrex-proposals/secure_config_report.json.pending" \
    "no document was sent: the README citation is dropped, nothing found"
}

test_intent_document_not_utf8_is_left_out() {
  # INTENT: a document of the list that is not well-formed UTF-8 (invalid
  # bytes, a surrogate) or carries a NUL byte is left out and the log says
  # "left out (not UTF-8 text)"; what the log lists as sent is exactly what
  # the request carries, byte for byte.
  # CONTEXT: R4-4 review round 1 (jq replaced invalid bytes, so the text
  # sent differed from the bytes and sha256 listed).
  # EXPIRES IF: the contract accepts binary documents.
  local body d t="$FIXTURES_PROPOSE/tree" listed sent
  _live_case
  printf 'support \377\376 bytes\n' > "$CASE_DIR/bad1"
  commit_file "$CASE_DIR/bad1" SUPPORT.md
  printf 'privacy\000nul\n' > "$CASE_DIR/bad2"
  commit_file "$CASE_DIR/bad2" PRIVACY.md
  printf 'surrogate \355\240\200 here\n' > "$CASE_DIR/bad3"
  commit_file "$CASE_DIR/bad3" .github/SUPPORT.md
  printf 'caf\303\251 ok\n' > "$CASE_DIR/good"
  commit_file "$CASE_DIR/good" docs/SUPPORT.md
  make_event private
  _queue_done
  run_action propose=true propose-with-model=true
  assert_rc 0
  for d in SUPPORT.md PRIVACY.md .github/SUPPORT.md; do
    assert_line_eq "$RUN_STDOUT" "- $d: left out (not UTF-8 text)" "$d: said"
  done
  body="$(_first_propose_body)"
  listed="$(sed -n 's/^- \([^:]*\): [0-9]* bytes, sha256 [0-9a-f]\{64\}\r\{0,1\}$/\1/p' "$RUN_STDOUT" | sort | tr '\n' ' ')"
  sent="$(jq -r '.start.documents[].path' "$body" | tr -d '\r' | sort | tr '\n' ' ')"
  assert_eq "CONTRIBUTING.md README.md SECURITY.md docs/SUPPORT.md docs/threat-model.md " "$listed" "listed: the clean documents"
  assert_eq "$listed" "$sent" "listed = sent"
  for d in CONTRIBUTING.md README.md SECURITY.md docs/SUPPORT.md docs/threat-model.md; do
    assert_eq "$(base64 < "$WS/$d" | tr -d '\r\n')" \
      "$(jq -r --arg p "$d" '.start.documents[] | select(.path == $p) | .text | @base64' "$body" | tr -d '\r\n')" "$d: sent byte for byte"
  done
}

test_intent_credential_filter_ports_the_reader_patterns() {
  # INTENT: the runner's credential filter (bin/doccheck.pl) is the reader's
  # own (services/reader/filters.py of the Seetrex repository): every
  # pattern, by name, on a case each, including assignments whose name
  # starts with a word and `_` (DB_PASSWORD, AWS_SECRET_ACCESS_KEY), bare
  # token/secret keys, and the placeholder rule (${NAME}, $NAME in capitals,
  # <...> are not secrets; $Lowercase is), and Python's semantics where Perl
  # differs: 0x1C..0x1F are \s, and (?i) makes [A-Za-z] of the token value
  # match U+017F. The expected verdicts were measured against filters.py
  # with the same texts.
  # CONTEXT: R4-4 review round 1 (the runner's list was shorter than the
  # reader's) and round 2 (\x1f, \x1c and U+017F passed doccheck.pl and not
  # filters.py).
  # EXPIRES IF: filters.py changes its list (then the cases change with it).
  local name want text got names
  while IFS=$'\t' read -r name want text; do
    case "$name" in '#'* | '') continue ;; esac
    text="${text%$'\r'}"
    text="${text//@@/}"
    text="${text//@FS@/$'\x1c'}"
    text="${text//@RS@/$'\x1e'}"
    text="${text//@US@/$'\x1f'}"
    printf '%s' "$text" > "$TEST_TMP/case.txt"
    got="$(perl "$ACTION_ROOT/bin/doccheck.pl" "$TEST_TMP/case.txt" | tr -d '\r')"
    if [ "$want" = ok ]; then
      assert_eq ok "$got" "case $name"
    else
      assert_eq "credential $want" "$got" "case $name"
    fi
  done < "$FIXTURES_PROPOSE/credential-cases.tsv"
  names="$(grep -v '^#' "$FIXTURES_PROPOSE/credential-cases.tsv" | cut -f2 | tr -d '\r' | grep -v -x ok | sort -u | wc -l)"
  assert_eq 19 "${names//[[:space:]]/}" "every one of the 19 patterns of filters.py has a case"
}

test_intent_line_hash_handles_crlf_ranges() {
  # INTENT: the line-range hash of detect.sh and of propose.sh drops the \r
  # of a CRLF line and joins a range of several lines with \n, no trailing
  # \n, as the contract states; detect.sh over a CRLF tree gives the facts of
  # the same tree in LF.
  # CONTEXT: R4-4 review round 1 (no CRLF fixture with a range of lines).
  # EXPIRES IF: the contract changes its hash rule.
  local script lf crlf want want4 f
  printf 'one\r\ntwo\r\nthree\r\nfour' > "$TEST_TMP/crlf.txt"
  # Git for Windows' gawk reads in text mode and drops every \r itself, which
  # would hide a missing sub(/\r$/, ""): BINMODE=3 makes it read the bytes as
  # Linux awk does (BINMODE means nothing there). Measured: without it, the
  # mutant that removes the sub() survived on Windows.
  awk() { command awk -v BINMODE=3 "$@"; }
  want="$(printf 'two\nthree' | sha256sum)"
  want="${want%% *}"
  for script in detect propose; do
    sed -n '/^range_sha256() {$/,/^}$/p' "$ACTION_ROOT/bin/$script.sh" > "$TEST_TMP/$script.fn"
    assert_ne "" "$(cat "$TEST_TMP/$script.fn")" "$script.sh has range_sha256"
    # shellcheck disable=SC1090
    source "$TEST_TMP/$script.fn"
    assert_eq "$want" "$(range_sha256 "$TEST_TMP/crlf.txt" 2 3)" "$script.sh: lines 2-3 of a CRLF file"
    want4="$(printf 'three\nfour' | sha256sum)"
    assert_eq "${want4%% *}" "$(range_sha256 "$TEST_TMP/crlf.txt" 3 4)" "$script.sh: a last line without a newline"
  done
  # detect.sh over the fixture tree converted to CRLF: the same facts.
  lf="$TEST_TMP/lf"
  crlf="$TEST_TMP/crlf"
  cp -R "$FIXTURES_PROPOSE/tree" "$lf"
  cp -R "$FIXTURES_PROPOSE/tree" "$crlf"
  while IFS= read -r -d '' f; do
    sed 's/$/\r/' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
  done < <(find "$crlf" -type f -print0)
  bash "$ACTION_ROOT/bin/detect.sh" "$lf" "$ACTION_ROOT/bin/filters" | tr -d '\r' > "$TEST_TMP/lf.json"
  bash "$ACTION_ROOT/bin/detect.sh" "$crlf" "$ACTION_ROOT/bin/filters" | tr -d '\r' > "$TEST_TMP/crlf.json"
  # The copy is CRLF: 12 lines, 12 more bytes, the same text without \r.
  assert_eq $(( $(wc -c < "$lf/SECURITY.md") + 12 )) "$(wc -c < "$crlf/SECURITY.md" | tr -d '[:space:]')" "the copy is CRLF"
  assert_eq "$(cat "$lf/SECURITY.md")" "$(tr -d '\r' < "$crlf/SECURITY.md")" "the copy differs only by \\r"
  assert_eq "$(cat "$TEST_TMP/lf.json")" "$(cat "$TEST_TMP/crlf.json")" "CRLF and LF trees give the same facts"
  assert_json "$TEST_TMP/crlf.json" '.facts | length == 10' "the ten facts"
}

test_intent_detector_citation_backs_only_its_targets() {
  # INTENT: a layer-D citation is kept only when the fact it names (same
  # path, lines and hash) comes from a detector whose targets name that
  # field of that category (detector_targets of the runtime contract, from
  # DetectorId::targets()): the CODEOWNERS hint never sets cvd_policy.in_place,
  # reporting_contact_address_provided or applies_to_open_source, the
  # security policy heading never sets applies_to_open_source; the policy
  # heading for cvd_policy.in_place and the contact line for the contact
  # field are kept.
  # CONTEXT: R4-4 review round 2 (any fact sent backed any layer-D field:
  # measured with codeowners_file on the three fields).
  # EXPIRES IF: the contract lets a hint set a field.
  local art t="$FIXTURES_PROPOSE/tree" co s3 s5
  co="$(_lines_sha "$t/CODEOWNERS" 1 1)"
  s3="$(_lines_sha "$t/SECURITY.md" 3 3)"
  s5="$(_lines_sha "$t/SECURITY.md" 5 5)"
  _live_case
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  jq -n --arg co "$co" --arg s5 "$s5" '
    def c($f; $p; $a; $b; $h): {field: $f, value: true, path: $p, line_start: $a, line_end: $b, quote_sha256: $h};
    {version: 1, status: "done", proposals: {
      third_party_components_report: {state: "ready", citations: [
        c("due_diligence.applies_to_open_source"; "CODEOWNERS"; 1; 1; $co)]},
      cvd_disclosure_report: {state: "ready", citations: [
        c("cvd_policy.in_place"; "CODEOWNERS"; 1; 1; $co),
        c("vulnerability_information_sharing.reporting_contact_address_provided"; "SECURITY.md"; 5; 5; $s5)]}}}' \
    > "$CASE_DIR/done.json"
  set_api_response 200 "$CASE_DIR/done.json"
  run_action propose=true
  assert_rc 0
  assert_json "$art/cvd_disclosure_report.json" \
    '.payload.cvd_policy.in_place == false and .payload.vulnerability_information_sharing.reporting_contact_address_provided == true' \
    "cvd: the CODEOWNERS fact does not back cvd_policy.in_place, the contact line backs the contact"
  assert_no_file "$art/third_party_components_report.json" "tpc: the CODEOWNERS fact does not back applies_to_open_source"
  assert_line_eq "$RUN_STDOUT" "Seetrex proposed attestations for review: 1 citations kept, 2 dropped (not verified against this commit), 2 files in the seetrex-proposals artifact." \
    "run 1: one kept, two dropped"

  _live_case
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  jq -n --arg co "$co" --arg s3 "$s3" '
    def c($f; $p; $a; $b; $h): {field: $f, value: true, path: $p, line_start: $a, line_end: $b, quote_sha256: $h};
    {version: 1, status: "done", proposals: {
      third_party_components_report: {state: "ready", citations: [
        c("due_diligence.applies_to_open_source"; "SECURITY.md"; 3; 3; $s3)]},
      cvd_disclosure_report: {state: "ready", citations: [
        c("cvd_policy.in_place"; "SECURITY.md"; 3; 3; $s3),
        c("vulnerability_information_sharing.reporting_contact_address_provided"; "CODEOWNERS"; 1; 1; $co)]}}}' \
    > "$CASE_DIR/done.json"
  set_api_response 200 "$CASE_DIR/done.json"
  run_action propose=true
  assert_rc 0
  assert_json "$art/cvd_disclosure_report.json" \
    '.payload.cvd_policy.in_place == true and .payload.vulnerability_information_sharing.reporting_contact_address_provided == false' \
    "cvd: the policy heading backs cvd_policy.in_place, the CODEOWNERS fact not the contact"
  assert_no_file "$art/third_party_components_report.json" "tpc: the policy heading does not back applies_to_open_source"
  assert_line_eq "$RUN_STDOUT" "Seetrex proposed attestations for review: 1 citations kept, 2 dropped (not verified against this commit), 2 files in the seetrex-proposals artifact." \
    "run 2: one kept, two dropped"
}

test_intent_document_check_failure_requests_nothing() {
  # INTENT: when the credential check of a document cannot run (perl exits
  # non-zero, here a perl of the PATH that exits 127), the proposal step
  # fails closed: the warning "A document could not be checked" and no call
  # to the propose route; the push is recorded as always.
  # CONTEXT: R4-4 review round 2 (the fail-closed branch had no test).
  # EXPIRES IF: the credential check leaves perl.
  local old_path="$PATH"
  _live_case
  mkdir -p "$CASE_DIR/fakebin"
  printf '#!/bin/sh\nprintf x >> "%s"\nexit 127\n' "$CASE_DIR/perl.calls" > "$CASE_DIR/fakebin/perl"
  chmod +x "$CASE_DIR/fakebin/perl"
  _queue_done
  export PATH="$CASE_DIR/fakebin:$PATH"
  run_action propose=true propose-with-model=true
  export PATH="$old_path"
  assert_rc 0
  assert_file_exists "$CASE_DIR/perl.calls" "the fake perl was the one called"
  assert_line_eq "$RUN_STDOUT" "::warning::A document could not be checked: no proposal was requested." "the warning"
  assert_eq 0 "$(_propose_call_count)" "no call to the propose route"
  _assert_record_kept "a check that cannot run"
}

test_intent_document_check_ignores_inherited_perl_environment() {
  # INTENT: the credential check runs perl without PERL5OPT, PERL5LIB,
  # PERLLIB or PERL5DB from the job's environment: a strict.pm of the
  # workflow's own (through any of them) or a debugger hook cannot answer
  # "ok" for a document with a private key; the document is still left out.
  # CONTEXT: R4-4 review round 2 (perl inherited them).
  # EXPIRES IF: the credential check leaves perl.
  local evil variant
  for variant in PERL5LIB PERLLIB PERL5OPT PERL5DB; do
    setup_case
    _commit_tree "$FIXTURES_PROPOSE/tree"
    commit_file "$FIXTURES_PROPOSE/key-SECURITY.md" SECURITY.md
    make_event private
    set_api_response 200 "$FIXTURES_PROPOSE/push-200.json"
    evil="$CASE_DIR/evil"
    mkdir -p "$evil"
    printf 'package strict;\nprint "ok\\n";\nexit 0;\n1;\n' > "$evil/strict.pm"
    (
      case "$variant" in
        PERL5LIB) export PERL5LIB="$evil" ;;
        PERLLIB) export PERLLIB="$evil" ;;
        PERL5OPT) export PERL5OPT="-I$evil" ;;
        PERL5DB) export PERL5OPT=-d PERL5DB='BEGIN { print "ok\n"; exit 0 }' ;;
      esac
      run_action dry-run=true propose=true propose-with-model=true
      printf '%s\n' "$RUN_RC" > "$CASE_DIR/rc"
    )
    RUN_RC="$(cat "$CASE_DIR/rc")"
    assert_rc 0
    assert_line_eq "$RUN_STDOUT" "- SECURITY.md: left out (a line looks like a credential: private_key_block)" \
      "$variant: the key document is still left out"
  done
}

test_intent_citation_checks_each_bite() {
  # INTENT: each check of a line citation stands on its own: a layer-M
  # citation past the end of a sent document (line 400) whose quote_sha256
  # is the hash of nothing, a reversed range (5-3) with that same hash, a
  # layer-M citation and a layer-D citation that carry `source: vuln_scan`
  # are all dropped, while a valid citation of the same answer is kept.
  # CONTEXT: R4-4 review round 2 (the end-of-file and range-order checks and
  # the `source` of a line citation could be removed without a red test).
  # EXPIRES IF: the contract changes the citation shapes.
  local art t="$FIXTURES_PROPOSE/tree" empty
  empty="$(printf '' | sha256sum)"
  empty="${empty%% *}"
  _live_case
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  jq -n --arg e "$empty" --arg c4 "$(_lines_sha "$t/CONTRIBUTING.md" 4 4)" --arg s3 "$(_lines_sha "$t/SECURITY.md" 3 3)" '
    def c($f; $p; $a; $b; $h): {field: $f, value: true, path: $p, line_start: $a, line_end: $b, quote_sha256: $h};
    {version: 1, status: "done", proposals: {
      third_party_components_report: {state: "ready", citations: [
        c("component_vulnerabilities.fix_sharing_commitment"; "CONTRIBUTING.md"; 4; 4; $c4),
        c("due_diligence.process_documented"; "CONTRIBUTING.md"; 5; 3; $e)]},
      cvd_disclosure_report: {state: "ready", citations: [
        c("vulnerability_information_sharing.measures_in_place"; "SECURITY.md"; 400; 400; $e),
        (c("cvd_policy.enforced"; "SECURITY.md"; 3; 3; $s3) + {source: "vuln_scan"}),
        (c("cvd_policy.in_place"; "SECURITY.md"; 3; 3; $s3) + {source: "vuln_scan"})]}}}' \
    > "$CASE_DIR/done.json"
  set_api_response 200 "$CASE_DIR/done.json"
  run_action propose=true propose-with-model=true
  assert_rc 0
  assert_json "$art/third_party_components_report.json" \
    '.payload.component_vulnerabilities.fix_sharing_commitment == true and .payload.due_diligence.process_documented == false' \
    "tpc: the valid citation kept, the reversed range dropped"
  assert_no_file "$art/cvd_disclosure_report.json" "cvd: past the end, M with source, D with source: all dropped, nothing found"
  assert_line_eq "$RUN_STDOUT" "Seetrex proposed attestations for review: 1 citations kept, 4 dropped (not verified against this commit), 2 files in the seetrex-proposals artifact." \
    "one kept, four dropped"
}

test_intent_scan_citation_needs_a_scanned_package() {
  # INTENT: the scanner-backed true of monitoring_lifecycle_report needs at
  # least one scanned package: an SBOM without `library` components (an
  # application only) gives scanned_packages 0, and a scan citation that
  # carries exactly the values sent (0 findings, 0 packages, the hash) is
  # still dropped.
  # CONTEXT: plan R4 section 1 (zero findings over nothing scanned proves
  # nothing) and R4-4 review round 2 (the >= 1 check had no test).
  # EXPIRES IF: the scanner field leaves the contract.
  local art sha
  setup_case
  _commit_tree "$FIXTURES_PROPOSE/tree"
  set_trivy_fixture json "$FIXTURES_PROPOSE/trivy-clean.json"
  jq '.components = [{"bom-ref": "fixture-app", type: "application", name: "fixture-app"}] | .dependencies = []' \
    "$FIXTURES_COMMON/sbom.cdx.json" > "$CASE_DIR/sbom-nolib.json"
  set_trivy_fixture cyclonedx "$CASE_DIR/sbom-nolib.json"
  _push_with_mlr "$CASE_DIR/push.json"
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  run_action dry-run=true propose=true
  assert_rc 0
  sha="$(sed -n 's/^Scan of the push: 0 findings over 0 packages, report sha256 \([0-9a-f]\{64\}\)\r\{0,1\}$/\1/p' "$RUN_STDOUT")"
  assert_ne "" "$sha" "the clean scan over no library: 0 findings over 0 packages"
  reset_logs
  set_api_response 200 "$CASE_DIR/push.json"
  _mlr_response "$CASE_DIR/done.json" 0 0 "$sha"
  set_api_response 200 "$CASE_DIR/done.json"
  run_action propose=true
  assert_rc 0
  assert_json "$(_first_propose_body)" ".start.scan == {finding_count: 0, scanned_packages: 0, report_sha256: \"$sha\"}" \
    "the request carries the scan the citation repeats"
  assert_no_file "$art/monitoring_lifecycle_report.json.pending" "0 packages: dropped"
  assert_line_eq "$RUN_STDOUT" "Seetrex proposed attestations for review: 0 citations kept, 1 dropped (not verified against this commit), 0 files in the seetrex-proposals artifact." \
    "counted as dropped"
}
