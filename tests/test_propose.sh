# shellcheck shell=bash
# Dynamic tests of the proposal step (bin/propose.sh through bin/run.sh,
# plan R4 section 2, amendment #334): the opt-in, the dry run, the job log,
# what leaves the runner, the closed list of documents, the rehydration of
# citations, the artifact and the exit table. The detectors themselves are
# tested in tests/test_detect.sh.

FIXTURES_PROPOSE="$TESTS_DIR/fixtures/propose"
SEETREX_PROPOSE_URL='https://api.seetrex.com/v1/action/propose'
MODEL_DOCUMENT_LIST='README.md SECURITY.md .github/SECURITY.md docs/SECURITY.md CONTRIBUTING.md .github/CONTRIBUTING.md docs/CONTRIBUTING.md SUPPORT.md .github/SUPPORT.md docs/SUPPORT.md CHANGELOG.md THREAT_MODEL.md docs/THREAT_MODEL.md docs/threat-model.md docs/DEPENDENCIES.md'

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

  # The reader is unreachable: push recorded, list in the log, the request
  # attempted once and failed.
  _live_case
  set_api_transport_error 7
  run_action propose=true propose-with-model=true
  assert_rc 0
  _assert_record_kept "reader unreachable"
  for d in README.md SECURITY.md CONTRIBUTING.md docs/threat-model.md; do
    assert_line_eq "$RUN_STDOUT" "- $d: $(_file_bytes "$t/$d") bytes, sha256 $(_sha "$t/$d")" "unreachable: listed $d"
  done
  assert_line_eq "$RUN_STDOUT" "::warning::Seetrex could not be reached for the proposal: no proposal; the record of this push is not affected." \
    "unreachable: warning"
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
  assert_json "$body" '.start | keys == ["categories", "facts"]' "start: categories and facts only, no documents"
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
  # The list in propose.sh is the contract's, verbatim.
  list_line="$(grep -E "^readonly MODEL_DOCUMENTS=" "$ACTION_ROOT/bin/propose.sh" | tr -d '\r')"
  assert_eq "readonly MODEL_DOCUMENTS='$MODEL_DOCUMENT_LIST'" "$list_line" "propose.sh carries the contract's list"
  assert_file_not_contains "$ACTION_ROOT/bin/propose.sh" 'find "$TREE"' "no search of the tree for documents"
}

test_intent_runner_drops_citation_whose_hash_mismatches() {
  # INTENT: every citation of the answer is rehydrated from the local file of
  # the commit and its quote_sha256 compared; a citation that does not match
  # is dropped and its field set to false in the proposed envelope, the
  # review says "not found" for it, and a category left with no cited true is
  # delivered as nothing found. A matching citation is kept with its quote
  # rehydrated locally in the review.
  # CONTEXT: plan R4 section 2.1 (third check of the citation) and section 1
  # (zero cited true = nothing found).
  # EXPIRES IF: the server returns the quote itself (it never does: no text).
  local art t="$FIXTURES_PROPOSE/tree"
  _live_case
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  _queue_done
  run_action propose=true
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
  # Two matching citations, one spanning two lines.
  assert_json "$art/cvd_disclosure_report.json" '.payload.cvd_policy.in_place == true and .payload.vulnerability_information_sharing.reporting_contact_address_provided == true' \
    "cvd: both citations kept"
  assert_file_contains "$art/cvd_disclosure_report.review.md" '    We acknowledge reports within 5 working days.' "cvd review: second line of the quote"
  # Summary: only paths and lines.
  assert_file_contains "$GITHUB_STEP_SUMMARY" '| `cra-art13-third-party-components` | `third_party_components_report` | proposal ready (1 fact cited: CONTRIBUTING.md:3-3) |' \
    "summary: tpc with one fact"
  assert_file_contains "$GITHUB_STEP_SUMMARY" '| `cra-annex1p2-cvd-disclosure` | `cvd_disclosure_report` | proposal ready (2 facts cited: SECURITY.md:3-3, SECURITY.md:5-6) |' \
    "summary: cvd with two facts"
  assert_file_contains "$GITHUB_STEP_SUMMARY" '| `cra-annex1-secure-design` | `secure_design_report` | nothing found |' "summary: nothing found"
  assert_file_not_contains "$GITHUB_STEP_SUMMARY" 'Dependencies are reviewed' "summary: no quote"
  assert_line_eq "$RUN_STDOUT" "Seetrex proposed attestations for review: 4 citations kept, 1 dropped (their lines do not match this commit), 7 files in the seetrex-proposals artifact." \
    "the closing line counts kept and dropped"
  assert_file_contains "$GITHUB_OUTPUT" "proposals=$art" "the artifact output"
  # The unrequested category of the answer is ignored.
  assert_no_file "$art/user_information_report.json.pending" "an unrequested category writes nothing"
  assert_no_file "$art/user_information_report.review.md" "an unrequested category writes no review"

  # Every hash wrong: no envelope is delivered, every proposal is nothing found.
  _live_case
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  _queue_done bad
  run_action propose=true
  assert_rc 0
  assert_no_file "$art/third_party_components_report.json" "all bad: no tpc envelope"
  assert_no_file "$art/cvd_disclosure_report.json" "all bad: no cvd envelope"
  assert_no_file "$art/secure_config_report.json.pending" "all bad: no pending envelope"
  assert_file_contains "$GITHUB_STEP_SUMMARY" '| `cra-art13-third-party-components` | `third_party_components_report` | nothing found |' \
    "all bad: tpc nothing found"
  assert_line_eq "$RUN_STDOUT" "Seetrex proposed attestations for review: 0 citations kept, 5 dropped (their lines do not match this commit), 1 files in the seetrex-proposals artifact." \
    "all bad: counts"
  _assert_record_kept "all bad"

  # A citation past the end of the file, and one whose file does not exist.
  _live_case
  art="$RUNNER_TEMP/seetrex-out/seetrex-proposals"
  _done_response "$CASE_DIR/done.json"
  jq '.proposals.cvd_disclosure_report.citations[0].line_start = 400 | .proposals.cvd_disclosure_report.citations[0].line_end = 400
      | .proposals.cvd_disclosure_report.citations[1].path = "docs/MISSING.md"' "$CASE_DIR/done.json" > "$CASE_DIR/done2.json"
  set_api_response 200 "$CASE_DIR/done2.json"
  run_action propose=true
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
  run_action propose=true
  assert_rc 0
  assert_file_exists "$art/secure_config_report.json.pending" "needs_person: .json.pending"
  assert_no_file "$art/secure_config_report.json" "needs_person: no .json"
  assert_json "$art/secure_config_report.json.pending" \
    '.schema == "seetrex.attestation.v2" and .attested_via == "reader+person" and .payload.secure_configuration.secure_by_default == true and .payload.secure_configuration.tailor_made_agreement == false' \
    "the pending envelope"
  review="$art/secure_config_report.review.md"
  assert_file_contains "$review" '- `security_updates_capability.auto_updates.applicable`: decide yourself' "review: a pending field"
  assert_file_contains "$review" '- `secure_configuration.secure_by_default` = true: `README.md:3-3`' "review: the cited true"
  assert_file_contains "$review" '    Secure by default: every option ships closed.' "review: the quote"
  assert_file_contains "$review" '- `security_updates_capability.updates_mechanism` = false: not found' "review: a false"
  assert_file_not_contains "$review" '- `secure_configuration.tailor_made_agreement` = false: not found' "review: a pending field is not 'not found'"
  assert_file_contains "$GITHUB_STEP_SUMMARY" '| `cra-annex1-secure-config-updates` | `secure_config_report` | needs a person (8 fields to decide; 1 fact cited: README.md:3-3) |' \
    "summary: needs a person"
  # security_updates_policy: never an envelope, a review of its fields.
  assert_no_file "$art/security_updates_policy.json" "sup: no envelope"
  assert_no_file "$art/security_updates_policy.json.pending" "sup: no pending envelope"
  assert_file_contains "$art/security_updates_policy.review.md" '- `policy.support_period_end_at`: decide yourself' "sup review"
  assert_file_contains "$GITHUB_STEP_SUMMARY" '| `cra-art13-security-updates` | `security_updates_policy` | needs a person (9 fields to decide; no fact cited) |' \
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
  # request, the log says so by path only, and no byte of it reaches the
  # body; the other documents still go.
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
  assert_line_eq "$RUN_STDOUT" "- SECURITY.md: left out (a line looks like a credential)" "the log names the file left out"
  assert_line_eq "$RUN_STDOUT" "- README.md: left out (a line looks like a credential)" "the log names the second file left out"
  assert_file_not_contains "$RUN_STDOUT" 'hunter2' "no password in the log"
  assert_file_not_contains "$RUN_STDOUT" 'PRIVATE KEY' "no key marker in the log"
  assert_file_not_contains "$GITHUB_STEP_SUMMARY" 'hunter2' "no password in the summary"
  # (the replaced SECURITY.md has no Supported Versions heading: 9 facts)
  assert_line_eq "$RUN_STDOUT" "Requesting proposals from Seetrex for 5 categories, with 9 facts and 2 documents." "two documents counted"

  # An empty document and one over the cap are left out too.
  _live_case
  : > "$CASE_DIR/empty"
  commit_file "$CASE_DIR/empty" CHANGELOG.md
  head -c 70000 /dev/zero | tr '\0' 'x' > "$CASE_DIR/big"
  commit_file "$CASE_DIR/big" SUPPORT.md
  make_event private
  _queue_done
  run_action propose=true propose-with-model=true
  assert_rc 0
  body="$(_first_propose_body)"
  assert_json "$body" '[.start.documents[].path] | sort == ["CONTRIBUTING.md", "README.md", "SECURITY.md", "docs/threat-model.md"]' \
    "empty and oversize documents are not sent"
  assert_line_eq "$RUN_STDOUT" "- CHANGELOG.md: left out (empty)" "empty: said"
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
  assert_eq 21 "$(_propose_call_count)" "the start and twenty polls"
  assert_eq 22 "$(token_call_count)" "a fresh token for the push and for each of the 21 proposal requests"
  assert_eq 20 "$(sleep_count)" "twenty waits"
  assert_eq $'5\n10\n20\n30\n30' "$(sleep_log | head -n 5)" "backoff 5, 10, 20, 30, 30..."
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
