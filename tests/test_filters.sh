# shellcheck shell=bash disable=SC2016
# (SC2016 is off for this file: its single-quoted strings are literal Markdown
# rows with backticks, compared as text, never meant to expand.)
# Filter-level tests of bin/filters/*.jq: each filter is run on its own, with
# the exact invocation documented at the top of the .jq file (the one
# bin/run.sh uses), over the synthetic fixtures of tests/fixtures/filters/.
# The run-level halves (through bin/run.sh) live in tests/test_run.sh; names
# that exist there too carry the suffix __filter here.
#
# jq on Windows writes CRLF in text mode; every output is read through
# _lf so the same assertions hold on Windows and on ubuntu-24.04.

FILTERS_DIR="$ACTION_ROOT/bin/filters"
FIXTURES_FILTERS="$TESTS_DIR/fixtures/filters"

# _lf <in> <out>: copy without CR.
_lf() {
  tr -d '\r' < "$1" > "$2"
}

# _filter <name> <input> <output> [jq options...]: runs bin/filters/<name>.jq
# as `jq <options> -f <filter> < input > output`, output without CR.
# Aborts the test (via fail) if jq exits non-zero.
_filter() {
  local name="$1" input="$2" output="$3" rc=0
  shift 3
  jq "$@" -f "$FILTERS_DIR/$name.jq" < "$input" > "$output.raw" 2> "$output.err" || rc=$?
  if [ "$rc" -ne 0 ]; then
    cat "$output.err" >&2
    fail "$name.jq exited $rc on $(basename "$input")"
  fi
  _lf "$output.raw" "$output"
}

# _body_check_rc <body-file>: prints body_check.jq's exit code (never fails).
_body_check_rc() {
  local rc=0
  jq -n -e -f "$FILTERS_DIR/body_check.jq" < "$1" > /dev/null 2>&1 || rc=$?
  printf '%s\n' "$rc"
}

# _json_eq <expected> <actual> <msg>: the two files hold the same JSON value.
# Scratch files go to the cwd ($TEST_TMP), never next to a fixture.
_json_eq() {
  jq -S . "$1" > json_eq.expected.raw
  jq -S . "$2" > json_eq.actual.raw
  _lf json_eq.expected.raw json_eq.expected
  _lf json_eq.actual.raw json_eq.actual
  assert_eq "$(cat json_eq.expected)" "$(cat json_eq.actual)" "$3"
}

# ------------------------------------------------------------------ sbom.jq

test_intent_sbom_filter_keeps_bom_ref_and_dependencies() {
  local in="$FIXTURES_FILTERS/sbom-nested.cdx.json" n_in n_out
  _filter sbom "$in" out.json -c

  # The whole reduction, at every nesting level.
  _json_eq "$FIXTURES_FILTERS/sbom-nested.expected.json" out.json \
    "sbom.jq output equals the expected reduction"

  # Every component keeps its bom-ref, nested ones included (6 in the fixture:
  # subject, its child and grandchild, outer, inner, innermost + 1 sibling).
  n_in="$(jq '[.. | objects | select(has("type")) | select(has("bom-ref"))] | length' "$in" | tr -d '\r')"
  jq '[.. | objects | select(has("bom-ref"))] | length' out.json > n_out.raw
  _lf n_out.raw n_out
  n_out="$(cat n_out)"
  assert_eq 7 "$n_out" "bom-ref kept on all 7 components, every level"
  assert_eq "$n_in" "$n_out" "same bom-ref count as the components of the original"
  assert_json out.json '.metadata.component.components[0].components[0]["bom-ref"] == "subject-grandchild-ref"' \
    "bom-ref kept two levels under metadata.component"
  assert_json out.json '.components[0].components[0].components[0]["bom-ref"] == "pkg:npm/innermost-fixture@0.0.1"' \
    "bom-ref kept three levels under components"

  # dependencies verbatim, including the entry without dependsOn.
  jq -S '.dependencies' "$in" > dep_in.raw
  jq -S '.dependencies' out.json > dep_out.raw
  _lf dep_in.raw dep_in
  _lf dep_out.raw dep_out
  assert_eq "$(cat dep_in)" "$(cat dep_out)" "dependencies identical to the original"

  # Out: provenance, personal data and volatile fields.
  assert_file_not_contains out.json '"author"' "no author"
  assert_file_not_contains out.json '"authors"' "no authors"
  assert_file_not_contains out.json '"supplier"' "no supplier"
  assert_file_not_contains out.json '"properties"' "no properties"
  assert_file_not_contains out.json '"vulnerabilities"' "no vulnerabilities"
  assert_file_not_contains out.json '"serialNumber"' "no serialNumber"
  assert_file_not_contains out.json '"timestamp"' "no metadata.timestamp"
  assert_file_not_contains out.json 'example.invalid' "no e-mail or URL"
  assert_file_not_contains out.json 'marker' "no description, publisher, copyright, annotation"
  assert_json out.json '.metadata | keys == ["component"]' "metadata holds the subject only"

  # Absent stays absent: no dependencies, no subject, no specVersion invented.
  _filter sbom "$FIXTURES_FILTERS/sbom-no-graph.cdx.json" nograph.json -c
  assert_json nograph.json 'has("dependencies") | not' "absent dependencies stay absent"
  assert_json nograph.json 'has("metadata") | not' "metadata without a subject is not written"
  assert_json nograph.json '.components[0].components == []' "an empty nested components stays []"
  printf '{"bomFormat":"CycloneDX"}' > minimal.json
  _filter sbom minimal.json minimal.out -c
  assert_eq '{"bomFormat":"CycloneDX"}' "$(cat minimal.out)" "no key the original lacks"
}

test_intent_sbom_filter_refuses_a_document_that_is_not_an_object() {
  local rc=0
  printf '[{"bomFormat":"CycloneDX"}]' > arr.json
  jq -c -f "$FILTERS_DIR/sbom.jq" < arr.json > out.json 2> /dev/null || rc=$?
  assert_ne 0 "$rc" "sbom.jq fails on a non-object document"
}

# ----------------------------------------------------------------- trivy.jq

test_intent_trivy_body_has_no_commit_metadata() {
  _filter trivy "$FIXTURES_FILTERS/trivy-with-metadata.json" out.json -c
  assert_file_not_contains out.json 'Metadata' "no Metadata"
  assert_file_not_contains out.json '@' "no @ (no e-mail, no PkgID)"
  assert_file_not_contains out.json 'marker-7c1e' "no commit message"
  assert_file_not_contains out.json 'Alice' "no author or committer name"
  assert_file_not_contains out.json 'ArtifactName' "no ArtifactName"
  assert_file_not_contains out.json '/home/' "no local path"
  assert_file_not_contains out.json '0123456789abcdef' "no commit id"
  assert_file_not_contains out.json 'example.invalid' "no URL nor e-mail"
}

test_intent_trivy_filter_reproduces_the_serde_shape() {
  _filter trivy "$FIXTURES_FILTERS/trivy-with-metadata.json" out.json -c
  _json_eq "$FIXTURES_FILTERS/trivy-with-metadata.expected.json" out.json \
    "trivy.jq output equals the serde shape of TrivyReport"

  # Option without skip -> null; CreatedAt (skip_serializing_if) -> absent.
  printf '{"Results":null,"CreatedAt":null}' > bare.json
  _filter trivy bare.json bare.out -c
  assert_eq '{"SchemaVersion":null,"Results":[]}' "$(cat bare.out)" \
    "absent SchemaVersion is null, null CreatedAt is dropped, null Results is []"
  printf '{"SchemaVersion":2}' > nores.json
  _filter trivy nores.json nores.out -c
  assert_eq '{"SchemaVersion":2,"Results":[]}' "$(cat nores.out)" "absent Results is []"

  # Shapes serde refuses are not made acceptable.
  local rc=0
  printf '{"SchemaVersion":2,"Results":{"a":{"Target":"x"}}}' > objres.json
  jq -c -f "$FILTERS_DIR/trivy.jq" < objres.json > objres.out 2> /dev/null || rc=$?
  assert_ne 0 "$rc" "Results as an object is an error, not a list"
  rc=0
  printf '{"Results":[{"Vulnerabilities":{"x":{"VulnerabilityID":"CVE-2099-0001"}}}]}' > objvuln.json
  jq -c -f "$FILTERS_DIR/trivy.jq" < objvuln.json > objvuln.out 2> /dev/null || rc=$?
  assert_ne 0 "$rc" "Vulnerabilities as an object is an error, not a list"
}

# ------------------------------------------------------------ body_check.jq

test_intent_body_contains_only_declared_fields__filter() {
  local body i=0
  local -a accepted=(
    '{"sbom":"s","trivy":"t","attestations":["a"]}'
    '{"sbom":"s","trivy_left_out":true,"attestations":["a"]}'
    '{"sbom":"s","trivy_left_out":true,"attestations":[]}'
    '{"sbom":"s"}'
    '{"attestations":["a","b"]}'
  )
  local -a rejected=(
    '{"sbom":"s","trivy":"t","attestations":["a"],"extra":1}'
    '{"sbom":"s","repin":true}'
    '{"sbom":"s","trivy_left_out":false}'
    '{"sbom":"s","trivy_left_out":"true"}'
    '{"sbom":"s","trivy":"t","trivy_left_out":true}'
    '{"sbom":{"bomFormat":"CycloneDX"}}'
    '{"trivy":1}'
    '{"sbom":"s","attestations":"a"}'
    '{"sbom":"s","attestations":[{"a":1}]}'
    '{"repin":true}'
    '{"close":true}'
    '{}'
    '{"attestations":[]}'
    '["sbom"]'
    '"sbom"'
    '{"sbom":"s"} {"sbom":"s","extra":1}'
    '{"sbom":"s","extra":1} {"sbom":"s"}'
    ''
  )
  for body in "${accepted[@]}"; do
    i=$((i + 1))
    printf '%s' "$body" > "acc$i.json"
    assert_eq 0 "$(_body_check_rc "acc$i.json")" "accepted: $body"
  done
  i=0
  for body in "${rejected[@]}"; do
    i=$((i + 1))
    printf '%s' "$body" > "rej$i.json"
    assert_ne 0 "$(_body_check_rc "rej$i.json")" "rejected: $body"
  done

  # 32 attestations pass, 33 do not (server cap, action_router.rs:437).
  jq -n -c '{sbom:"s", attestations:[range(32) | "a"]}' > a32.json
  jq -n -c '{sbom:"s", attestations:[range(33) | "a"]}' > a33.json
  assert_eq 0 "$(_body_check_rc a32.json)" "32 attestations are accepted"
  assert_eq 1 "$(_body_check_rc a33.json)" "33 attestations are refused"
}

# ------------------------------------------------------ summary_counters.jq

test_intent_summary_counters_keeps_results_out_of_the_summary__filter() {
  local f needle
  for f in response-violated response-odd; do
    _filter summary_counters "$FIXTURES_FILTERS/$f.json" "$f.md" -r
    for needle in VIOLATED SATISFIED INDETERMINATE STALEHISTORY LEAKEDTOPLEVEL \
                  RECORDONLYOUTCOME NOT_APPLICABLE outcome 'cra-' \
                  "The engine's last verdict" 'kept as history' \
                  'This is not a result' 'there is no document in force' \
                  'Odd legend' 'record legend' \
                  vuln_scan sbom_within_tolerance x_future_category 'Bad Name' \
                  scan_created_at evaluated_at '2099-' surprise_status \
                  'gh-987654321' 'example-org' 'seetrex.record'; do
      assert_file_not_contains "$f.md" "$needle" "$f counters summary: no [$needle]"
    done
  done
  # It still counts, by status only.
  assert_eq "$(cat "$FIXTURES_FILTERS/response-violated.counters.md")" \
    "$(cat response-violated.md)" "counters summary of response-violated"
  assert_line_eq response-odd.md '- other: 2' "unknown statuses are counted, not named"
  assert_line_eq response-odd.md '- current: 1' "current counted"
}

# ---------------------------------------------------------- summary_full.jq

test_intent_summary_full_renders_from_results_never_from_the_record() {
  _filter summary_full "$FIXTURES_FILTERS/response-violated.json" out.md -r
  assert_eq "$(cat "$FIXTURES_FILTERS/response-violated.full.md")" "$(cat out.md)" \
    "full summary of response-violated"
  assert_file_not_contains out.md 'cra-record-only-marker' "no ruleset of record.results"
  assert_file_not_contains out.md 'RECORDONLYOUTCOME' "no outcome of record.results"
  assert_file_not_contains out.md 'record legend marker' "no legend of record.results"
  assert_file_not_contains out.md '2099-01-01' "no date of record.results"
  assert_file_not_contains out.md 'seetrex.record' "nothing else of the record"

  # With results gone, the record does not stand in for them.
  jq 'del(.results)' "$FIXTURES_FILTERS/response-violated.json" > noresults.json
  _filter summary_full noresults.json nores.md -r
  assert_file_not_contains nores.md 'cra-' "no obligation when results is missing"
  assert_file_not_contains nores.md 'RECORDONLYOUTCOME' "record not read when results is missing"
  assert_line_eq nores.md 'The answer carried no readable results.' "fixed line without results"
}

test_intent_summary_full_shows_outcome_only_for_current() {
  _filter summary_full "$FIXTURES_FILTERS/response-violated.json" ok.md -r
  assert_line_eq ok.md '| `cra-art13-vulnerability-handling` | current | VIOLATED |' "current shows its outcome"
  assert_line_eq ok.md '| `cra-art13-third-party-components` | not current | - |' \
    "not_current shows no outcome"
  assert_file_not_contains ok.md 'STALEHISTORY' "last_verdict.outcome never shown"

  _filter summary_full "$FIXTURES_FILTERS/response-odd.json" odd.md -r
  assert_file_not_contains odd.md 'STALEHISTORY' "last_verdict.outcome never shown (odd)"
  assert_file_not_contains odd.md 'LEAKEDTOPLEVEL' "an outcome on a not_current is not shown"
  assert_line_eq odd.md '| `cra-annex1-secure-design` | not current | - |' "not_current row"
  assert_line_eq odd.md '| `cra-art13-security-updates` | (unknown status) | - |' \
    "an unknown status shows no outcome and is not echoed"
  assert_file_not_contains odd.md 'surprise_status' "unknown status not echoed"
}

test_intent_summary_full_copies_the_legend_verbatim() {
  local key text
  _filter summary_full "$FIXTURES_FILTERS/response-violated.json" out.md -r
  for key in current not_current no_verdict not_documented; do
    jq -r --arg k "$key" '.results.legend[$k]' "$FIXTURES_FILTERS/response-violated.json" > legend.raw
    _lf legend.raw legend.txt
    text="$(cat legend.txt)"
    assert_line_eq out.md "- **${key//_/ }**: $text" "legend $key verbatim"
  done
  _filter summary_full "$FIXTURES_FILTERS/response-odd.json" odd.md -r
  assert_line_eq odd.md '- **current**: Odd legend current, verbatim.' "legend copied from the answer, not built in"
  assert_line_eq odd.md '- **not documented**: (missing from the answer)' "a missing legend entry is not invented"
}

test_intent_summary_full_echoes_only_well_formed_skipped_names() {
  local n
  _filter summary_full "$FIXTURES_FILTERS/response-odd.json" odd.md -r
  assert_line_eq odd.md '- `x_future_category`: a document of this category was not read.' \
    "a well-formed unknown name gets the fixed sentence"
  assert_line_eq odd.md '- `vuln_scan`: the vulnerability report was not read (it was over its size cap, or the Action left it out); the obligations that read it are not current.' \
    "vuln_scan gets its fixed sentence"
  assert_file_not_contains odd.md 'Bad Name' "an ill-formed name is not echoed"
  assert_file_not_contains odd.md '<b>' "no markup from skipped"
  assert_file_not_contains odd.md 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    "a name over 64 characters is not echoed"
  assert_file_not_contains odd.md '42' "a non-string is not echoed"
  grep -c -F -x -- '- A document was left out for a reason this version of the Action cannot read.' odd.md > n.raw || true
  _lf n.raw n
  n="$(cat n)"
  assert_eq 4 "$n" "one generic line per ill-formed value (bad, too long, empty, number)"

  # No skipped key: no section at all.
  jq 'del(.skipped)' "$FIXTURES_FILTERS/response-violated.json" > noskip.json
  _filter summary_full noskip.json noskip.md -r
  assert_file_not_contains noskip.md 'Left out of this push' "no section without skipped"
}

test_intent_summary_full_never_echoes_markup_from_the_answer() {
  _filter summary_full "$FIXTURES_FILTERS/response-odd.json" odd.md -r
  assert_file_not_contains odd.md '<img' "outcome markup not echoed"
  assert_file_not_contains odd.md '<script' "evaluated_at markup not echoed"
  assert_file_not_contains odd.md 'injected' "ruleset id with a pipe not echoed"
  assert_line_eq odd.md '| `cra-art13-vulnerability-handling` | current | (unreadable) |' \
    "an ill-formed outcome reads as unreadable"
  assert_line_eq odd.md 'Evaluated at: (unreadable)' "an ill-formed date reads as unreadable"
  assert_line_eq odd.md 'Scan in force created at: none readable' "null scan_created_at"

  # A value that matches its pattern but for a final newline (jq's `$` also
  # matches before one) is unreadable too: `jq -r` would print it as two
  # lines (review A-M7 of the third review).
  jq '.results.evaluated_at += "\n" | .results.scan_created_at += "\n"
      | .results.obligations[0].ruleset_id += "\n"
      | .results.obligations[0].outcome += "\n"' \
    "$FIXTURES_FILTERS/response-violated.json" > nl.json
  _filter summary_full nl.json nl.md -r
  assert_line_eq nl.md 'Evaluated at: (unreadable)' "evaluated_at ending in a newline"
  assert_line_eq nl.md 'Scan in force created at: (unreadable)' "scan_created_at ending in a newline"
  assert_line_eq nl.md '| `(unreadable)` | current | (unreadable) |' "ruleset id and outcome ending in a newline"
}

# ---------------------------------------------------------------- dry_run.jq

test_intent_dry_run_filter_shows_keys_sizes_and_counts_only() {
  local s_bytes t_bytes
  _filter sbom "$FIXTURES_FILTERS/sbom-nested.cdx.json" sbom.json -c
  _filter trivy "$FIXTURES_FILTERS/trivy-with-metadata.json" trivy.json -c
  printf '{"a":1}' > att1
  printf '{"bb":2}' > att2
  jq -n -c --rawfile s sbom.json --rawfile t trivy.json --rawfile a1 att1 --rawfile a2 att2 \
    '{sbom:$s, trivy:$t, attestations:[$a1,$a2]}' > body.json
  s_bytes="$(wc -c < sbom.json)"
  s_bytes="${s_bytes//[[:space:]]/}"
  t_bytes="$(wc -c < trivy.json)"
  t_bytes="${t_bytes//[[:space:]]/}"

  # Exactly these lines: keys, sizes, the attestation count. Nothing else.
  _filter dry_run body.json out.txt -r
  printf '%s\n' \
    'Body keys: attestations, sbom, trivy' \
    'attestations: 2 documents, 15 bytes' \
    "sbom: $s_bytes bytes" \
    "trivy: $t_bytes bytes" > expected.txt
  assert_eq "$(cat expected.txt)" "$(cat out.txt)" "dry-run lines of a document push"

  # Nothing from inside a document.
  local needle
  for needle in CVE- GHSA- left-pad HIGH LOW outer-fixture inner-fixture \
                Vulnerabilit component purl 'bom-ref' severit; do
    assert_file_not_contains out.txt "$needle" "dry run: no [$needle]"
  done

  # Left-out report and control requests.
  jq -n -c --rawfile s sbom.json '{sbom:$s, trivy_left_out:true, attestations:[]}' > left.json
  _filter dry_run left.json left.txt -r
  printf '%s\n' \
    'Body keys: attestations, sbom, trivy_left_out' \
    'attestations: 0 documents, 0 bytes' \
    "sbom: $s_bytes bytes" \
    'trivy_left_out: true (the vulnerability report is left out)' > left.expected
  assert_eq "$(cat left.expected)" "$(cat left.txt)" "dry-run lines of a push with the report left out"
  printf '{"repin":true}' > repin.json
  _filter dry_run repin.json repin.txt -r
  printf '%s\n' 'Body keys: repin' 'repin: true (control request)' > repin.expected
  assert_eq "$(cat repin.expected)" "$(cat repin.txt)" "dry-run lines of a repin request"
}

test_intent_dry_run_filter_never_echoes_an_undeclared_key() {
  printf '{"sbom":"s","alice@example.invalid":"x","Metadata":{"Author":"Alice"}}' > body.json
  _filter dry_run body.json out.txt -r
  assert_file_not_contains out.txt 'alice' "undeclared key not echoed"
  assert_file_not_contains out.txt 'Metadata' "undeclared key not echoed"
  assert_file_not_contains out.txt 'Alice' "undeclared value not echoed"
  assert_line_eq out.txt 'Body keys: (undeclared), (undeclared), sbom' "undeclared keys shown as such"
}
