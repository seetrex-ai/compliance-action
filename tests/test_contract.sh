# shellcheck shell=bash
# Tests of the copy of reader contract 1 the Action speaks
# (tests/fixtures/contract, from the Seetrex repository; README.md there says
# from which commit) and of bin/contract/reader-contract-1.json, the part of
# it bin/propose.sh reads at run time.

CONTRACT_DIR="$TESTS_DIR/fixtures/contract"

test_intent_runtime_contract_is_derived_from_the_contract() {
  # INTENT: bin/contract/reader-contract-1.json is exactly what derive.jq
  # gives from the copied schemas (closed list of documents, detector
  # catalogue, per category the payload leaves with their fixed values and
  # the fields each layer may cite); the leaves of every payload are exactly
  # the boolean keys of the category's template; every pending field is a
  # fixed leaf; the detector catalogue of filters/facts.jq is the contract's;
  # the copies are the ones README.md names by hash.
  # CONTEXT: R4-4 review round 1 (the branch carried lists of its own written
  # on an older contract).
  # EXPIRES IF: the contract changes version (then the copies change, with
  # README.md, in the same commit).
  local f cat line name sha
  jq -S -n --slurpfile req "$CONTRACT_DIR/propose-request.schema.json" \
    --slurpfile resp "$CONTRACT_DIR/propose-response.schema.json" \
    --slurpfile facts "$CONTRACT_DIR/facts.schema.json" -f "$CONTRACT_DIR/derive.jq" > "$TEST_TMP/derived.json"
  assert_eq true "$(jq -n --slurpfile a "$TEST_TMP/derived.json" --slurpfile b "$ACTION_ROOT/bin/contract/reader-contract-1.json" \
    '$a[0] == $b[0]' | tr -d '\r')" "bin/contract/reader-contract-1.json is the derivation of the copied contract"
  assert_file_not_contains "$ACTION_ROOT/bin/contract/reader-contract-1.json" $'\r' "LF line endings"
  for f in "$CONTRACT_DIR"/templates/*.json; do
    cat="$(basename "$f" .json)"
    [ "$cat" = security_updates_policy ] && continue
    assert_eq "$(jq -c '[.payload | paths(type == "boolean") | join(".")] | sort' "$f" | tr -d '\r')" \
      "$(jq -c --arg c "$cat" '.categories[$c].leaves | keys' "$ACTION_ROOT/bin/contract/reader-contract-1.json" | tr -d '\r')" \
      "$cat: the payload leaves are the template's keys"
  done
  assert_json "$ACTION_ROOT/bin/contract/reader-contract-1.json" \
    '[.categories[] | select(.leaves != null) | .pending_fields[] as $f | .leaves[$f] != null] | all' "every pending field has a fixed value"
  assert_json "$ACTION_ROOT/bin/contract/reader-contract-1.json" \
    '[.categories[] | select(.leaves != null) | (.model_fields + .detector_fields + .scan_fields)[] as $f | .leaves[$f] == null] | all' \
    "every citable field is a free leaf"
  assert_json "$ACTION_ROOT/bin/contract/reader-contract-1.json" '.categories.security_updates_policy.leaves == null' \
    "security_updates_policy has no payload to propose"
  line="$(sed -n '/^def catalogue:/,/;$/p' "$ACTION_ROOT/bin/filters/facts.jq" | tr -d '\r\n' | sed 's/^def catalogue://; s/;$//')"
  assert_eq "$(jq -c '."$defs".detector_id.enum' "$CONTRACT_DIR/facts.schema.json" | tr -d '\r')" "$(jq -n -c "$line" | tr -d '\r')" \
    "facts.jq's catalogue is the contract's"
  while read -r sha name; do
    assert_eq "$sha" "$(sha256sum < "$CONTRACT_DIR/$name" | cut -d' ' -f1)" "$name: the copy README.md names"
  done < <(sed -n '/^```$/,/^```$/p' "$CONTRACT_DIR/README.md" | grep -E '^[0-9a-f]{64}  ' | tr -d '\r')
}

test_intent_contract_validator_checks_the_keywords_it_reads() {
  # INTENT: tests/fixtures/contract/validate.jq, which the proposal tests
  # use to check requests and envelopes against the contract, accepts a
  # valid document and refuses each rule it claims: an extra key, a value
  # outside an enum, a pattern, a cap, a missing key, oneOf; and refuses a
  # keyword it does not know instead of ignoring it.
  # CONTEXT: R4-4 review round 1 (validate the request against the schema).
  # EXPIRES IF: the tests use a full JSON Schema validator instead.
  local doc out
  _v() {
    jq -c -n --slurpfile schema "$CONTRACT_DIR/propose-request.schema.json" --slurpfile doc "$1" --arg def '' \
      -f "$CONTRACT_DIR/validate.jq" | tr -d '\r'
  }
  doc="$TEST_TMP/doc.json"
  printf '{"version":1,"start":{"categories":["cvd_disclosure_report"],"facts":[],"scan":{"finding_count":0,"scanned_packages":3,"report_sha256":"%s"}}}' \
    "$(printf 'x' | sha256sum | cut -d' ' -f1)" > "$doc"
  assert_eq '[]' "$(_v "$doc")" "a valid start"
  jq '.start.extra = 1' "$doc" > "$doc.1"
  assert_ne '[]' "$(_v "$doc.1")" "an extra key of start"
  jq '.start.categories = ["changelog"]' "$doc" > "$doc.2"
  assert_ne '[]' "$(_v "$doc.2")" "a category outside the enum"
  jq '.start.scan.report_sha256 |= ascii_upcase' "$doc" > "$doc.3"
  assert_ne '[]' "$(_v "$doc.3")" "an upper-case sha256 (pattern)"
  jq '.start.scan.scanned_packages = 1000001' "$doc" > "$doc.4"
  assert_ne '[]' "$(_v "$doc.4")" "a count over the cap"
  jq 'del(.start.facts)' "$doc" > "$doc.5"
  assert_ne '[]' "$(_v "$doc.5")" "a missing key"
  jq '.start.documents = [{path: "CHANGELOG.md", bytes: 1, sha256: .start.scan.report_sha256, text: "x"}]' "$doc" > "$doc.6"
  assert_ne '[]' "$(_v "$doc.6")" "a document off the closed list"
  printf '{"version":1,"ticket":"%s"}' "$(printf 'a%.0s' $(seq 1 40))" > "$doc.7"
  assert_eq '[]' "$(_v "$doc.7")" "a valid poll (the other branch of oneOf)"
  printf '{"type":"object","if":{}}' > "$TEST_TMP/unknown.schema.json"
  out="$(jq -c -n --slurpfile schema "$TEST_TMP/unknown.schema.json" --slurpfile doc "$doc" --arg def '' \
    -f "$CONTRACT_DIR/validate.jq" | tr -d '\r')"
  assert_contains "$out" "unknown keyword" "a keyword the validator does not know is an error"
}
