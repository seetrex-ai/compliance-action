# shellcheck shell=bash
# Tests of bin/detect.sh (the detectors of the proposal step, plan R4
# section 1 layer D) and of bin/filters/facts.jq: run directly over the
# fixture tree of tests/fixtures/propose/tree, and through bin/run.sh in a
# dry run with propose: true (the tree is then the one of GITHUB_SHA).

FIXTURES_PROPOSE="$TESTS_DIR/fixtures/propose"

DETECTOR_IDS='dependency_review_step dependency_update_config security_policy_file security_contact security_analyzer_step scheduled_security_analysis release_provenance_step threat_model_file supported_versions_table codeowners_file'

# _detect <tree> <out.json>: runs bin/detect.sh of the Action under test on a
# tree; fails the test if it exits non-zero or prints something else.
_detect() {
  local rc=0
  bash "$ACTION_ROOT/bin/detect.sh" "$1" "$ACTION_ROOT/bin/filters" > "$2.raw" 2> "$2.err" || rc=$?
  if [ "$rc" -ne 0 ]; then
    cat "$2.err" >&2
    fail "detect.sh exited $rc"
  fi
  tr -d '\r' < "$2.raw" > "$2"
}

# _lines_sha <file> <start> <end>: the contract's line-range hash, computed
# independently of detect.sh (sed + command substitution, not awk).
_lines_sha() {
  local text line
  text="$(sed -n "$2,$3p" "$1" | sed 's/\r$//')"
  line="$(printf '%s' "$text" | sha256sum)"
  printf '%s\n' "${line%% *}"
}

# _fact <facts.json> <id> <path>: prints "start end sha" of that fact, or
# nothing when the fact is absent.
_fact() {
  jq -r --arg id "$2" --arg p "$3" \
    '.facts[] | select(.id == $id and .path == $p) | "\(.line_start) \(.line_end) \(.line_sha256)"' "$1" \
    | tr -d '\r'
}

# _commit_tree <dir>: copies a fixture tree into the workspace, commits it in
# one commit and points GITHUB_SHA and the event at it.
_commit_tree() {
  cp -R "$1/." "$WS/"
  git -C "$WS" add -A
  git -C "$WS" commit -q -m "fixture tree"
  _refresh_sha
  make_event private
}

test_intent_detector_ignores_the_seetrex_action_itself() {
  # INTENT: a workflow that names the step seetrex-ai/compliance-action is
  # never a fact: not its `run: trivy fs .` as a security analyzer, not its
  # cron as a scheduled analysis, not anything else of that file. Another
  # workflow with CodeQL and a cron does give both facts.
  # CONTEXT: plan R4 section 1 (mandatory exclusion): the Action's own
  # vulnerability scan would otherwise count as the user's security testing
  # (circular evidence).
  # EXPIRES IF: the detectors stop reading workflows.
  local f="$TEST_TMP/facts.json" only="$TEST_TMP/only"
  _detect "$FIXTURES_PROPOSE/tree" "$f"
  assert_json "$f" '[.facts[] | select(.path == ".github/workflows/seetrex.yml")] | length == 0' \
    "no fact cites the Action's own workflow"
  assert_json "$f" '[.facts[] | select(.id == "security_analyzer_step")] | map(.path) == [".github/workflows/codeql.yml"]' \
    "the analyzer fact is CodeQL's workflow only"
  assert_json "$f" '[.facts[] | select(.id == "scheduled_security_analysis")] | map(.path) == [".github/workflows/codeql.yml"]' \
    "the scheduled fact is CodeQL's workflow only"
  assert_eq "12 12 $(_lines_sha "$FIXTURES_PROPOSE/tree/.github/workflows/codeql.yml" 12 12)" \
    "$(_fact "$f" security_analyzer_step .github/workflows/codeql.yml)" "CodeQL: the analyze step line is cited"
  assert_eq "5 5 $(_lines_sha "$FIXTURES_PROPOSE/tree/.github/workflows/codeql.yml" 5 5)" \
    "$(_fact "$f" scheduled_security_analysis .github/workflows/codeql.yml)" "CodeQL: the cron line is cited"
  assert_eq "11 11 $(_lines_sha "$FIXTURES_PROPOSE/tree/.github/workflows/release.yml" 11 11)" \
    "$(_fact "$f" release_provenance_step .github/workflows/release.yml)" "release: the provenance step is cited"

  # A tree whose only workflow is the Action's: no workflow fact at all.
  mkdir -p "$only/.github/workflows"
  cp "$FIXTURES_PROPOSE/tree/.github/workflows/seetrex.yml" "$only/.github/workflows/ci.yml"
  _detect "$only" "$TEST_TMP/only.json"
  assert_json "$TEST_TMP/only.json" '.facts == []' "only the Action's workflow: no fact"
}

test_intent_detector_facts_follow_the_contract() {
  # INTENT: every fact has exactly the five fields of the contract, an id of
  # the closed catalogue, a repository path, 1 <= line_start <= line_end, and
  # a line_sha256 equal to the hash of those lines of the file computed by
  # another method; facts are unique; the output carries no text of the tree.
  # CONTEXT: reader contract 1 (facts.schema.json); R4-1a/R4-3 validate the
  # same shape on the other side, so the runner must produce it exactly.
  # EXPIRES IF: the contract changes version.
  local f="$TEST_TMP/facts.json" ids id n line id_ path start end sha
  _detect "$FIXTURES_PROPOSE/tree" "$f"
  assert_json "$f" '.version == 1 and (.facts | type) == "array" and (.facts | length) > 0' "version 1 with facts"
  assert_json "$f" '[.facts[] | keys] | all(. == ["id", "line_end", "line_sha256", "line_start", "path"])' \
    "exactly the five fields"
  ids="$(printf '%s' "$DETECTOR_IDS" | tr ' ' '\n' | jq -R . | jq -s -c .)"
  assert_json "$f" "[.facts[].id] | all(IN(${ids}[]))" "ids from the closed catalogue"
  assert_json "$f" '[.facts[] | .line_start >= 1 and .line_end >= .line_start] | all' "line order"
  assert_json "$f" '.facts == (.facts | unique)' "unique and sorted"
  assert_json "$f" '[.facts[].path] | all(test("^\\.?[A-Za-z0-9_-][A-Za-z0-9._-]*(/\\.?[A-Za-z0-9_-][A-Za-z0-9._-]*)*$"))' \
    "repository paths"
  n=0
  while IFS=$'\t' read -r id_ path start end sha; do
    assert_eq "$(_lines_sha "$FIXTURES_PROPOSE/tree/$path" "$start" "$end")" "$sha" "$id_ $path:$start-$end: hash of those lines"
    n=$((n + 1))
  done < <(jq -r '.facts[] | "\(.id)\t\(.path)\t\(.line_start)\t\(.line_end)\t\(.line_sha256)"' "$f" | tr -d '\r')
  assert_eq 10 "$n" "ten facts in the fixture tree"
  # Each detector the fixture tree exercises, by path.
  for id in security_policy_file security_contact supported_versions_table; do
    assert_json "$f" "[.facts[] | select(.id == \"$id\" and .path == \"SECURITY.md\")] | length == 1" "$id on SECURITY.md"
  done
  assert_json "$f" '[.facts[] | select(.id == "security_contact" and .path == ".well-known/security.txt")] | length == 1' \
    "security.txt contact"
  assert_eq "3 3 $(_lines_sha "$FIXTURES_PROPOSE/tree/SECURITY.md" 3 3)" "$(_fact "$f" security_policy_file SECURITY.md)" \
    "the report heading line is the fact"
  assert_eq "3 3 $(_lines_sha "$FIXTURES_PROPOSE/tree/.github/dependabot.yml" 3 3)" \
    "$(_fact "$f" dependency_update_config .github/dependabot.yml)" "the first package-ecosystem line"
  assert_eq "1 1 $(_lines_sha "$FIXTURES_PROPOSE/tree/docs/threat-model.md" 1 1)" "$(_fact "$f" threat_model_file docs/threat-model.md)" \
    "threat model hint"
  assert_eq "1 1 $(_lines_sha "$FIXTURES_PROPOSE/tree/CODEOWNERS" 1 1)" "$(_fact "$f" codeowners_file CODEOWNERS)" "CODEOWNERS hint"
  # Never text: no heading, address, command or file not on the fixed lists.
  for line in 'Reporting a Vulnerability' 'security@example.invalid' 'codeql-action' 'package-ecosystem' 'Threat model' \
    'maintainers' 'never sent' 'src/main.rs' 'docs/security-notes.md'; do
    assert_file_not_contains "$f" "$line" "the facts carry [$line]"
  done
}

test_intent_detectors_read_only_the_commit_tree() {
  # INTENT: through run.sh the detectors see exactly the tree of GITHUB_SHA:
  # a SECURITY.md modified in the worktree is cited with the hash of the
  # committed line, an untracked workflow with an analyzer and a staged-only
  # threat model give no fact, and a later commit checked out as HEAD is not
  # what is read.
  # CONTEXT: run.sh materialises the commit blob by blob (plan D1, review
  # I-7); the proposal step must not open a second door to the worktree.
  # EXPIRES IF: the server reads the commit itself.
  local old committed_sha
  setup_case
  _commit_tree "$FIXTURES_PROPOSE/tree"
  old="$GITHUB_SHA"
  committed_sha="$(_lines_sha "$FIXTURES_PROPOSE/tree/SECURITY.md" 3 3)"
  printf 'later commit\n' > "$CASE_DIR/later.txt"
  commit_file "$CASE_DIR/later.txt" later.txt
  export GITHUB_SHA="$old"
  make_event private
  printf '# Security Policy\n\n## Reporting a Vulnerability (edited in the worktree)\n' > "$WS/SECURITY.md"
  mkdir -p "$WS/.github/workflows"
  cp "$FIXTURES_PROPOSE/tree/.github/workflows/codeql.yml" "$WS/.github/workflows/untracked-semgrep.yml"
  printf '# Staged threat model\n' > "$WS/docs/THREAT_MODEL.md"
  git -C "$WS" add docs/THREAT_MODEL.md
  set_api_response 200 "$FIXTURES_PROPOSE/push-200.json"
  run_action dry-run=true propose=true
  assert_rc 0
  assert_line_eq "$RUN_STDOUT" "- security_policy_file: SECURITY.md:3-3, sha256 $committed_sha" \
    "the committed heading line, not the worktree's"
  assert_file_not_contains "$RUN_STDOUT" "untracked-semgrep.yml" "an untracked workflow is not read"
  assert_file_not_contains "$RUN_STDOUT" "THREAT_MODEL.md" "a staged-only file is not read"
  assert_file_not_contains "$RUN_STDOUT" "later.txt" "the later commit is not read"
  assert_eq 0 "$(api_call_count)" "dry run: no Seetrex call"
  assert_eq 0 "$(token_call_count)" "dry run: no token"
  assert_eq "# Security Policy" "$(head -n 1 "$WS/SECURITY.md")" "the worktree is untouched"
}

FIXTURES_DETECT="$TESTS_DIR/fixtures/detect"

test_intent_detector_counts_only_real_uncommented_steps() {
  # INTENT: a workflow detector counts only real steps: a commented `uses:`,
  # `run:`, `cron:` or a commented line inside a run block never makes a
  # fact; security_analyzer_step is CodeQL, Semgrep, Trivy, grype,
  # OSV-Scanner, `cargo audit`, `npm audit` only (gitleaks, zizmor,
  # Scorecard, `pnpm audit`, `yarn audit` do not count, nor a step named
  # "trivy"); release_provenance_step is a step that signs or attests, never
  # the cosign installer. A real `npm audit` line of a run block, a
  # `cosign sign-blob` of a folded block and a dependency-review step do
  # count, with their line.
  # CONTEXT: R4-4 review round 1 (a commented analyzer counted; the list of
  # analyzers went beyond plan R4 section 1 as amended by R4-1b).
  # EXPIRES IF: the detectors parse YAML with a real parser.
  local f="$TEST_TMP/neg.json" p="$TEST_TMP/pos.json" t="$FIXTURES_DETECT/positive"
  _detect "$FIXTURES_DETECT/negative" "$f"
  assert_json "$f" '[.facts[] | select(.path | startswith(".github/workflows/"))] == []' \
    "negative tree: no workflow fact (commented steps, non-product analyzers, the cosign installer, the Action in capitals)"
  _detect "$t" "$p"
  assert_eq "15 15 $(_lines_sha "$t/.github/workflows/ci.yml" 15 15)" "$(_fact "$p" security_analyzer_step .github/workflows/ci.yml)" \
    "the npm audit line of a run block"
  assert_eq "6 6 $(_lines_sha "$t/.github/workflows/ci.yml" 6 6)" "$(_fact "$p" scheduled_security_analysis .github/workflows/ci.yml)" \
    "the cron of the analyzer's workflow"
  assert_eq "16 16 $(_lines_sha "$t/.github/workflows/ci.yml" 16 16)" "$(_fact "$p" dependency_review_step .github/workflows/ci.yml)" \
    "the dependency-review step"
  assert_eq "12 12 $(_lines_sha "$t/.github/workflows/release.yml" 12 12)" "$(_fact "$p" release_provenance_step .github/workflows/release.yml)" \
    "cosign sign-blob in a folded block, not the installer line"
}

test_intent_detector_excludes_the_action_by_its_uses_step_only() {
  # INTENT: the Action's own workflow is excluded by a `uses:` step whose
  # value starts with seetrex-ai/compliance-action, in any case; a comment
  # that names the Action (a line of its own or after another step) does not
  # exclude a legitimate workflow; `uses: ./` is the Action only in the
  # Action's own repository (GITHUB_REPOSITORY seetrex-ai/compliance-action).
  # CONTEXT: R4-4 review round 1 (a case-sensitive grep of the whole file:
  # a comment excluded a workflow, capitals did not).
  # EXPIRES IF: the Action stops scanning vulnerabilities itself.
  local f="$TEST_TMP/f.json"
  _detect "$FIXTURES_DETECT/negative" "$f"
  assert_json "$f" '[.facts[] | select(.path == ".github/workflows/seetrex-upper.yml")] == []' \
    "Seetrex-AI/Compliance-Action in capitals: excluded"
  _detect "$FIXTURES_DETECT/positive" "$f"
  assert_json "$f" '[.facts[] | select(.path == ".github/workflows/ci.yml")] | length == 3' \
    "a workflow whose comments name the Action is still read"
  GITHUB_REPOSITORY=example-org/example-repo _detect "$FIXTURES_DETECT/self" "$f"
  assert_json "$f" '[.facts[] | select(.id == "security_analyzer_step")] | length == 1' "uses: ./ in another repository: not the Action"
  GITHUB_REPOSITORY=Seetrex-AI/Compliance-Action _detect "$FIXTURES_DETECT/self" "$f"
  assert_json "$f" '.facts == []' "uses: ./ in the Action's own repository: excluded"
}

test_intent_detector_contact_is_an_address_not_a_remote_or_the_own_form() {
  # INTENT: security_contact is an e-mail address of SECURITY.md (or the
  # Contact: of security.txt): an SSH remote (git@github.com:org/repo.git),
  # the user of an ssh:// URL and the .../security/advisories/new form of the
  # repository are never a contact, in SECURITY.md nor as the Contact: of
  # security.txt (any case, http or https, www., a trailing /); a real
  # address on a later line is cited, and so is the advisories form of
  # another repository in security.txt.
  # CONTEXT: contract 1 (detector_id: the advisories form of the pushing
  # repository is never a security_contact fact) and R4-4 review rounds 1
  # and 2 (security.txt took any Contact: line, the own form included).
  # EXPIRES IF: the repositories stop being treated as private.
  local f="$TEST_TMP/f.json" t="$FIXTURES_DETECT/positive"
  GITHUB_REPOSITORY=example-org/example-repo _detect "$FIXTURES_DETECT/negative" "$f"
  assert_json "$f" '[.facts[] | select(.id == "security_contact")] == []' "remotes and the advisories form: no contact"
  GITHUB_REPOSITORY=example-org/example-repo _detect "$t" "$f"
  assert_eq "4 4 $(_lines_sha "$t/SECURITY.md" 4 4)" "$(_fact "$f" security_contact SECURITY.md)" "the address on line 4, not the remote on line 3"
  assert_eq "2 2 $(_lines_sha "$t/.well-known/security.txt" 2 2)" "$(_fact "$f" security_contact .well-known/security.txt)" \
    "security.txt: another repository's form on line 2, not the own form on line 1"
  # The hint for the threat model also reads .github/THREAT_MODEL.md.
  assert_eq "1 1 $(_lines_sha "$t/.github/THREAT_MODEL.md" 1 1)" "$(_fact "$f" threat_model_file .github/THREAT_MODEL.md)" \
    ".github/THREAT_MODEL.md is a threat-model hint"
}
