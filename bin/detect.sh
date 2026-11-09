#!/usr/bin/env bash
# Seetrex Compliance Action -- bin/detect.sh: the deterministic detectors of
# the proposal step (plan R4 section 1, layer D, plus the three hints of the
# reader contract), run by bin/propose.sh.
#
#   bash "$GITHUB_ACTION_PATH/bin/detect.sh" <tree> <filters>
#
# <tree> is the tree of GITHUB_SHA as run.sh wrote it under WORK (blob by
# blob, byte for byte as committed: never the worktree); <filters> is
# bin/filters/. Prints ONE JSON document to stdout, assembled by
# filters/facts.jq to the shape of facts.schema.json of reader contract 1:
#   {version: 1, facts: [{id, path, line_start, line_end, line_sha256}]}
# A fact is a detector id and a line locator with the hash of those lines
# (the lines line_start..line_end, each without its \n or \r\n, joined with
# \n, no trailing \n, SHA-256, lower-case hex). This script never prints a
# line of the repository: no heading, no address, no command, no file name
# outside the fixed lists below. Everything else of the repository stays in
# the runner.
#
# Detectors (id -> what is cited):
#   dependency_review_step      a `uses: actions/dependency-review-action`
#                               step of a workflow
#   dependency_update_config    the first `package-ecosystem:` line of
#                               .github/dependabot.yml|yaml, or line 1 of a
#                               Renovate configuration file
#   security_policy_file        the heading of a report/disclosure section
#                               of SECURITY.md (root, .github/, docs/)
#   security_contact            a line of SECURITY.md with an e-mail address
#                               or a `/security/advisories/new` URL, or the
#                               `Contact:` line of .well-known/security.txt
#   security_analyzer_step      a workflow step that runs an analyzer
#                               (CodeQL, Trivy, grype, Semgrep, OSV-Scanner,
#                               cargo/npm audit, gitleaks, zizmor, Scorecard)
#   scheduled_security_analysis the `cron:` line of a workflow that runs an
#                               analyzer
#   release_provenance_step     a workflow step that signs or attests a
#                               release (attest-build-provenance, cosign,
#                               slsa-github-generator)
#   threat_model_file           line 1 of THREAT_MODEL.md,
#                               docs/THREAT_MODEL.md or docs/threat-model.md
#   supported_versions_table    the "Supported Versions" heading of SECURITY.md
#   codeowners_file             line 1 of CODEOWNERS (root, .github/, docs/)
# One fact per detector and file: the first matching line.
#
# Exclusion (plan R4 section 1): a workflow that names the step
# `seetrex-ai/compliance-action` is skipped whole by every workflow detector,
# so the Action's own vulnerability scan never counts as the user's security
# testing (circular evidence).
set +x
set -euo pipefail
umask 077

if [ $# -ne 2 ] || [ ! -d "$1" ] || [ ! -f "$2/facts.jq" ]; then
  printf 'detect.sh: usage: detect.sh <tree> <filters> (a tree directory and bin/filters with facts.jq)\n' >&2
  exit 2
fi
TREE="$1"
FILTERS="$2"

readonly SEETREX_STEP='seetrex-ai/compliance-action'
readonly SECURITY_FILES='SECURITY.md .github/SECURITY.md docs/SECURITY.md'
readonly THREAT_MODEL_FILES='THREAT_MODEL.md docs/THREAT_MODEL.md docs/threat-model.md'
readonly CODEOWNERS_FILES='CODEOWNERS .github/CODEOWNERS docs/CODEOWNERS'
readonly DEPENDABOT_FILES='.github/dependabot.yml .github/dependabot.yaml'
readonly RENOVATE_FILES='renovate.json renovate.json5 .renovaterc .renovaterc.json .github/renovate.json .github/renovate.json5'
readonly SECURITY_TXT='.well-known/security.txt'

# Extended regular expressions (grep -E). `uses:` steps are matched by their
# action name, commands by the word at the start of a command.
readonly RE_USES='^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*["'"'"']?'
readonly RE_CMD='(^|run:|&&|;|\|)[[:space:]]*'
readonly RE_DEP_REVIEW="${RE_USES}actions/dependency-review-action[@/]"
readonly RE_ANALYZER_USES="${RE_USES}(github/codeql-action/analyze|aquasecurity/trivy-action|anchore/scan-action|returntocorp/semgrep-action|semgrep/semgrep-action|google/osv-scanner-action|google/osv-scanner/actions/scanner|rustsec/audit-check|actions-rust-lang/audit|gitleaks/gitleaks-action|zizmorcore/zizmor-action|ossf/scorecard-action)[@/]"
readonly RE_ANALYZER_CMD="${RE_CMD}(cargo[[:space:]]+audit|npm[[:space:]]+audit|pnpm[[:space:]]+audit|yarn[[:space:]]+(npm[[:space:]]+)?audit|semgrep|trivy|grype|gitleaks|zizmor|osv-scanner)([[:space:]]|\$)"
readonly RE_CRON='^[[:space:]]*(-[[:space:]]*)?cron:[[:space:]]*'
readonly RE_PROVENANCE_USES="${RE_USES}(actions/attest-build-provenance|actions/attest|sigstore/cosign-installer|sigstore/gh-action-sigstore-python|slsa-framework/slsa-github-generator)[@/]"
readonly RE_PROVENANCE_CMD="${RE_CMD}cosign[[:space:]]+(sign|attest)([[:space:]]|\$)"
readonly RE_PACKAGE_ECOSYSTEM='^[[:space:]]*(-[[:space:]]*)?package-ecosystem:'
readonly RE_REPORT_HEADING='^#{1,6}[[:space:]].*(report|disclos)'
readonly RE_SUPPORTED_HEADING='^#{1,6}[[:space:]].*supported[[:space:]]+versions'
readonly RE_CONTACT='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|/security/advisories/new'
readonly RE_SECURITY_TXT_CONTACT='^Contact:[[:space:]]*[^[:space:]]'

WORK="$(mktemp -d)"
# shellcheck disable=SC2317  # runs from the EXIT trap below
cleanup() {
  rm -rf -- "$WORK"
}
trap cleanup EXIT
: > "$WORK/facts.tsv"

# A regular file of the tree, by repository path; never through a link.
tree_file() {
  [ -f "$TREE/$1" ] && [ ! -L "$TREE/$1" ]
}

# Number of lines of a file (a last line without \n counts).
line_count() {
  local n
  n="$(awk 'END { print NR }' "$1")"
  printf '%s\n' "${n//[[:space:]]/}"
}

# SHA-256 of lines <start>..<end> of <file> under the contract's rule.
range_sha256() {
  local line
  line="$(awk -v s="$2" -v e="$3" \
    'NR >= s && NR <= e { sub(/\r$/, ""); if (NR > s) printf "\n"; printf "%s", $0 }' \
    "$1" | sha256sum)"
  printf '%s\n' "${line%% *}"
}

# Number of the first line of <file> matching the ERE <re> (case-insensitive);
# empty when none. The line itself is never kept.
first_match() {
  local out
  out="$(grep -a -n -i -E -m 1 -e "$2" -- "$1" 2> /dev/null || true)"
  out="${out%%:*}"
  out="${out%$'\r'}"
  if [[ "$out" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$out"
  fi
}

# emit <id> <path> <start> <end>: one candidate fact.
emit() {
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$(range_sha256 "$TREE/$2" "$3" "$4")" >> "$WORK/facts.tsv"
}

# emit_first <id> <path> <re>: cites the first line matching <re>, if any.
emit_first() {
  local n
  n="$(first_match "$TREE/$2" "$3")"
  if [ -n "$n" ]; then
    emit "$1" "$2" "$n" "$n"
  fi
}

# emit_line1 <id> <path>: cites line 1 of a non-empty file.
emit_line1() {
  if [ "$(line_count "$TREE/$2")" -ge 1 ]; then
    emit "$1" "$2" 1 1
  fi
}

# ------------------------------------------------------------- workflows
shopt -s nullglob
for wf in "$TREE"/.github/workflows/*.yml "$TREE"/.github/workflows/*.yaml; do
  [ -f "$wf" ] && [ ! -L "$wf" ] || continue
  rel="${wf#"$TREE/"}"
  # The Action's own workflow is never evidence.
  if grep -a -q -F -e "$SEETREX_STEP" -- "$wf" 2> /dev/null; then
    continue
  fi
  emit_first dependency_review_step "$rel" "$RE_DEP_REVIEW"
  n="$(first_match "$wf" "$RE_ANALYZER_USES")"
  if [ -z "$n" ]; then
    n="$(first_match "$wf" "$RE_ANALYZER_CMD")"
  fi
  if [ -n "$n" ]; then
    emit security_analyzer_step "$rel" "$n" "$n"
    emit_first scheduled_security_analysis "$rel" "$RE_CRON"
  fi
  n="$(first_match "$wf" "$RE_PROVENANCE_USES")"
  if [ -z "$n" ]; then
    n="$(first_match "$wf" "$RE_PROVENANCE_CMD")"
  fi
  if [ -n "$n" ]; then
    emit release_provenance_step "$rel" "$n" "$n"
  fi
done
shopt -u nullglob

# ------------------------------------------------------- dependency updates
for f in $DEPENDABOT_FILES; do
  tree_file "$f" || continue
  emit_first dependency_update_config "$f" "$RE_PACKAGE_ECOSYSTEM"
done
for f in $RENOVATE_FILES; do
  tree_file "$f" || continue
  emit_line1 dependency_update_config "$f"
done

# ----------------------------------------------------------- SECURITY.md
for f in $SECURITY_FILES; do
  tree_file "$f" || continue
  emit_first security_policy_file "$f" "$RE_REPORT_HEADING"
  emit_first security_contact "$f" "$RE_CONTACT"
  emit_first supported_versions_table "$f" "$RE_SUPPORTED_HEADING"
done
if tree_file "$SECURITY_TXT"; then
  emit_first security_contact "$SECURITY_TXT" "$RE_SECURITY_TXT_CONTACT"
fi

# ------------------------------------------------------------------ hints
for f in $THREAT_MODEL_FILES; do
  tree_file "$f" || continue
  emit_line1 threat_model_file "$f"
done
for f in $CODEOWNERS_FILES; do
  tree_file "$f" || continue
  emit_line1 codeowners_file "$f"
done

# ------------------------------------------------------------ assemble
jq -c -n -R -f "$FILTERS/facts.jq" < "$WORK/facts.tsv"
