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
#   security_contact            the first line of SECURITY.md with an e-mail
#                               address, or the first `Contact:` line of
#                               .well-known/security.txt (RFC 9116: an
#                               address or a URL) that is not the
#                               `.../security/advisories/new` form of the
#                               pushing repository (any case, http or https,
#                               with or without `www.` or a trailing `/`):
#                               contract 1, detector_id: a third party cannot
#                               open that form in a private repository. In
#                               SECURITY.md only an address counts, never a
#                               URL; an SSH remote (`git@github.com:o/r.git`)
#                               or a user in a URL (`ssh://git@host/...`) is
#                               not an address
#   security_analyzer_step      a workflow step that runs a product security
#                               analyzer: CodeQL, Trivy, grype, Semgrep,
#                               OSV-Scanner, `cargo audit`, `npm audit` (plan
#                               R4 section 1; gitleaks, zizmor, Scorecard and
#                               the other audits do not count)
#   scheduled_security_analysis the `cron:` line of a workflow that runs an
#                               analyzer
#   release_provenance_step     a workflow step that signs or attests:
#                               actions/attest-build-provenance,
#                               slsa-framework/slsa-github-generator, or a
#                               `cosign sign|sign-blob|attest|attest-blob`
#                               command (installing cosign is not signing)
#   threat_model_file           line 1 of THREAT_MODEL.md,
#                               .github/THREAT_MODEL.md, docs/THREAT_MODEL.md
#                               or docs/threat-model.md
#   supported_versions_table    the "Supported Versions" heading of SECURITY.md
#   codeowners_file             line 1 of CODEOWNERS (root, .github/, docs/)
# One fact per detector and file: the first matching line.
#
# Workflows are read step by step (steps_of below): a `uses:` line, a `run:`
# line or a line of a `run: |` / `run: >` block, a `cron:` line. A line whose
# first non-blank character is `#` is a comment and never counts, in the
# YAML or inside a run block; a `uses:` value is matched from its start, so
# a trailing comment never makes a step.
#
# Exclusion (plan R4 section 1): a workflow with a step `uses:
# seetrex-ai/compliance-action` (any case, `@ref` or a sub-path) is skipped
# whole by every workflow detector, so the Action's own vulnerability scan
# never counts as the user's security testing (circular evidence). In the
# Action's own repository (GITHUB_REPOSITORY seetrex-ai/compliance-action,
# any case) a step `uses: ./` is the Action too. A comment that names the
# Action excludes nothing.
set +x
set -euo pipefail
umask 077

if [ $# -ne 2 ] || [ ! -d "$1" ] || [ ! -f "$2/facts.jq" ]; then
  printf 'detect.sh: usage: detect.sh <tree> <filters> (a tree directory and bin/filters with facts.jq)\n' >&2
  exit 2
fi
TREE="$1"
FILTERS="$2"

readonly SECURITY_FILES='SECURITY.md .github/SECURITY.md docs/SECURITY.md'
readonly THREAT_MODEL_FILES='THREAT_MODEL.md .github/THREAT_MODEL.md docs/THREAT_MODEL.md docs/threat-model.md'
readonly CODEOWNERS_FILES='CODEOWNERS .github/CODEOWNERS docs/CODEOWNERS'
readonly DEPENDABOT_FILES='.github/dependabot.yml .github/dependabot.yaml'
readonly RENOVATE_FILES='renovate.json renovate.json5 .renovaterc .renovaterc.json .github/renovate.json .github/renovate.json5'
readonly SECURITY_TXT='.well-known/security.txt'

# Extended regular expressions (grep -E, case-insensitive), matched against
# the value of a step (steps_of): a `uses:` value from its first character
# (an optional quote), a command at the start of a command of a run line.
readonly RE_VALUE='^["'"'"']?'
readonly RE_CMD='(^|&&|;|\|)[[:space:]]*'
readonly RE_SEETREX_STEP="${RE_VALUE}seetrex-ai/compliance-action([@/[:space:]\"']|\$)"
readonly RE_SELF_STEP="${RE_VALUE}\./?[\"']?([[:space:]]|\$)"
readonly RE_DEP_REVIEW="${RE_VALUE}actions/dependency-review-action[@/]"
readonly RE_ANALYZER_USES="${RE_VALUE}(github/codeql-action/analyze|aquasecurity/trivy-action|anchore/scan-action|returntocorp/semgrep-action|semgrep/semgrep-action|google/osv-scanner-action|google/osv-scanner/actions/scanner|rustsec/audit-check|actions-rust-lang/audit)[@/]"
readonly RE_ANALYZER_CMD="${RE_CMD}(cargo[[:space:]]+audit|npm[[:space:]]+audit|semgrep|trivy|grype|osv-scanner)([[:space:]]|\$)"
readonly RE_PROVENANCE_USES="${RE_VALUE}(actions/attest-build-provenance|slsa-framework/slsa-github-generator)[@/]"
readonly RE_PROVENANCE_CMD="${RE_CMD}cosign[[:space:]]+(sign|sign-blob|attest|attest-blob)([[:space:]]|\$)"
readonly RE_PACKAGE_ECOSYSTEM='^[[:space:]]*(-[[:space:]]*)?package-ecosystem:'
readonly RE_REPORT_HEADING='^#{1,6}[[:space:]].*(report|disclos)'
readonly RE_SUPPORTED_HEADING='^#{1,6}[[:space:]].*supported[[:space:]]+versions'
# An address, plus the character after it when it is `:` or `/` (an SSH
# remote or a user in a URL, never an address).
readonly RE_ADDRESS='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}[:/]?'
readonly RE_SECURITY_TXT_CONTACT='^Contact:[[:space:]]*[^[:space:]]'

# The Action's own repository: there, `uses: ./` is the Action.
SELF_REPO=false
repo_lc="$(printf '%s' "${GITHUB_REPOSITORY:-}" | tr '[:upper:]' '[:lower:]')"
if [ "$repo_lc" = seetrex-ai/compliance-action ]; then
  SELF_REPO=true
fi

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

# first_address <file>: number of the first line with an e-mail address
# that is not an SSH remote or the user of a URL; empty when none.
first_address() {
  local hit nr m
  while IFS= read -r hit || [ -n "$hit" ]; do
    hit="${hit%$'\r'}"
    nr="${hit%%:*}"
    m="${hit#*:}"
    case "$m" in
      *: | */) continue ;;
    esac
    if [[ "$nr" =~ ^[0-9]+$ ]]; then
      printf '%s\n' "$nr"
      return 0
    fi
  done < <(grep -a -n -o -E -e "$RE_ADDRESS" -- "$1" 2> /dev/null || true)
}

# own_advisories_form <value>: true when a security.txt Contact: value is the
# .../security/advisories/new form of the pushing repository (any case, http
# or https, with or without www. or a trailing /). Without GITHUB_REPOSITORY,
# the form of any repository (it may be this one).
own_advisories_form() {
  local v="${1,,}"
  v="${v#https://}"
  v="${v#http://}"
  v="${v#www.}"
  v="${v%/}"
  if [ -n "$repo_lc" ]; then
    [ "$v" = "github.com/$repo_lc/security/advisories/new" ]
  else
    [[ "$v" =~ ^github\.com/[^/]+/[^/]+/security/advisories/new$ ]]
  fi
}

# first_contact <security.txt>: number of the first `Contact:` line whose
# value is not the advisories form of the pushing repository; empty when
# none. The line itself is never kept.
first_contact() {
  local hit nr v
  while IFS= read -r hit || [ -n "$hit" ]; do
    hit="${hit%$'\r'}"
    nr="${hit%%:*}"
    v="${hit#*:}"
    v="${v#*:}"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    if own_advisories_form "$v"; then
      continue
    fi
    if [[ "$nr" =~ ^[0-9]+$ ]]; then
      printf '%s\n' "$nr"
      return 0
    fi
  done < <(grep -a -n -i -E -e "$RE_SECURITY_TXT_CONTACT" -- "$1" 2> /dev/null || true)
}

# emit_line1 <id> <path>: cites line 1 of a non-empty file.
emit_line1() {
  if [ "$(line_count "$TREE/$2")" -ge 1 ]; then
    emit "$1" "$2" 1 1
  fi
}

# steps_of <workflow>: the step lines of a workflow, one per line, written
# under WORK (never printed): <line number> TAB <kind> TAB <value>, kind
# `uses` (value: what follows `uses:`), `run` (an inline command, or one line
# of a block scalar `run: |` / `run: >` / `run:` followed by a more indented
# block) or `cron` (no value). Comment lines never come out. POSIX awk only
# (mawk has no {n} intervals).
steps_of() {
  awk '
    { sub(/\r$/, "") }
    inblock {
      if ($0 ~ /^[ \t]*$/) next
      if (match($0, /[^ ]/) - 1 > bindent) {
        if ($0 !~ /^[ \t]*#/) print NR "\trun\t" $0
        next
      }
      inblock = 0
    }
    /^[ \t]*#/ { next }
    match($0, /^[ \t]*(-[ \t]+)?uses:/) {
      v = substr($0, RLENGTH + 1)
      sub(/^[ \t]+/, "", v)
      print NR "\tuses\t" v
      next
    }
    match($0, /^[ \t]*(-[ \t]+)?run:/) {
      v = substr($0, RLENGTH + 1)
      sub(/^[ \t]+/, "", v)
      if (v == "" || v ~ /^[|>][-+0-9]*[ \t]*(#.*)?$/) {
        inblock = 1
        bindent = RLENGTH - 4
      } else {
        print NR "\trun\t" v
      }
      next
    }
    /^[ \t]*(-[ \t]+)?cron:/ { print NR "\tcron\t" }
  ' "$1"
}

# first_step <steps.tsv> <kind> <re>: number of the first step line of that
# kind whose value matches the ERE <re> (case-insensitive); empty when none.
first_step() {
  local nr kind value
  while IFS=$'\t' read -r nr kind value || [ -n "$nr" ]; do
    [ "$kind" = "$2" ] || continue
    if [ "$2" = cron ] || printf '%s\n' "$value" | grep -q -i -E -e "$3"; then
      printf '%s\n' "$nr"
      return 0
    fi
  done < "$1"
}

# ------------------------------------------------------------- workflows
shopt -s nullglob
for wf in "$TREE"/.github/workflows/*.yml "$TREE"/.github/workflows/*.yaml; do
  [ -f "$wf" ] && [ ! -L "$wf" ] || continue
  rel="${wf#"$TREE/"}"
  steps_of "$wf" > "$WORK/steps.tsv"
  # The Action's own workflow is never evidence.
  if [ -n "$(first_step "$WORK/steps.tsv" uses "$RE_SEETREX_STEP")" ]; then
    continue
  fi
  if [ "$SELF_REPO" = true ] && [ -n "$(first_step "$WORK/steps.tsv" uses "$RE_SELF_STEP")" ]; then
    continue
  fi
  n="$(first_step "$WORK/steps.tsv" uses "$RE_DEP_REVIEW")"
  if [ -n "$n" ]; then
    emit dependency_review_step "$rel" "$n" "$n"
  fi
  n="$(first_step "$WORK/steps.tsv" uses "$RE_ANALYZER_USES")"
  if [ -z "$n" ]; then
    n="$(first_step "$WORK/steps.tsv" run "$RE_ANALYZER_CMD")"
  fi
  if [ -n "$n" ]; then
    emit security_analyzer_step "$rel" "$n" "$n"
    n="$(first_step "$WORK/steps.tsv" cron '')"
    if [ -n "$n" ]; then
      emit scheduled_security_analysis "$rel" "$n" "$n"
    fi
  fi
  n="$(first_step "$WORK/steps.tsv" uses "$RE_PROVENANCE_USES")"
  if [ -z "$n" ]; then
    n="$(first_step "$WORK/steps.tsv" run "$RE_PROVENANCE_CMD")"
  fi
  if [ -n "$n" ]; then
    emit release_provenance_step "$rel" "$n" "$n"
  fi
done
shopt -u nullglob
rm -f -- "$WORK/steps.tsv"

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
  n="$(first_address "$TREE/$f")"
  if [ -n "$n" ]; then
    emit security_contact "$f" "$n" "$n"
  fi
  emit_first supported_versions_table "$f" "$RE_SUPPORTED_HEADING"
done
if tree_file "$SECURITY_TXT"; then
  n="$(first_contact "$TREE/$SECURITY_TXT")"
  if [ -n "$n" ]; then
    emit security_contact "$SECURITY_TXT" "$n" "$n"
  fi
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
