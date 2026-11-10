#!/usr/bin/env bash
# Seetrex Compliance Action -- bin/propose.sh: the opt-in proposal step (plan
# R4 section 2, amendment #334), started by bin/run.sh when `propose` is true.
#
#   bash "$GITHUB_ACTION_PATH/bin/propose.sh" <work> <filters> <out_dir> <dry-run> <with-model>
#
# <work> is run.sh's WORK directory: <work>/tree is the tree of GITHUB_SHA
# (blob by blob, never the worktree), <work>/resp the 200 answer of the push
# (live run only) and <work>/trivy.json the reduced vulnerability report when
# it was sent. <out_dir> is the artifact directory of the run; <dry-run> and
# <with-model> are `true` or `false`, already validated by run.sh.
#
# <work>/body.json is the body of the push as it was sent (or, in a dry run,
# as it would be): its `trivy` string is the reduced vulnerability report and
# its `sbom` string the SBOM of the same pinned Trivy over the same tree.
#
# Reader contract 1 is read at run time from bin/contract/reader-contract-1.json
# (derived from the contract's schemas by tests/fixtures/contract/derive.jq;
# tests/test_contract.sh fails if it drifts): the closed list of documents and,
# per category, the leaves of the payload, which fields each layer may cite
# and the fixed value of each pending field.
#
# What it does, in order:
#   1. bin/detect.sh over <work>/tree: facts {id, path, lines, hash}, no text.
#   2. With <with-model> true: the documents of the closed list that exist in
#      the tree, whole, as text; each one is listed in the job log (path,
#      bytes, sha256) BEFORE anything is requested or sent, and what is listed
#      is exactly what is sent. A file that is empty, over 64 KiB, not UTF-8
#      text (or with a NUL byte), or matching a credential pattern
#      (bin/doccheck.pl, the patterns of the reader's own filter) is left out
#      and said so; at most 12 files and 256 KiB in all.
#   3. The scan of the push, when its report was sent: {finding_count,
#      scanned_packages, report_sha256}. finding_count counts the entries of
#      the reduced report, report_sha256 hashes exactly the `trivy` string the
#      push sent. scanned_packages counts the `library` components of the SBOM
#      the same push sent: the reduced report keeps only the findings (never
#      the package list, bin/filters/trivy.jq), and the SBOM is the package
#      list of the same pinned Trivy over the same tree. Without a report in
#      the push (left out for size), no scan is sent.
#   4. Dry run: lists the facts, the scan and the documents that would be sent
#      and stops. No token, no request.
#   5. Live: the categories whose obligations the push left not_documented
#      (from <work>/resp), POST /v1/action/propose {version, start} with a
#      fresh OIDC token; a 202 {ticket} is polled with a fresh token each
#      time, with backoff, until 200 {status: done}, or until 40 polls or 10
#      minutes (waits plus elapsed time) run out.
#   6. Every citation is checked here: its field must be citable in its
#      category by its layer (contract), a layer-M citation must name a
#      document this run sent, a layer-D citation must be exactly a fact this
#      run sent ({path, line_start, line_end} and its hash) of a detector
#      whose targets (detector_targets of the contract file, from
#      DetectorId::targets()) name that field of that category, the scan citation
#      must carry exactly the three values sent; a line citation is then
#      rehydrated from the local file and its quote_sha256 compared. Anything
#      else is dropped. Two citations for one field reject the category whole
#      (a warning).
#   7. The proposal is rebuilt here from the contract, never copied from the
#      answer: every leaf of the category's payload, true only when a kept
#      citation names it, every pending leaf at the fixed value of the
#      contract (the value that exempts nothing), every other leaf false. A
#      category left with no cited true is "nothing found" (an unfilled
#      template would decide VIOLATED).
#   8. Artifact <out_dir>/seetrex-proposals/: <category>.json for `ready`,
#      <category>.json.pending for `needs_person` (the Action only reads
#      *.json, so it is never ingested by mistake), <category>.review.md
#      written from the rebuilt payload: each true as `path:lines` plus the
#      quote rehydrated here, each false as "not found", each pending field as
#      "decide yourself". security_updates_policy is never proposed: only its
#      review.md, whatever the answer says. Job summary per obligation
#      (filters/summary_proposals.jq): only paths and lines.
#
# Exit 0: proposals written, nothing to propose, or a dry run. Exit 1: the
# reader could not be used; the warning is already printed, and run.sh turns
# it into a failed job only with `strict`. The record of the push is never
# affected: it was handled before this script starts.
set +x
set -euo pipefail
umask 077

readonly PROPOSE_URL='https://api.seetrex.com/v1/action/propose'
readonly AUDIENCE_QUERY='audience=https%3A%2F%2Fapi.seetrex.com'
readonly DOC_CAP=65536
readonly DOCS_TOTAL_CAP=262144
readonly MAX_DOCS=12
readonly MAX_POLLS=40
readonly MAX_WAIT=600
readonly MAX_SCANNED_PACKAGES=1000000
# Ruleset -> attestable category (OSS_CATEGORY_RULESETS of the server; the
# vulnerability-handling ruleset has no attestable category).
readonly CATEGORY_MAP='{
  "cra-art13-third-party-components": "third_party_components_report",
  "cra-art13-security-updates": "security_updates_policy",
  "cra-annex1-access-data-protection": "data_protection_report",
  "cra-annex1-availability-resilience": "availability_resilience_report",
  "cra-annex1-monitoring-lifecycle": "monitoring_lifecycle_report",
  "cra-annex1-secure-config-updates": "secure_config_report",
  "cra-annex1-secure-design": "secure_design_report",
  "cra-annex1p2-cvd-disclosure": "cvd_disclosure_report",
  "cra-annex1p2-testing-distribution": "security_testing_report",
  "cra-annex2-user-information": "user_information_report"
}'
readonly RE_PATH='^\.?[A-Za-z0-9_-][A-Za-z0-9._-]*(/\.?[A-Za-z0-9_-][A-Za-z0-9._-]*)*$'

# shellcheck disable=SC2016  # literal backticks
L_NO_OIDC='The workflow lacks `permissions: id-token: write`: no proposal was requested.'

if [ $# -ne 5 ]; then
  printf 'propose.sh: five arguments expected: <work> <filters> <out_dir> <dry-run> <with-model>\n' >&2
  exit 1
fi
WORK="$1"
FILTERS="$2"
OUT_DIR="$3"
DRY_RUN="$4"
WITH_MODEL="$5"
BIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for v in "$DRY_RUN" "$WITH_MODEL"; do
  case "$v" in
    true|false) ;;
    *) printf 'propose.sh: dry-run and with-model must be true or false\n' >&2; exit 1 ;;
  esac
done
[ -d "$WORK/tree" ] || { printf 'propose.sh: %s/tree is not a directory\n' "$WORK" >&2; exit 1; }
[ -f "$FILTERS/summary_proposals.jq" ] || { printf 'propose.sh: filters/summary_proposals.jq is missing\n' >&2; exit 1; }
[ -f "$BIN_DIR/detect.sh" ] || { printf 'propose.sh: detect.sh is missing\n' >&2; exit 1; }
[ -f "$BIN_DIR/doccheck.pl" ] || { printf 'propose.sh: doccheck.pl is missing\n' >&2; exit 1; }
CONTRACT="$BIN_DIR/contract/reader-contract-1.json"
jq -e '.contract == 1 and (.model_documents | type) == "array" and (.categories | type) == "object"
  and (.detector_targets | type) == "object"' \
  "$CONTRACT" > /dev/null 2>&1 \
  || { printf 'propose.sh: bin/contract/reader-contract-1.json is missing or unreadable\n' >&2; exit 1; }
TREE="$WORK/tree"
P="$WORK/propose"
rm -rf -- "$P"
mkdir "$P"

# Prints a line to the log and appends it to the job summary.
say() {
  printf '%s\n' "$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

# A reader failure: warning in the log and the summary; the caller exits 1.
warn() {
  printf '::warning::%s\n' "$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

fail() {
  warn "$1"
  exit 1
}

sha256_of() {
  local line
  line="$(sha256sum -- "$1")"
  printf '%s\n' "${line%% *}"
}

bytes_of() {
  local n
  n="$(wc -c < "$1")"
  printf '%s\n' "${n//[[:space:]]/}"
}

line_count() {
  local n
  n="$(awk 'END { print NR }' "$1")"
  printf '%s\n' "${n//[[:space:]]/}"
}

# SHA-256 of lines <start>..<end> of <file>: each line without its \n or
# \r\n, joined with \n, no trailing \n (the contract's rule, as detect.sh).
range_sha256() {
  local line
  line="$(awk -v s="$2" -v e="$3" \
    'NR >= s && NR <= e { sub(/\r$/, ""); if (NR > s) printf "\n"; printf "%s", $0 }' \
    "$1" | sha256sum)"
  printf '%s\n' "${line%% *}"
}

# A regular file of the tree, never through a link.
tree_file() {
  [ -f "$TREE/$1" ] && [ ! -L "$TREE/$1" ]
}

# Molde of run.sh's dry_file_line: how a file is listed in the log.
file_line() {
  printf -- '- %s: %s bytes, sha256 %s\n' "$1" "$(bytes_of "$2")" "$(sha256_of "$2")"
}

# ------------------------------------------------------------- 1. facts
bash "$BIN_DIR/detect.sh" "$TREE" "$FILTERS" > "$P/facts.json" \
  || fail "The detectors could not read the commit: no proposal was requested."
jq -e '.version == 1 and (.facts | type) == "array"' "$P/facts.json" > /dev/null 2>&1 \
  || fail "The detectors produced something this version cannot read: no proposal was requested."
n_facts="$(jq '.facts | length' "$P/facts.json")"
n_facts="${n_facts%$'\r'}"

# -------------------------------------------------------- 2. documents
# Listed BEFORE any request: one line per file, as it is sent (path, bytes,
# sha256), or why it is left out. Never a line of the file. The list is the
# contract's (model_document_path), in its order.
printf '[]' > "$P/documents.json"
n_docs=0
if [ "$WITH_MODEL" = true ]; then
  total=0
  jq -r '.model_documents[]' "$CONTRACT" | tr -d '\r' > "$P/model_documents.txt"
  printf 'Documents for the reader (fixed list; text as committed at this commit):\n'
  while IFS= read -r d || [ -n "$d" ]; do
    tree_file "$d" || continue
    f="$TREE/$d"
    b="$(bytes_of "$f")"
    if [ "$b" -eq 0 ]; then
      printf -- '- %s: left out (empty)\n' "$d"
      continue
    fi
    if [ "$b" -gt "$DOC_CAP" ]; then
      printf -- '- %s: left out (%s bytes, over the 64 KiB cap)\n' "$d" "$b"
      continue
    fi
    # Never with an inherited PERL5OPT (-M), PERL5LIB / PERLLIB (a strict.pm
    # of the workflow's own) or PERL5DB: the verdict is doccheck.pl's alone.
    verdict="$(env -u PERL5OPT -u PERL5LIB -u PERLLIB -u PERL5DB perl "$BIN_DIR/doccheck.pl" "$f" 2> /dev/null)" \
      || fail "A document could not be checked: no proposal was requested."
    verdict="${verdict%$'\r'}"
    case "$verdict" in
      ok) ;;
      not_utf8)
        printf -- '- %s: left out (not UTF-8 text)\n' "$d"
        continue
        ;;
      'credential '[a-z_]*)
        printf -- '- %s: left out (a line looks like a credential: %s)\n' "$d" "${verdict#credential }"
        continue
        ;;
      *) fail "A document could not be checked: no proposal was requested." ;;
    esac
    if [ "$n_docs" -ge "$MAX_DOCS" ]; then
      printf -- '- %s: left out (more than %s documents)\n' "$d" "$MAX_DOCS"
      continue
    fi
    if [ $((total + b)) -gt "$DOCS_TOTAL_CAP" ]; then
      printf -- '- %s: left out (%s bytes would exceed the 256 KiB total)\n' "$d" "$b"
      continue
    fi
    jq -c --rawfile text "$f" --arg path "$d" --argjson bytes "$b" --arg sha "$(sha256_of "$f")" \
      '. + [{path: $path, bytes: $bytes, sha256: $sha, text: $text}]' \
      "$P/documents.json" > "$P/documents.next" \
      || fail "A document could not be read as text: no proposal was requested."
    # Listed = sent: the text that would travel is the file, byte for byte.
    sent_b64="$(jq -r '.[-1].text | @base64' "$P/documents.next" | tr -d '\r\n')"
    file_b64="$(base64 < "$f" | tr -d '\r\n')"
    if [ "$sent_b64" != "$file_b64" ]; then
      rm -f -- "$P/documents.next"
      printf -- '- %s: left out (not UTF-8 text)\n' "$d"
      continue
    fi
    mv -f -- "$P/documents.next" "$P/documents.json"
    file_line "$d" "$f"
    n_docs=$((n_docs + 1))
    total=$((total + b))
  done < "$P/model_documents.txt"
  if [ "$n_docs" -eq 0 ]; then
    printf -- '- (none of the listed documents is in this commit: facts only)\n'
  fi
fi

# ------------------------------------------------------------ 3. scan
# From the push body: the `trivy` string exactly as sent (decoded through
# base64 so that no newline is added or translated on the way), its entry
# count, and the library components of the SBOM of the same push.
printf 'null' > "$P/scan.json"
if [ -f "$WORK/body.json" ] && jq -e '(.trivy | type) == "string" and (.sbom | type) == "string"' \
  "$WORK/body.json" > /dev/null 2>&1; then
  jq -r '.trivy | @base64' "$WORK/body.json" | tr -d '\r\n' | base64 -d > "$P/trivy.sent" 2> /dev/null \
    || : > "$P/trivy.sent"
  findings="$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$P/trivy.sent" 2> /dev/null || true)"
  findings="${findings%$'\r'}"
  packages="$(jq '
    def entries: if (.components | type) == "array" then .components[] | objects | ., entries else empty end;
    .sbom | fromjson | [entries | select(.type == "library")] | length' "$WORK/body.json" 2> /dev/null || true)"
  packages="${packages%$'\r'}"
  if [[ "$findings" =~ ^[0-9]{1,7}$ ]] && [ "$findings" -le "$MAX_SCANNED_PACKAGES" ] \
    && [[ "$packages" =~ ^[0-9]{1,7}$ ]] && [ "$packages" -le "$MAX_SCANNED_PACKAGES" ]; then
    jq -c -n --argjson f "$findings" --argjson p "$packages" --arg sha "$(sha256_of "$P/trivy.sent")" \
      '{finding_count: $f, scanned_packages: $p, report_sha256: $sha}' > "$P/scan.json"
  fi
  rm -f -- "$P/trivy.sent"
fi
scan_line="$(jq -r 'if . == null then "none (the push sent no vulnerability report)"
  else "\(.finding_count) findings over \(.scanned_packages) packages, report sha256 \(.report_sha256)" end' "$P/scan.json")"
scan_line="${scan_line%$'\r'}"

# --------------------------------------------------------- 4. dry run
if [ "$DRY_RUN" = true ]; then
  printf 'Facts the detectors found (id, path:lines, sha256 of those lines):\n'
  jq -r '.facts[] | "- \(.id): \(.path):\(.line_start)-\(.line_end), sha256 \(.line_sha256)"' "$P/facts.json"
  if [ "$n_facts" -eq 0 ]; then
    printf -- '- (none)\n'
  fi
  printf 'Scan of the push: %s\n' "$scan_line"
  say "Dry run: a proposal request with $n_facts facts and $n_docs documents would be sent to Seetrex after the push. Nothing was sent."
  exit 0
fi

# ------------------------------------------------------ 5. categories
[ -f "$WORK/resp" ] || fail "The answer of the push is not available: no proposal was requested."
jq -c --argjson map "$CATEGORY_MAP" '
  [.results.obligations // [] | if type == "array" then .[] else empty end
   | select(type == "object" and .status == "not_documented")
   | .ruleset_id | strings | select($map[.] != null)
   | {ruleset_id: ., category: $map[.]}]
  | unique_by(.category)' "$WORK/resp" > "$P/obligations.json" 2> /dev/null \
  || fail "The answer of the push could not be read: no proposal was requested."
n_cat="$(jq 'length' "$P/obligations.json")"
n_cat="${n_cat%$'\r'}"
if [ "$n_cat" -eq 0 ]; then
  say "Every obligation that reads an attestation has a document in force: nothing to propose."
  exit 0
fi

jq -c -n --slurpfile facts "$P/facts.json" --slurpfile obl "$P/obligations.json" \
  --slurpfile docs "$P/documents.json" --slurpfile scan "$P/scan.json" '
  {version: 1,
   start: ({categories: ([$obl[0][].category] | unique), facts: $facts[0].facts}
           + (if ($docs[0] | length) > 0 then {documents: $docs[0]} else {} end)
           + (if $scan[0] != null then {scan: $scan[0]} else {} end))}' \
  > "$P/body.json"

# ------------------------------------------------------- 5. OIDC token
# Molde of run.sh's fetch_token: the JWT never touches argv; masked, written
# into a 600 header file, variable dropped. Called anew before every request.
fetch_token() {
  if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
    fail "$L_NO_OIDC"
  fi
  case "$ACTIONS_ID_TOKEN_REQUEST_URL" in
    https://*) ;;
    *) fail "The runner's OIDC token URL is not https: no proposal was requested." ;;
  esac
  [[ "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" =~ ^[^[:space:]]+$ ]] \
    || fail "The runner's OIDC request token is malformed: no proposal was requested."
  printf '::add-mask::%s\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN"
  local sep='?' code rc=0 jwt
  case "$ACTIONS_ID_TOKEN_REQUEST_URL" in
    *'?'*) sep='&' ;;
  esac
  printf 'Authorization: Bearer %s\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" > "$P/token-request.hdr"
  chmod 600 "$P/token-request.hdr"
  code="$(curl -q -sS --proto '=https' --max-time 30 -H @"$P/token-request.hdr" \
    -o "$P/token.json" -w '%{http_code}' \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}${sep}${AUDIENCE_QUERY}")" || rc=$?
  rm -f -- "$P/token-request.hdr"
  if [ "$rc" -ne 0 ] || [ "$code" != 200 ] || [ ! -f "$P/token.json" ]; then
    rm -f -- "$P/token.json"
    fail "The OIDC token could not be obtained from the runner: no proposal was requested."
  fi
  jwt="$(jq -r '.value | strings' "$P/token.json" 2> /dev/null || true)"
  rm -f -- "$P/token.json"
  jwt="${jwt%$'\r'}"
  if ! [[ "$jwt" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$ ]]; then
    fail "The OIDC token could not be obtained from the runner: no proposal was requested."
  fi
  printf '::add-mask::%s\n' "$jwt"
  printf 'Authorization: Bearer %s\n' "$jwt" > "$P/auth.hdr"
  chmod 600 "$P/auth.hdr"
  unset jwt
}

# ---------------------------------------------------- 6. POST + polling
HTTP=""
post_body() {
  local code rc=0
  rm -f -- "$P/resp"
  code="$(curl -q -sS --proto '=https' --max-time 60 -H @"$P/auth.hdr" \
    -H 'Content-Type: application/json' --data-binary @"$1" \
    -o "$P/resp" -w '%{http_code}' "$PROPOSE_URL")" || rc=$?
  rm -f -- "$P/auth.hdr"
  if [ "$rc" -ne 0 ] || ! [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then
    HTTP=000
  else
    HTTP="$code"
  fi
  [ -f "$P/resp" ] || : > "$P/resp"
}

resp_status() {
  local s
  s="$(jq -r 'if type == "object" then (.status | strings) else empty end' "$P/resp" 2> /dev/null || true)"
  s="${s%$'\r'}"
  case "$s" in
    pending|done) printf '%s\n' "$s" ;;
  esac
}

# Everything but 200 done / 202 pending: one warning, exit 1.
propose_failure() {
  case "$HTTP" in
    000) fail "Seetrex could not be reached for the proposal: no proposal; the record of this push is not affected." ;;
    200|202) fail "Seetrex answered the proposal request with something this version cannot read: no proposal; the record of this push is not affected." ;;
    401) fail "Seetrex did not accept the proposal request (401): no proposal; the record of this push is not affected." ;;
    429) fail "Seetrex is limiting the rate of proposal requests (429): no proposal; the record of this push is not affected." ;;
    5[0-9][0-9]) fail "Seetrex's reader is unavailable ($HTTP): no proposal; the record of this push is not affected." ;;
    *) fail "Seetrex refused the proposal request ($HTTP): no proposal; the record of this push is not affected." ;;
  esac
}

say "Requesting proposals from Seetrex for $n_cat categories, with $n_facts facts and $n_docs documents."
fetch_token
post_body "$P/body.json"
status="$(resp_status)"
polls=0
delay=5
waited=0
t0="$SECONDS"
while [ "$HTTP" = 202 ] && [ "$status" = pending ]; do
  ticket="$(jq -r '.ticket | strings' "$P/resp" 2> /dev/null || true)"
  ticket="${ticket%$'\r'}"
  [[ "$ticket" =~ ^[A-Za-z0-9_-]{32,64}$ ]] || fail "Seetrex's ticket for the proposal is malformed: no proposal; the record of this push is not affected."
  polls=$((polls + 1))
  # Two caps: the number of polls, and 10 minutes of waits or of wall clock
  # (a slow answer counts too), whichever comes first.
  if [ "$polls" -gt "$MAX_POLLS" ] || [ $((waited + delay)) -gt "$MAX_WAIT" ] \
    || [ $((SECONDS - t0 + delay)) -gt "$MAX_WAIT" ]; then
    fail "Seetrex's reader did not finish in time: no proposal; the record of this push is not affected."
  fi
  sleep "$delay"
  waited=$((waited + delay))
  if [ "$delay" -lt 30 ]; then
    delay=$((delay * 2))
    [ "$delay" -le 30 ] || delay=30
  fi
  printf '{"version":1,"ticket":"%s"}' "$ticket" > "$P/poll.json"
  fetch_token
  post_body "$P/poll.json"
  status="$(resp_status)"
done
if ! { [ "$HTTP" = 200 ] && [ "$status" = done ]; }; then
  propose_failure
fi
jq -e '(.proposals | type) == "object"' "$P/resp" > /dev/null 2>&1 || propose_failure

# --------------------------------------------------- 7. check citations
# Only the requested categories that have an envelope, only the citable
# fields of each layer. Each citation becomes one line:
#   <category> <index> <kind> <field> <path> <start> <end> <sha256>
# kind `line` (a layer-M citation of a document this run sent, or a layer-D
# citation that is exactly a fact this run sent by a detector that targets
# that field of that category: both rehydrated below),
# `scan` (the scan citation, with exactly the values this run sent) or `bad`.
jq -r --slurpfile obl "$P/obligations.json" --slurpfile contract "$CONTRACT" \
  --slurpfile facts "$P/facts.json" --slurpfile docs "$P/documents.json" --slurpfile scan "$P/scan.json" \
  --arg re_path "$RE_PATH" '
  def line_ok:
    ((.path | type) == "string") and (.path | test($re_path)) and (.path | length) <= 512
    and ((.line_start | type) == "number") and ((.line_end | type) == "number")
    and (.line_start | . == floor and . >= 1) and (.line_end | . == floor and . <= 1000000)
    and .line_start <= .line_end
    and ((.quote_sha256 | type) == "string") and (.quote_sha256 | test("^[0-9a-f]{64}$"));
  ([$obl[0][].category]) as $wanted
  | $contract[0].categories as $cats
  | $contract[0].detector_targets as $targets
  | [$docs[0][].path] as $sent_docs
  | $facts[0].facts as $sent_facts
  | $scan[0] as $s
  | .proposals | to_entries[]
  | select(.key | IN($wanted[]))
  | .key as $cat | $cats[$cat] as $k
  | select($k != null and $k.leaves != null)
  | ((.value | if type == "object" then .citations else null end) | if type == "array" then . else [] end)
  | to_entries[]
  | .key as $i | .value as $c
  | (if ($c | type) != "object" or $c.value != true or ($c.field | type) != "string" then "bad"
     elif ($c.field | IN($k.scan_fields[])) then
       (if $c.source == "vuln_scan" and $s != null and $s.finding_count == 0 and $s.scanned_packages >= 1
           and $c.finding_count == $s.finding_count and $c.scanned_packages == $s.scanned_packages
           and $c.report_sha256 == $s.report_sha256
        then "scan" else "bad" end)
     elif ($c.field | IN($k.detector_fields[])) then
       (if ($c | line_ok) and $c.source == null
           and ([$sent_facts[] | select(.path == $c.path and .line_start == $c.line_start
                  and .line_end == $c.line_end and .line_sha256 == $c.quote_sha256)
                 | select(any(($targets[.id] // [])[]; .category == $cat and .field == $c.field))] | length) > 0
        then "line" else "bad" end)
     elif ($c.field | IN($k.model_fields[])) then
       (if ($c | line_ok) and $c.source == null and ($c.path | IN($sent_docs[])) then "line" else "bad" end)
     else "bad" end) as $kind
  | if $kind == "line" then
      "\($cat)\t\($i)\tline\t\($c.field)\t\($c.path)\t\($c.line_start)\t\($c.line_end)\t\($c.quote_sha256)"
    elif $kind == "scan" then "\($cat)\t\($i)\tscan\t\($c.field)\t-\t0\t0\t\($c.report_sha256)"
    else "\($cat)\t\($i)\tbad\t-\t-\t0\t0\t-" end' \
  "$P/resp" > "$P/citations.tsv" 2> /dev/null \
  || fail "The proposals could not be read: no proposal; the record of this push is not affected."

# verdicts.tsv: <category> <index> ok|drop. A line citation is kept only when
# the hash of the local lines equals quote_sha256.
: > "$P/verdicts.tsv"
n_kept=0
n_dropped=0
while IFS=$'\t' read -r category idx kind field path start end sha || [ -n "$category" ]; do
  sha="${sha%$'\r'}"
  verdict=drop
  case "$kind" in
    line)
      if tree_file "$path" && [ "$end" -le "$(line_count "$TREE/$path")" ] \
        && [ "$(range_sha256 "$TREE/$path" "$start" "$end")" = "$sha" ]; then
        verdict=ok
      fi
      ;;
    scan) verdict=ok ;;
  esac
  if [ "$verdict" = ok ]; then
    n_kept=$((n_kept + 1))
  else
    n_dropped=$((n_dropped + 1))
  fi
  printf '%s\t%s\t%s\n' "$category" "$idx" "$verdict" >> "$P/verdicts.tsv"
done < "$P/citations.tsv"

# ------------------------------------------------- 8. rebuild proposals
# Never copied from the answer: the payload is the contract's leaves, a free
# leaf true only when a kept citation names it, a fixed leaf at its fixed
# value; the citations are rewritten from the checked fields only. States:
# ready / needs_person (as the contract fixes for the category),
# nothing_found, rejected (one field cited twice), unreadable.
jq -c --slurpfile obl "$P/obligations.json" --slurpfile contract "$CONTRACT" --rawfile verdicts "$P/verdicts.tsv" '
  ([$obl[0][].category]) as $wanted
  | $contract[0].categories as $cats
  | ([$verdicts | split("\n")[] | rtrimstr("\r") | select(length > 0) | split("\t")
      | select(length == 3 and .[2] == "ok") | "\(.[0])/\(.[1])"]) as $ok
  | .proposals | to_entries
  | map(select(.key | IN($wanted[])) | select($cats[.key] != null))
  | map(.key as $cat | $cats[$cat] as $k | .value as $p
    | (($p | if type == "object" then .citations else null end) | if type == "array" then . else [] end) as $all
    | ([$all | to_entries[] | select("\($cat)/\(.key)" | IN($ok[])) | .value
        | if .source == "vuln_scan"
          then {field, value: true, source, finding_count, scanned_packages, report_sha256}
          else {field, value: true, path, line_start, line_end, quote_sha256} end]) as $kept
    | if $k.leaves == null then {key: $cat, value: {state: "needs_person", pending_fields: $k.pending_fields}}
      elif ($p | type) != "object" then {key: $cat, value: {state: "unreadable"}}
      elif $p.state == "nothing_found" then {key: $cat, value: {state: "nothing_found"}}
      elif $p.state != $k.state then {key: $cat, value: {state: "unreadable"}}
      elif ([$all[] | objects | .field | strings] | group_by(.) | any(length > 1)) then
        {key: $cat, value: {state: "rejected"}}
      elif ($kept | length) == 0 then {key: $cat, value: {state: "nothing_found"}}
      else
        [$kept[].field] as $cited
        | (reduce ($k.leaves | to_entries[]) as $l ({};
            setpath($l.key | split("."); if $l.value != null then $l.value else ($l.key | IN($cited[])) end))) as $payload
        | {key: $cat, value: ({state: $k.state,
            envelope: {schema: "seetrex.attestation.v2", category: $cat, attested_via: "reader+person", payload: $payload},
            citations: $kept}
            + (if $k.state == "needs_person" then {pending_fields: $k.pending_fields} else {} end))}
      end)
  | from_entries' "$P/resp" > "$P/proposals.json" 2> /dev/null \
  || fail "The proposals could not be read: no proposal; the record of this push is not affected."

# ------------------------------------------------------- 9. artifact
ART="$OUT_DIR/seetrex-proposals"
rm -rf -- "$ART"
mkdir -p "$ART"
n_files=0

# Appends the lines <start>..<end> of <path>, indented, to <review>.
append_quote() {
  awk -v s="$2" -v e="$3" 'NR >= s && NR <= e { sub(/\r$/, ""); print "    " $0 }' "$TREE/$1" >> "$4"
}

# write_review <category>: <category>.review.md from the rebuilt proposal and
# the contract's leaves (field names come from the contract, never from the
# answer).
# shellcheck disable=SC2016  # literal backticks (Markdown) throughout
write_review() {
  local c="$1" review="$ART/$1.review.md" state kind field path start end extra sha
  state="$(jq -r --arg c "$c" '.[$c].state' "$P/proposals.json")"
  state="${state%$'\r'}"
  if [ "$c" = security_updates_policy ]; then
    {
      printf '# %s\n\n' "$c"
      printf 'Never proposed: every field of this category is yours to decide. Fill the template by hand.\n\n## Decide yourself\n\n'
      jq -r --arg c "$c" --slurpfile contract "$CONTRACT" \
        '$contract[0].categories[$c].pending_fields[] | "- `\(.)`: decide yourself"' "$P/proposals.json"
    } > "$review"
    return 0
  fi
  {
    printf '# %s\n\n' "$c"
    if [ "$state" = ready ]; then
      printf 'Proposal ready: review each citation below; to accept, copy `%s.json` to `.seetrex/attestations/` and commit it. The commit is your signature.\n\n' "$c"
    else
      printf 'Needs a person: decide the pending fields below, then rename `%s.json.pending` to `%s.json` under `.seetrex/attestations/` and commit it. Each pending field is proposed at the value that exempts nothing: decide it.\n\n' "$c" "$c"
    fi
    printf '## Proposed true, with the citation rehydrated from this commit\n\n'
  } > "$review"
  jq -r --arg c "$c" --slurpfile contract "$CONTRACT" '
    .[$c] as $p
    | $contract[0].categories[$c].leaves | to_entries[] | select(.value == null) | .key as $f
    | select(($p.envelope.payload | getpath($f | split("."))) == true)
    | $p.citations[] | select(.field == $f)
    | if .source == "vuln_scan" then "scan\t\($f)\t-\t0\t0\t\(.scanned_packages)\t\(.report_sha256)"
      else "line\t\($f)\t\(.path)\t\(.line_start)\t\(.line_end)\t-\t-" end' "$P/proposals.json" > "$P/cites.tsv"
  while IFS=$'\t' read -r kind field path start end extra sha || [ -n "$kind" ]; do
    sha="${sha%$'\r'}"
    if [ "$kind" = scan ]; then
      printf -- '- `%s` = true: the vulnerability scan of this push has 0 findings over %s packages (report sha256 %s).\n\n' \
        "$field" "$extra" "$sha" >> "$review"
    else
      printf -- '- `%s` = true: `%s:%s-%s`\n\n' "$field" "$path" "$start" "$end" >> "$review"
      append_quote "$path" "$start" "$end" "$review"
      printf '\n' >> "$review"
    fi
  done < "$P/cites.tsv"
  if [ ! -s "$P/cites.tsv" ]; then
    printf -- '- (none)\n\n' >> "$review"
  fi
  {
    printf '## Not found (left false)\n\n'
    jq -r --arg c "$c" --slurpfile contract "$CONTRACT" '
      .[$c].envelope.payload as $pl
      | [$contract[0].categories[$c].leaves | to_entries[] | select(.value == null) | .key
         | . as $f | select(($pl | getpath($f | split("."))) == false)]
      | if length == 0 then "- (none)" else .[] | "- `\(.)` = false: not found" end' "$P/proposals.json"
    printf '\n## Fixed by the contract (never proposed)\n\n'
    jq -r --arg c "$c" --slurpfile contract "$CONTRACT" '
      $contract[0].categories[$c] as $k
      | [$k.leaves | to_entries[] | select(.value != null) | select(.key | IN($k.pending_fields[]) | not)]
      | if length == 0 then "- (none)" else .[] | "- `\(.key)` = \(.value)" end' "$P/proposals.json"
    printf '\n## Decide yourself\n\n'
    jq -r --arg c "$c" --slurpfile contract "$CONTRACT" '
      $contract[0].categories[$c] as $k
      | [$k.pending_fields[] | {key: ., value: $k.leaves[.]}]
      | if length == 0 then "- (none)"
        else .[] | "- `\(.key)`: decide yourself (proposed as \(.value), the value that exempts nothing)" end' "$P/proposals.json"
  } >> "$review"
}

while IFS= read -r category || [ -n "$category" ]; do
  category="${category%$'\r'}"
  [[ "$category" =~ ^[a-z_]{1,64}$ ]] || continue
  state="$(jq -r --arg c "$category" '.[$c].state' "$P/proposals.json")"
  state="${state%$'\r'}"
  if [ "$category" = security_updates_policy ]; then
    # Never an envelope, whatever the answer says: only the review.
    write_review "$category"
    n_files=$((n_files + 1))
    continue
  fi
  case "$state" in
    ready)
      jq --arg c "$category" '.[$c].envelope' "$P/proposals.json" > "$ART/$category.json"
      ;;
    needs_person)
      jq --arg c "$category" '.[$c].envelope' "$P/proposals.json" > "$ART/$category.json.pending"
      ;;
    rejected)
      warn "Seetrex's proposal for $category cites one field twice: that category was left out."
      continue
      ;;
    *) continue ;;
  esac
  write_review "$category"
  n_files=$((n_files + 2))
done < <(jq -r 'keys[]' "$P/proposals.json")

if [ "$n_files" -gt 0 ]; then
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf 'proposals=%s\n' "$ART" >> "$GITHUB_OUTPUT"
  fi
else
  rm -rf -- "$ART"
fi

# --------------------------------------------------------- 10. summary
jq -c -n --slurpfile obl "$P/obligations.json" --slurpfile prop "$P/proposals.json" \
  '{obligations: $obl[0], proposals: $prop[0]}' > "$P/summary.in"
if jq -r -f "$FILTERS/summary_proposals.jq" "$P/summary.in" > "$P/summary.md" 2> /dev/null; then
  cat "$P/summary.md"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    cat "$P/summary.md" >> "$GITHUB_STEP_SUMMARY"
  fi
else
  warn "The proposals summary could not be rendered."
fi
say "Seetrex proposed attestations for review: $n_kept citations kept, $n_dropped dropped (not verified against this commit), $n_files files in the seetrex-proposals artifact."
exit 0
