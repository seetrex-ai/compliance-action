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
# What it does, in order:
#   1. bin/detect.sh over <work>/tree: facts {id, path, lines, hash}, no text.
#   2. With <with-model> true: the documents of the closed list below that
#      exist in the tree, whole, as text; each one is listed in the job log
#      (path, bytes, sha256) BEFORE anything is requested or sent. A file over
#      64 KiB, empty, or matching a credential pattern is left out and said
#      so; at most 12 files and 256 KiB in all.
#   3. Dry run: lists the facts and the documents that would be sent and
#      stops. No token, no request.
#   4. Live: the categories whose obligations the push left not_documented
#      (from <work>/resp), POST /v1/action/propose {version, start} with a
#      fresh OIDC token; a 202 {ticket} is polled with a fresh token each
#      time, with backoff, until 200 {status: done} or the polls run out.
#   5. Every citation of the answer is rehydrated from the local file of the
#      tree and its quote_sha256 compared; a citation that does not match is
#      dropped and its field set to false. A category left with no cited true
#      is "nothing found" (an unfilled template would decide VIOLATED).
#   6. Artifact <out_dir>/seetrex-proposals/: <category>.json for `ready`,
#      <category>.json.pending for `needs_person` (the Action only reads
#      *.json, so it is never ingested by mistake), <category>.review.md with
#      each true as `path:lines` plus the quote rehydrated here, each false as
#      "not found", each pending field as "decide yourself". Job summary per
#      obligation (filters/summary_proposals.jq): only paths and lines.
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
readonly MAX_POLLS=20
# The closed list of documents the reader may read (reader contract 1,
# propose-request.schema.json, model_document_path): exact names, no globs,
# never source code, workflows, dependabot.yml or lockfiles.
readonly MODEL_DOCUMENTS='README.md SECURITY.md .github/SECURITY.md docs/SECURITY.md CONTRIBUTING.md .github/CONTRIBUTING.md docs/CONTRIBUTING.md SUPPORT.md .github/SUPPORT.md docs/SUPPORT.md CHANGELOG.md THREAT_MODEL.md docs/THREAT_MODEL.md docs/threat-model.md docs/DEPENDENCIES.md'
# A document with one of these is left out (the reader filters again).
readonly CREDENTIAL_RE='-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|(api[_-]?key|passw(or)?d|secret|token)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"'[:space:]]{8,}'
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
readonly RE_FIELD='^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$'

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
# Listed BEFORE any request: one line per file, as it would be sent (path,
# bytes, sha256), or why it is left out. Never a line of the file.
printf '[]' > "$P/documents.json"
n_docs=0
if [ "$WITH_MODEL" = true ]; then
  total=0
  printf 'Documents for the reader (fixed list; text as committed at this commit):\n'
  for d in $MODEL_DOCUMENTS; do
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
    if grep -a -q -i -E -e "$CREDENTIAL_RE" -- "$f" 2> /dev/null; then
      printf -- '- %s: left out (a line looks like a credential)\n' "$d"
      continue
    fi
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
    mv -f -- "$P/documents.next" "$P/documents.json"
    file_line "$d" "$f"
    n_docs=$((n_docs + 1))
    total=$((total + b))
  done
  if [ "$n_docs" -eq 0 ]; then
    printf -- '- (none of the listed documents is in this commit: facts only)\n'
  fi
fi

# --------------------------------------------------------- 3. dry run
if [ "$DRY_RUN" = true ]; then
  printf 'Facts the detectors found (id, path:lines, sha256 of those lines):\n'
  jq -r '.facts[] | "- \(.id): \(.path):\(.line_start)-\(.line_end), sha256 \(.line_sha256)"' "$P/facts.json"
  if [ "$n_facts" -eq 0 ]; then
    printf -- '- (none)\n'
  fi
  say "Dry run: a proposal request with $n_facts facts and $n_docs documents would be sent to Seetrex after the push. Nothing was sent."
  exit 0
fi

# ------------------------------------------------------ 4. categories
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
  --slurpfile docs "$P/documents.json" '
  {version: 1,
   start: ({categories: ([$obl[0][].category] | unique), facts: $facts[0].facts}
           + (if ($docs[0] | length) > 0 then {documents: $docs[0]} else {} end))}' \
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
while [ "$HTTP" = 202 ] && [ "$status" = pending ]; do
  ticket="$(jq -r '.ticket | strings' "$P/resp" 2> /dev/null || true)"
  ticket="${ticket%$'\r'}"
  [[ "$ticket" =~ ^[A-Za-z0-9_-]{32,64}$ ]] || fail "Seetrex's ticket for the proposal is malformed: no proposal; the record of this push is not affected."
  polls=$((polls + 1))
  if [ "$polls" -gt "$MAX_POLLS" ]; then
    fail "Seetrex's reader did not finish in time: no proposal; the record of this push is not affected."
  fi
  sleep "$delay"
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

# ------------------------------------------------- 7. rehydrate citations
# Only the requested categories, only readable shapes. Each citation becomes
# one line: <category> <index> <kind> <field> <path> <start> <end> <sha256>
# (kind: line, scan, or bad when a field does not match its pattern).
jq -r --slurpfile obl "$P/obligations.json" --arg re_path "$RE_PATH" --arg re_field "$RE_FIELD" '
  ([$obl[0][].category]) as $wanted
  | .proposals | to_entries[]
  | select(.key | IN($wanted[]))
  | .key as $cat
  | (.value.citations // [] | if type == "array" then . else [] end)
  | to_entries[]
  | .key as $i | .value as $c
  | if ($c | type) != "object" or $c.value != true
       or (($c.field | type) != "string") or ($c.field | test($re_field) | not) or ($c.field | length) > 256 then
      "\($cat)\t\($i)\tbad\t-\t-\t0\t0\t-"
    elif $c.source == "vuln_scan" then
      if $c.field == "market_availability.no_known_exploitable_vulnerabilities" and $c.finding_count == 0
         and (($c.report_sha256 | type) == "string") and ($c.report_sha256 | test("^[0-9a-f]{64}$")) then
        "\($cat)\t\($i)\tscan\t\($c.field)\t-\t0\t0\t\($c.report_sha256)"
      else "\($cat)\t\($i)\tbad\t-\t-\t0\t0\t-" end
    elif (($c.path | type) == "string") and ($c.path | test($re_path)) and ($c.path | length) <= 512
         and (($c.line_start | type) == "number") and (($c.line_end | type) == "number")
         and ($c.line_start | . == floor and . >= 1) and ($c.line_end | . == floor and . <= 1000000)
         and $c.line_start <= $c.line_end
         and (($c.quote_sha256 | type) == "string") and ($c.quote_sha256 | test("^[0-9a-f]{64}$")) then
      "\($cat)\t\($i)\tline\t\($c.field)\t\($c.path)\t\($c.line_start)\t\($c.line_end)\t\($c.quote_sha256)"
    else "\($cat)\t\($i)\tbad\t-\t-\t0\t0\t-" end' \
  "$P/resp" > "$P/citations.tsv" 2> /dev/null \
  || fail "The proposals could not be read: no proposal; the record of this push is not affected."

# The sha256 of the reduced report as sent (the body string, no newline).
scan_sha=""
if [ -f "$WORK/trivy.json" ]; then
  jq -j '.' "$WORK/trivy.json" > "$P/trivy.sent" 2> /dev/null || : > "$P/trivy.sent"
  if [ "$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$WORK/trivy.json" 2> /dev/null || printf 1)" = 0 ]; then
    scan_sha="$(sha256_of "$P/trivy.sent")"
  fi
fi

# verdicts.tsv: <category> <index> ok|drop. A citation is kept only when the
# hash of the local lines equals quote_sha256 (or, for the scan, the hash of
# the report this run sent with zero findings).
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
    scan)
      if [ -n "$scan_sha" ] && [ "$sha" = "$scan_sha" ]; then
        verdict=ok
      fi
      ;;
  esac
  if [ "$verdict" = ok ]; then
    n_kept=$((n_kept + 1))
  else
    n_dropped=$((n_dropped + 1))
  fi
  printf '%s\t%s\t%s\n' "$category" "$idx" "$verdict" >> "$P/verdicts.tsv"
done < "$P/citations.tsv"

# The proposals with the verdicts applied: dropped citations removed and
# their field set to false; a category left with no cited true becomes
# nothing_found; shapes this version cannot read are dropped.
jq -c --slurpfile obl "$P/obligations.json" --rawfile verdicts "$P/verdicts.tsv" --arg re_field "$RE_FIELD" '
  ([$obl[0][].category]) as $wanted
  | ([$verdicts | split("\n")[] | select(length > 0) | split("\t") | select(length == 3 and .[2] == "ok")
     | "\(.[0])/\(.[1])"]) as $ok
  | def envelope_ok($cat):
      type == "object" and .schema == "seetrex.attestation.v2" and .category == $cat
      and .attested_via == "reader+person" and (.payload | type) == "object" and (.payload | length) > 0
      and ([.payload | .. | select(type != "object" and type != "boolean")] | length == 0);
    def pending_ok: (if type == "array" then . else [] end)
      | [.[] | strings | select(test($re_field) and length <= 256)] | unique;
  .proposals | to_entries
  | map(select(.key | IN($wanted[])))
  | map(.key as $cat | .value as $p
    | ($p.citations // [] | if type == "array" then . else [] end
       | to_entries | map(select("\($cat)/\(.key)" | IN($ok[]))) | map(.value)) as $kept
    | ($p.citations // [] | if type == "array" then . else [] end
       | to_entries | map(select("\($cat)/\(.key)" | IN($ok[]) | not)) | map(.value.field | strings)) as $dropped
    | if $p.state == "nothing_found" then {key: $cat, value: {state: "nothing_found"}}
      elif $cat == "security_updates_policy" and $p.state == "needs_person" then
        {key: $cat, value: {state: "needs_person", pending_fields: ($p.pending_fields | pending_ok)}}
      elif ($p.state == "ready" or $p.state == "needs_person") and ($p.envelope | envelope_ok($cat)) then
        (reduce $dropped[] as $f ($p.envelope; .payload |= setpath($f | split("."); false))) as $env
        | if ($kept | length) == 0 then {key: $cat, value: {state: "nothing_found"}}
          else {key: $cat, value: ({state: $p.state, envelope: $env, citations: $kept}
                 + (if $p.state == "needs_person" then {pending_fields: ($p.pending_fields | pending_ok)} else {} end))}
          end
      else {key: $cat, value: {state: "unreadable"}} end)
  | from_entries' "$P/resp" > "$P/proposals.json" 2> /dev/null \
  || fail "The proposals could not be read: no proposal; the record of this push is not affected."

# ------------------------------------------------------- 8. artifact
ART="$OUT_DIR/seetrex-proposals"
rm -rf -- "$ART"
mkdir -p "$ART"
n_files=0

# Appends the lines <start>..<end> of <path>, indented, to <review>.
append_quote() {
  awk -v s="$2" -v e="$3" 'NR >= s && NR <= e { sub(/\r$/, ""); print "    " $0 }' "$TREE/$1" >> "$4"
}

while IFS= read -r category || [ -n "$category" ]; do
  category="${category%$'\r'}"
  [[ "$category" =~ ^[a-z_]{1,64}$ ]] || continue
  state="$(jq -r --arg c "$category" '.[$c].state' "$P/proposals.json")"
  state="${state%$'\r'}"
  review="$ART/$category.review.md"
  case "$state" in
    nothing_found|unreadable) continue ;;
    ready)
      jq --arg c "$category" '.[$c].envelope' "$P/proposals.json" > "$ART/$category.json"
      n_files=$((n_files + 1))
      ;;
    needs_person)
      # Without an envelope (security_updates_policy) the review is written
      # below, on its own.
      jq -e --arg c "$category" '.[$c].envelope != null' "$P/proposals.json" > /dev/null || continue
      jq --arg c "$category" '.[$c].envelope' "$P/proposals.json" > "$ART/$category.json.pending"
      n_files=$((n_files + 1))
      ;;
    *) continue ;;
  esac
  {
    printf '# %s\n\n' "$category"
    case "$state" in
      ready) printf 'Proposal ready: review each citation below; to accept, copy `%s.json` to `.seetrex/attestations/` and commit it. The commit is your signature.\n\n' "$category" ;;
      needs_person) printf 'Needs a person: decide the pending fields below, then rename `%s.json.pending` to `%s.json` under `.seetrex/attestations/` and commit it. A pending field left `false` may exempt the obligation: decide it.\n\n' "$category" "$category" ;;
    esac
    printf '## Proposed true, with the citation rehydrated from this commit\n\n'
  } > "$review"
  jq -r --arg c "$category" '.[$c].citations // [] | .[]
    | if .source == "vuln_scan" then "scan\t\(.field)\t-\t0\t0\t\(.report_sha256)"
      else "line\t\(.field)\t\(.path)\t\(.line_start)\t\(.line_end)\t-" end' "$P/proposals.json" > "$P/cites.tsv"
  while IFS=$'\t' read -r kind field path start end extra || [ -n "$kind" ]; do
    extra="${extra%$'\r'}"
    if [ "$kind" = scan ]; then
      printf -- '- `%s` = true: the vulnerability scan of this push has 0 findings (report sha256 %s).\n\n' "$field" "$extra" >> "$review"
    else
      printf -- '- `%s` = true: `%s:%s-%s`\n\n' "$field" "$path" "$start" "$end" >> "$review"
      append_quote "$path" "$start" "$end" "$review"
      printf '\n' >> "$review"
    fi
  done < "$P/cites.tsv"
  if [ ! -s "$P/cites.tsv" ]; then
    printf -- '- (none)\n\n' >> "$review"
  fi
  printf '## Not found (left false)\n\n' >> "$review"
  jq -r --arg c "$category" '.[$c] as $p
    | ([$p.citations // [] | .[] | .field]) as $cited
    | ($p.pending_fields // []) as $pending
    | [$p.envelope.payload | paths(type == "boolean") | join(".")]
    | map(select(IN($cited[]) | not) | select(IN($pending[]) | not))
    | if length == 0 then "- (none)" else .[] | "- `\(.)` = false: not found" end' "$P/proposals.json" >> "$review"
  printf '\n## Decide yourself\n\n' >> "$review"
  jq -r --arg c "$category" '.[$c].pending_fields // []
    | if length == 0 then "- (none)" else .[] | "- `\(.)`: decide yourself" end' "$P/proposals.json" >> "$review"
  n_files=$((n_files + 1))
done < <(jq -r 'keys[]' "$P/proposals.json")

# security_updates_policy has no envelope: a review file with its fields.
if [ "$(jq -r '.security_updates_policy.state // empty' "$P/proposals.json")" = needs_person ] \
  && [ ! -f "$ART/security_updates_policy.review.md" ]; then
  {
    printf '# security_updates_policy\n\nNever proposed: every field of this category is yours to decide. Fill the template by hand.\n\n## Decide yourself\n\n'
    jq -r '.security_updates_policy.pending_fields // [] | if length == 0 then "- (none)" else .[] | "- `\(.)`: decide yourself" end' "$P/proposals.json"
  } > "$ART/security_updates_policy.review.md"
  n_files=$((n_files + 1))
fi

if [ "$n_files" -gt 0 ]; then
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf 'proposals=%s\n' "$ART" >> "$GITHUB_OUTPUT"
  fi
else
  rm -rf -- "$ART"
fi

# --------------------------------------------------------- 9. summary
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
say "Seetrex proposed attestations for review: $n_kept citations kept, $n_dropped dropped (their lines do not match this commit), $n_files files in the seetrex-proposals artifact."
exit 0
