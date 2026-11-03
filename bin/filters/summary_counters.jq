# bin/filters/summary_counters.jq -- the job summary of `summary: counters`,
# written from a 200 answer of the push route.
#
# Invocation (bin/run.sh), only after a 200 whose body is valid JSON:
#   jq -r -f "$GITHUB_ACTION_PATH/bin/filters/summary_counters.jq" < resp.json >> "$GITHUB_STEP_SUMMARY"
# No --arg. Output: markdown.
#
# Keeps the results out of the summary: it prints only how many obligations
# are in each `status`, under fixed labels. Never an `outcome`, a ruleset id
# (`cra-...`), the legend, a `skipped` name, `evaluated_at`,
# `scan_created_at`, nor anything of `.record`. A status outside the closed
# list of the server (current | not_current | no_verdict | not_documented,
# seetrex repo crates/compliance/src/api/action_router.rs ObligationState
# :860) is counted under "other", never echoed.

def obligations:
  if type == "object" and (.results | type) == "object"
     and (.results.obligations | type) == "array"
  then .results.obligations else [] end;

def count_of($s):
  [obligations[] | select(type == "object" and .status == $s)] | length;

def known: "current", "not_current", "no_verdict", "not_documented";

"## Seetrex Compliance",
"",
"Obligations by status (counters only):",
"",
"- current: \(count_of("current"))",
"- not current: \(count_of("not_current"))",
"- no verdict: \(count_of("no_verdict"))",
"- not documented: \(count_of("not_documented"))",
([obligations[] | select((type == "object" and (.status | IN(known))) | not)]
 | length
 | if . > 0 then "- other: \(.)" else empty end)
