# bin/filters/summary_proposals.jq -- the job summary of the proposal step,
# one row per obligation the push left not_documented.
#
# Invocation (bin/propose.sh), after the citations were rehydrated:
#   jq -r -f "$GITHUB_ACTION_PATH/bin/filters/summary_proposals.jq" < summary.in
# Input: {obligations: [{ruleset_id, category}], proposals: {<category>:
# {state, citations?, pending_fields?}}} as propose.sh assembled it. Output:
# markdown.
#
# Rules (plan R4 section 2.6): per obligation, "proposal ready (N
# citations: ...)", "needs a person (M fields to decide; ...)", "nothing
# found" or "rejected"; only paths and line numbers are echoed, never a
# quote, a field value or a model name. A citation is a detector's fact or a
# line the reader cited in a document: both are "citations", never "facts".
# Every datum echoed is printed only if it matches a closed pattern, else
# "(unreadable)": the summary is markdown, and nothing in it may come out as
# markup.

# Counted, not anchored: jq's `$` also matches before a final newline.
def safe($re):
  if type == "string"
     and ([match($re)] | length == 1 and .[0].offset == 0)
     and ([match($re)][0].length == length)
  then . else "(unreadable)" end;

def locator:
  if .source == "vuln_scan" then "vulnerability scan: 0 findings"
  else "\(.path | safe("^\\.?[A-Za-z0-9_-][A-Za-z0-9._-]*(/\\.?[A-Za-z0-9_-][A-Za-z0-9._-]*)*$")):\(.line_start | if type == "number" then floor else "?" end)-\(.line_end | if type == "number" then floor else "?" end)"
  end;

def cited:
  (.citations // [] | if type == "array" then map(select(type == "object")) else [] end) as $c
  | if ($c | length) == 0 then "no citation"
    else "\($c | length) citation\(if ($c | length) == 1 then "" else "s" end): \($c | map(locator) | join(", "))"
    end;

def proposal_cell:
  if type != "object" then "(unreadable)"
  elif .state == "ready" then "proposal ready (\(cited))"
  elif .state == "needs_person" then
    "needs a person (\(.pending_fields // [] | if type == "array" then length else 0 end) fields to decide; \(cited))"
  elif .state == "nothing_found" then "nothing found"
  elif .state == "rejected" then "rejected (one field cited twice)"
  else "(unreadable)" end;

"## Seetrex Compliance (proposals)",
"",
if type == "object" and (.obligations | type) == "array" and (.proposals | type) == "object" then
  "| Obligation | Category | Proposal |",
  "|---|---|---|",
  (.proposals as $p
   | .obligations[]
   | if type == "object" then
       "| `\(.ruleset_id | safe("^[a-z0-9][a-z0-9-]{0,63}$"))` | `\(.category | safe("^[a-z_]{1,64}$"))` | \($p[.category] | proposal_cell) |"
     else "| (unreadable) | (unreadable) | (unreadable) |" end),
  "",
  "A proposal has effect only once a person reviews it and commits it under `.seetrex/attestations/`."
else
  "The proposal step produced nothing readable."
end
