# bin/filters/summary_full.jq -- the job summary of `summary: full`, written
# from a 200 answer of the push route.
#
# Invocation (bin/run.sh), only after a 200 whose body is valid JSON:
#   jq -r -f "$GITHUB_ACTION_PATH/bin/filters/summary_full.jq" < resp.json >> "$GITHUB_STEP_SUMMARY"
# No --arg: the legend is copied from the answer itself. Output: markdown.
#
# Rules (plan section 3 step 18, REPLAN:625):
#   - reads `.results` and `.skipped` only, NEVER `.record` (the record is the
#     artifact; its copy of `results` is not what the summary shows);
#   - the result of an obligation is its `status`; `outcome` is shown only
#     for `status == "current"`, never `last_verdict.outcome` of a
#     `not_current` one (a stale verdict must not read as the current one);
#   - the legend is printed verbatim from `.results.legend`;
#   - each `skipped` value gets a fixed sentence, and its name is echoed only
#     if it matches ^[a-z_]{1,64}$; any other value gets one generic line;
#   - every other datum echoed from the answer (ruleset id, outcome, dates)
#     is printed only if it matches a closed pattern, else "(unreadable)": the
#     summary is markdown, and nothing in it may come out as markup.
# Server shapes (seetrex repo, crates/compliance/src/api/action_router.rs):
# PushResponse :811 (`skipped` absent when empty, :824-825), PushResults
# :836, Obligation :851 and ObligationState :860 (`status` in current |
# not_current | no_verdict | not_documented; `outcome` only at the top level
# of `current`, `last_verdict` in `not_current`), VerdictSeen :869, Legend
# :883 and LEGEND :890, PushRecord :905 (never read here), skipped
# values :506 (`sbom_within_tolerance`) and :511 (`vuln_scan`).

def safe($re):
  if type == "string" and test($re) then . else "(unreadable)" end;

def status_label:
  {current: "current", not_current: "not current", no_verdict: "no verdict",
   not_documented: "not documented"}[if type == "string" then . else "" end]
  // "(unknown status)";

def outcome_cell:
  if .status == "current" then (.outcome | safe("^[A-Z][A-Z_]{0,31}$"))
  else "-" end;

def skipped_line:
  if type == "string" and test("^[a-z_]{1,64}$") then
    if . == "vuln_scan" then
      "- `vuln_scan`: the vulnerability report was not read (it was over its size cap, or the Action left it out); the obligations that read it are not current."
    elif . == "sbom_within_tolerance" then
      "- `sbom_within_tolerance`: the SBOM was not recorded again; it is within tolerance of the one in force."
    else
      "- `\(.)`: a document of this category was not read."
    end
  else
    "- A document was left out for a reason this version of the Action cannot read."
  end;

def legend_line($key; $label):
  (.results.legend | if type == "object" then .[$key] else null end) as $text
  | if ($text | type) == "string" then "- **\($label)**: \($text)"
    else "- **\($label)**: (missing from the answer)" end;

def obligations:
  .results.obligations | if type == "array" then . else [] end;

"## Seetrex Compliance",
"",
if type == "object" and (.results | type) == "object" then
  "Evaluated at: \(.results.evaluated_at | safe("^[0-9A-Za-z:.+-]{1,64}$"))",
  "",
  (if .results.scan_created_at == null
   then "Scan in force created at: none readable"
   else "Scan in force created at: \(.results.scan_created_at | safe("^[0-9A-Za-z:.+-]{1,64}$"))"
   end),
  "",
  "| Obligation | Status | Outcome |",
  "|---|---|---|",
  (obligations[]
   | if type == "object" then
       "| `\(.ruleset_id | safe("^[a-z0-9][a-z0-9-]{0,63}$"))` | \(.status | status_label) | \(outcome_cell) |"
     else "| (unreadable) | (unknown status) | - |" end),
  "",
  "Legend:",
  legend_line("current"; "current"),
  legend_line("not_current"; "not current"),
  legend_line("no_verdict"; "no verdict"),
  legend_line("not_documented"; "not documented"),
  (.skipped
   | if type == "array" and length > 0 then
       "", "Left out of this push:", (.[] | skipped_line)
     else empty end)
else
  "The answer carried no readable results."
end
