# bin/filters/dry_run.jq -- describes, in a dry run, the body that WOULD be
# sent, without sending it.
#
# Invocation (bin/run.sh), on the body file it built (document push or
# control literal):
#   jq -r -f "$GITHUB_ACTION_PATH/bin/filters/dry_run.jq" < body.json
# No --arg. Output: plain text lines, for the log and/or the job summary.
#
# Plan section 3 step 15 lists what a dry run shows: files, sizes, sha256,
# the keys of the body, counts. This filter gives the keys and the sizes and
# counts that the body itself determines:
#   Body keys: <sorted keys>
#   sbom: <N> bytes                       (UTF-8 bytes of the string)
#   trivy: <N> bytes
#   trivy_left_out: true (the vulnerability report is left out)
#   attestations: <K> documents, <N> bytes
#   repin: true (control request) / close: true (control request)
# File names, file sizes and sha256 are run.sh's (jq cannot hash), and so are
# the two counts step 15 asks for (SBOM components, vulnerability report
# entries): run.sh measures them on the reduced files it built. This filter
# NEVER looks inside a document: no count of components, vulnerabilities,
# severities or packages, no name, no content. A key outside the declared
# ones is not echoed (one fixed line instead), nor is a value of an
# unexpected type.

def bytes: if type == "string" then utf8bytelength else null end;

def line($k; $v):
  if $k == "sbom" or $k == "trivy" then
    if ($v | type) == "string" then "\($k): \($v | bytes) bytes"
    else "\($k): (not a string)" end
  elif $k == "attestations" then
    if ($v | type) == "array" then
      "attestations: \($v | length) documents, \([$v[] | bytes // 0] | add // 0) bytes"
    else "attestations: (not a list)" end
  elif $k == "trivy_left_out" then
    if $v == true then "trivy_left_out: true (the vulnerability report is left out)"
    else "trivy_left_out: (not true)" end
  elif $k == "repin" or $k == "close" then
    if $v == true then "\($k): true (control request)"
    else "\($k): (not true)" end
  else
    "(a key this version of the Action does not declare)"
  end;

def declared: "sbom", "trivy", "trivy_left_out", "attestations", "repin", "close";

if type != "object" then
  "Body: not a JSON object"
else
  "Body keys: \([keys[] | if IN(declared) then . else "(undeclared)" end] | join(", "))",
  (keys[] as $k | line($k; .[$k]))
end
