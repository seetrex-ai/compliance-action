# bin/filters/facts.jq -- assembles the facts document of reader contract 1
# (crates/compliance/reader/contract/facts.schema.json in the Seetrex
# repository) from the candidate lines bin/detect.sh collects.
#
# Invocation (bin/detect.sh), raw lines on stdin:
#   jq -c -n -R -f "$GITHUB_ACTION_PATH/bin/filters/facts.jq" < facts.tsv
# Input: one candidate per line, five tab-separated fields:
#   <detector id> <repository path> <line_start> <line_end> <sha256>
# Output (-c): {version: 1, facts: [{id, path, line_start, line_end,
# line_sha256}]}, each fact validated against the contract (closed catalogue
# of ids, path pattern, 1 <= line_start <= line_end <= 1000000, 64 lower-case
# hex), de-duplicated and sorted, at most 256. A candidate that does not fit
# is dropped, never repaired. No text of the repository ever reaches this
# filter: a line that is not five fields is ignored.

def catalogue:
  ["dependency_review_step", "dependency_update_config", "security_policy_file",
   "security_contact", "security_analyzer_step", "scheduled_security_analysis",
   "release_provenance_step", "threat_model_file", "supported_versions_table",
   "codeowners_file"];

# The input lines carry no newline (jq -R splits on them), so an anchored
# test spans the whole field.
def whole($re): type == "string" and test($re);

def path_ok:
  whole("^\\.?[A-Za-z0-9_-][A-Za-z0-9._-]*(/\\.?[A-Za-z0-9_-][A-Za-z0-9._-]*)*$")
  and length <= 512;

def line_ok: whole("^[1-9][0-9]{0,6}$") and (tonumber <= 1000000);

def candidate:
  rtrimstr("\r")
  | select(length > 0)
  | split("\t")
  | select(length == 5)
  | select(.[0] | IN(catalogue[]))
  | select(.[1] | path_ok)
  | select(.[2] | line_ok)
  | select(.[3] | line_ok)
  | select((.[2] | tonumber) <= (.[3] | tonumber))
  | select(.[4] | whole("^[0-9a-f]{64}$"))
  | {id: .[0], path: .[1], line_start: (.[2] | tonumber),
     line_end: (.[3] | tonumber), line_sha256: .[4]};

{version: 1, facts: ([inputs | candidate] | unique | .[:256])}
