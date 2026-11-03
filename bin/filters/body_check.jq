# bin/filters/body_check.jq -- the last gate before a DOCUMENT push leaves the
# runner: the body holds only the fields the Action declares, with their types.
#
# Invocation (bin/run.sh), on the body file exactly as it will be sent:
#   jq -n -e -f "$GITHUB_ACTION_PATH/bin/filters/body_check.jq" < body.json > /dev/null
# `-n` is required: the filter reads the input stream itself, so that a file
# holding two JSON values is refused (with plain `jq -e` the LAST value would
# decide). No --arg. Exit 0 = the body may be sent; exit 1 = refused; any
# other non-zero (a parse error is 2 or 5) is refused as well.
# Control bodies ({"repin":true} / {"close":true}) are literals written by
# run.sh and never pass through this filter: `repin`/`close` are extra keys
# here on purpose.
#
# Accepted: exactly one JSON object whose keys are a subset of
#   sbom            string
#   trivy           string
#   attestations    array of strings, at most 32
#   trivy_left_out  the literal `true`, and only without `trivy`
# carrying at least one document (`sbom`, `trivy`, `trivy_left_out` or a
# non-empty `attestations`). Server side (seetrex repo,
# crates/compliance/src/api/action_router.rs): ActionPushRequest :769-790,
# `deny_unknown_fields`; the 32-attestation cap :437; an empty push is
# a 400 (:1170-1172); `trivy_left_out` is the
# field of plan section 2 (unit U1), `false` is never sent by the Action.

def declared: "sbom", "trivy", "attestations", "trivy_left_out";

def absent_or($k; cond): (has($k) | not) or (.[$k] | cond);

def well_formed:
  type == "object"
  and all(keys[]; IN(declared))
  and absent_or("sbom"; type == "string")
  and absent_or("trivy"; type == "string")
  and absent_or("attestations";
        type == "array" and length <= 32 and all(.[]; type == "string"))
  and absent_or("trivy_left_out"; . == true)
  and ((has("trivy_left_out") and has("trivy")) | not)
  and (has("sbom") or has("trivy") or has("trivy_left_out")
       or ((.attestations // []) | length) > 0);

[inputs] | length == 1 and (.[0] | well_formed)
