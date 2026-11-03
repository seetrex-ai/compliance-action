# bin/filters/sbom.jq -- reduces Trivy's CycloneDX output to the fields the
# Seetrex server reads, before it leaves the runner.
#
# Invocation (bin/run.sh):
#   jq -c -f "$GITHUB_ACTION_PATH/bin/filters/sbom.jq" < sbom.raw.json > sbom.json
# No --arg. Input: one CycloneDX JSON document. Output: one compact JSON
# object. A non-object input is an error (jq exits non-zero).
#
# Whitelist, recursive (plan section 3 step 11):
#   root       bomFormat, specVersion, metadata.component, components,
#              dependencies (verbatim)
#   component  bom-ref + COMPONENT_SUBSTANTIVE_FIELDS + components (nested
#              components reduced the same way, at every level)
# Ground truth (seetrex repo, crates/compliance/src/connectors/cyclonedx/mod.rs):
#   COMPONENT_SUBSTANTIVE_FIELDS at :562-564 (type, group, name, version, purl,
#   cpe, swid, scope, hashes, licenses); nested `components` normalized at
#   :600-603; the root whitelist of normalize_cyclonedx at :173-249. The server
#   resolves the subject's depth-1 graph from `dependencies` and the `bom-ref`s
#   BEFORE dropping them (:189-211, :401), so both must travel.
# A key is written only if the original has it: `metadata.component: null`
# would turn a document without a subject into a 400, and an absent
# `dependencies` means "no graph declared" (:200-209), not an empty one.
# What is not a JSON object/array where the server expects one is passed on
# untouched, so the server refuses it exactly as it would refuse the original.

def component_fields:
  "bom-ref", "type", "group", "name", "version", "purl", "cpe", "swid",
  "scope", "hashes", "licenses", "components";

# One function for both shapes (jq has no forward references): an array of
# components is reduced element by element, a component keeps the whitelist
# and recurses into its own `components`; anything else is left as it is.
def reduce_tree:
  if type == "array" then map(reduce_tree)
  elif type == "object" then
    with_entries(select(.key | IN(component_fields)))
    | if has("components") then .components |= reduce_tree else . end
  else . end;

if type != "object" then
  error("sbom.jq: the CycloneDX document is not a JSON object")
else
  with_entries(select(.key | IN("bomFormat", "specVersion", "metadata",
                                "components", "dependencies")))
  | if has("metadata") then
      if (.metadata | type) == "object" and (.metadata | has("component"))
      then .metadata = {component: (.metadata.component | reduce_tree)}
      else del(.metadata)
      end
    else . end
  | if has("components") then .components |= reduce_tree else . end
end
