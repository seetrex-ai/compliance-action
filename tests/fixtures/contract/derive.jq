# tests/fixtures/contract/derive.jq -- derives bin/contract/reader-contract-1.json
# (the part of reader contract 1 that bin/propose.sh reads at run time) from
# the contract's own schemas, copied in this directory (see README.md).
#
# Invocation (tests/test_contract.sh, and by hand when the contract moves):
#   jq -S -n --slurpfile req propose-request.schema.json \
#     --slurpfile resp propose-response.schema.json \
#     --slurpfile facts facts.schema.json -f derive.jq
#
# Output: {contract: 1, model_documents, detector_ids, categories: {<category>:
#   {state, leaves, model_fields, detector_fields, scan_fields, pending_fields}}}
# leaves: every leaf of payload_<category>, by dotted path; null for a free
# boolean (true only with a citation), the const for a fixed one (a pending
# field, or a descriptive field the contract fixes). security_updates_policy
# has no envelope: leaves is null. A leaf of another shape is an error: the
# runner only knows booleans.

def leaves($prefix):
  if has("properties") then
    .properties | to_entries[] | .key as $k | .value | leaves($prefix + [$k])
  elif has("const") then {key: ($prefix | join(".")), value: .const}
  elif .type == "boolean" then {key: ($prefix | join(".")), value: null}
  else error("derive.jq: leaf \($prefix | join(".")) is neither a boolean nor a const")
  end;

def enum_of($name): ($resp[0]["$defs"][$name].enum // []);

def citation_refs:
  .properties.citations.items
  | if has("oneOf") then .oneOf[] else . end
  | ."$ref";

($resp[0]["$defs"]) as $d
| {
    contract: 1,
    derived_from: "reader contract 1, Seetrex repository commit 8f4e1ac5 (crates/compliance/reader/contract), by tests/fixtures/contract/derive.jq",
    model_documents: $req[0]["$defs"].model_document_path.enum,
    detector_ids: $facts[0]["$defs"].detector_id.enum,
    categories: (
      $d.proposals.properties | to_entries | map(
        .key as $cat
        | (.value | if has("oneOf") then [.oneOf[] | select(."$ref" == null)][0] else . end) as $branch
        | {key: $cat, value: {
            state: $branch.properties.state.const,
            leaves: (if $branch.properties.envelope == null then null
                     else ($d["payload_" + $cat] | [leaves([])] | from_entries) end),
            model_fields: enum_of("model_fields_" + $cat),
            detector_fields: enum_of("detector_fields_" + $cat),
            scan_fields: (if [$branch | citation_refs] | any(. == "#/$defs/scan_citation")
                          then [$d.scan_citation.properties.field.const] else [] end),
            pending_fields: enum_of("pending_fields_" + $cat)
          }})
      | from_entries)
  }
