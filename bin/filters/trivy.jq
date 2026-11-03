# bin/filters/trivy.jq -- reduces Trivy's JSON report to the serde shape the
# Seetrex server parses, before it leaves the runner.
#
# Invocation (bin/run.sh):
#   jq -c -f "$GITHUB_ACTION_PATH/bin/filters/trivy.jq" < trivy.raw.json > trivy.json
# No --arg. Input: one Trivy JSON report. Output: one compact JSON object.
# A non-object input, or `Results`/`Vulnerabilities` that are neither an
# array nor null/absent, is an error (jq exits non-zero): serde would refuse
# them too, and mapping over an object would make one acceptable.
#
# Output shape (plan section 3 step 12), reproducing what serde re-serializes
# from TrivyReport (seetrex repo, crates/compliance/src/connectors/trivy/parser.rs):
#   SchemaVersion   Option<u32>, `default`, no skip      :44-45   -> null if absent
#   CreatedAt       Option<String>, skip_serializing_if  :61-62   -> only if non-null
#   Results         Vec, null/absent -> []                :72-73
#     Target          Option<String>                      :92-93   -> null if absent
#     Vulnerabilities Vec, null/absent -> []              :103-104
#       VulnerabilityID String (required)                 :111-112  verbatim
#       PkgName         Option<String>                    :115-116  -> null if absent
#       Severity        String (required)                 :122-123  verbatim
#       PublishedDate   Option<String>                    :129-130  -> null if absent
#       FixedVersion    Option<String>                    :136-137  -> null if absent
# Everything else is dropped: Metadata (Author, Committer, CommitMsg, ...),
# ArtifactName, ArtifactType, Class, Type, PkgID, InstalledVersion, Title,
# Description, ... The server's struct has no deny_unknown_fields, so the
# dropped keys never mattered to it.

def list_or_empty($what):
  if . == null then []
  elif type == "array" then .
  else error("trivy.jq: \($what) is neither an array nor null")
  end;

if type != "object" then
  error("trivy.jq: the Trivy report is not a JSON object")
else
  {SchemaVersion: .SchemaVersion}
  + (if .CreatedAt != null then {CreatedAt: .CreatedAt} else {} end)
  + {Results: (.Results | list_or_empty("Results") | map(
      {Target: .Target,
       Vulnerabilities: (.Vulnerabilities | list_or_empty("Vulnerabilities") | map(
         {VulnerabilityID, PkgName, Severity, PublishedDate, FixedVersion}))}))}
end
