## Seetrex Compliance

Evaluated at: 2099-06-06T06:06:06.654321Z

Scan in force created at: 2099-06-05T05:05:05.123456Z

| Obligation | Status | Outcome |
|---|---|---|
| `cra-art13-vulnerability-handling` | current | VIOLATED |
| `cra-art13-third-party-components` | not current | - |
| `cra-art13-security-updates` | current | SATISFIED |
| `cra-annex1-access-data-protection` | no verdict | - |
| `cra-annex1-availability-resilience` | not documented | - |
| `cra-annex1-monitoring-lifecycle` | not documented | - |
| `cra-annex1-secure-config-updates` | current | INDETERMINATE |
| `cra-annex1-secure-design` | not documented | - |
| `cra-annex1p2-cvd-disclosure` | no verdict | - |
| `cra-annex1p2-testing-distribution` | not documented | - |
| `cra-annex2-user-information` | not documented | - |

Legend:
- **current**: The engine's last verdict; at evaluated_at the documents in force are the ones it read and the engine gives the same result over them.
- **not current**: The engine's last verdict, kept as history; it does not stand at evaluated_at: the documents in force are not the ones it read, or the engine no longer gives this result over those same documents.
- **no verdict**: No verdict is on record over the documents in force. This is not a result.
- **not documented**: Not documented: there is no document in force of a kind this obligation reads.

Left out of this push:
- `vuln_scan`: the vulnerability report was not read (it was over its size cap, or the Action left it out); the obligations that read it are not current.
- `sbom_within_tolerance`: the SBOM was not recorded again; it is within tolerance of the one in force.
