# Reader contract 1 (copy)

Byte-for-byte copies of the reader contract the proposal step speaks, taken
from the Seetrex repository at commit `8f4e1ac5`
(`8f4e1ac581868a6d18c58063c544696c332ce6fa`):

| File here | Source in the Seetrex repository |
|---|---|
| `facts.schema.json` | `crates/compliance/reader/contract/facts.schema.json` |
| `propose-request.schema.json` | `crates/compliance/reader/contract/propose-request.schema.json` |
| `propose-response.schema.json` | `crates/compliance/reader/contract/propose-response.schema.json` |
| `reader-request.schema.json` | `crates/compliance/reader/contract/reader-request.schema.json` |
| `reader-response.schema.json` | `crates/compliance/reader/contract/reader-response.schema.json` |
| `templates/*.json` | `crates/compliance/attestations/templates/*.json` |

SHA-256 at that commit:

```
a0d5eac2d19ef3ad479971a7ef7664272ce61dc3e201cae61dcc69c5566d7f3e  facts.schema.json
7f7c4ccd1500bbff7d0ba06c9fd2b078ceb44b470b46afd08b5448544397940d  propose-request.schema.json
91360592424267c355a5e8c71462833eccf19103f4954a2284e6bc9ef8f6e5ee  propose-response.schema.json
8b3fdca4d76bf2f0a5dd13c1054fcaa4ccc35d58320c6acde28658c5aeb594d8  reader-request.schema.json
4f50821703b083d607894461286c61a450f62892eae010cbbe02fea9dab1563b  reader-response.schema.json
```

The tests read the contract from here, never from a copy written into a
test: the closed list of documents, the detector catalogue, the shape of the
request and the leaves of each payload.

**What the Action reads at run time** is `bin/contract/reader-contract-1.json`,
derived from these schemas by `derive.jq` (this directory). `tests/test_contract.sh`
derives it again and fails if the file in `bin/` differs, and checks that the
leaves of every payload are exactly the keys of the category's template. When
the contract moves: copy the five schemas and the templates again, update the
commit and the hashes above, and regenerate:

```
jq -S -n --slurpfile req propose-request.schema.json \
  --slurpfile resp propose-response.schema.json \
  --slurpfile facts facts.schema.json -f derive.jq > ../../../bin/contract/reader-contract-1.json
```

(and change `derived_from` in `derive.jq`).
