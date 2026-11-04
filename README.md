# Seetrex Compliance Action

**Status: under construction, private preview.** The Action is not published
yet: there is no release, no tag and no Marketplace listing. Access is not open
yet: while we finish it, the server admits only repositories owned by the
`seetrex-ai` organization, and there is no channel to request access. This
README describes what the Action does when released, and nothing in it is a
promise about a date.

## What it does

On every push to your repository's default branch (a push to any other
branch, or any other event, sends nothing), the Action runs in your own runner,
builds a component inventory (CycloneDX SBOM) and a vulnerability scan (Trivy),
picks up the attestation files you keep in `.seetrex/attestations/`, and sends
the three to Seetrex. What it scans is exactly the pushed commit
(`GITHUB_SHA`), each file copied byte for byte from the commit's objects:
files modified, staged or added in the working directory by earlier steps of
the job are not scanned; no `.gitattributes`, line-ending setting, filter or
`git replace` changes what is read; and the repository's own `trivy.yaml` and
`.trivyignore` are not applied. Files stored with Git LFS are scanned as the
pointer text that is committed, submodules are not scanned, and symbolic links
are skipped. With a partial or sparse clone (for example `filter: blob:none`
in `actions/checkout`), the Action never fetches a missing file from your
remote: the run stops and nothing is scanned or sent. Seetrex
evaluates them deterministically against a rule catalogue derived from the
Cyber Resilience Act (CRA) and appends the outcome to a hash-chained,
append-only record kept for your repository.

What you get back, in the same job:

- in the job summary, with `summary: full` (the default), the status of each
  obligation and, for the current ones, their outcome; with
  `summary: counters`, only how many obligations are in each status, and no
  result;
- `seetrex-record.json` as a run artifact, when Seetrex returns a record with
  its answer: your whole record to date (the chain, the results and, when
  available, the external anchoring proof).

The record is tamper-evident and you can check its integrity without Seetrex,
offline, with the open-source
[`seetrex-verifier`](https://github.com/seetrex-hq/seetrex-verifier)
(`verify-record` checks the whole file, since `seetrex-verifier` 0.3.8,
published 2026-11-03; `verify-chain` checks only the `chain` block, extract it
first with `jq .chain seetrex-record.json > chain.json`). What that check proves, and what it does not, is
stated below. Keep the file: GitHub expires run artifacts (90 days by
default), and the next push brings the full record again.

The Action does not replace Art. 14 vulnerability reporting, nor a conformity
assessment. It gives you a record of what was measured, when, and what the rule
catalogue said about it.

## Scope: private repositories only

In this phase the Action accepts **private** and **internal** repositories.
A public repository is refused by the server, and the Action itself stops
early with a fixed line when it detects one, so that no counts land in a
publicly readable job summary.

There is no account to create and no secret to copy. The workflow proves which
repository it runs for with the GitHub OIDC token of the run (`id-token:
write`), and that token is the only credential. The Action never reads
`github.token` and the server never connects to your systems.

## Install

Pinned by SHA once released; the `<sha>` placeholder of the Action is filled
in by the first release (`v1.0.0`). There is no moving `v1` tag. In a private
repository the job needs `actions/checkout` and both permissions below.

```yaml
on: { push: { branches: [main] } }  # your default branch; update it if you rename it
concurrency: { group: seetrex, cancel-in-progress: false }
permissions: { contents: read, id-token: write }
jobs:
  record:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        with: { persist-credentials: false }
      - uses: seetrex-ai/compliance-action@<sha> # v1.0.0
```

## What leaves your repository

Sent to `api.seetrex.com`:

- the CycloneDX SBOM, reduced to the fields the evaluation uses;
- the Trivy vulnerability report, reduced to the fields the evaluation uses;
  `Metadata.Author`, `Metadata.Committer` and `Metadata.CommitMsg` are removed
  before sending;
- the attestation files committed under `.seetrex/attestations/` at the pushed
  commit: only `*.json` files directly in that directory (not in
  subdirectories, not symbolic links), at most 32 (with more, nothing is
  sent);
- the OIDC token of the run, whose claims GitHub sets and the Action cannot
  trim: among them the `owner/repo` name, the numeric repository id and the
  numeric owner id, and also the login and the numeric id of the account that
  triggered the run (`actor`, `actor_id`), the workflow, the ref, the commit
  sha, the run id and the event name. The server checks the name and the
  ids, then keeps only the numeric ids: the repository id identifies your
  record, and the name is echoed back to you in `seetrex-record.json` but is
  not stored on Seetrex servers; the actor's login and id are not read.

Not sent: your source code, the identity of the author or committer (beyond
the token's `actor` claims above), commit messages, your `github.token`, or
anything else from the runner.

Network destinations of a run, all over HTTPS: `api.seetrex.com`; the Trivy
release download from `github.com` and the release-asset host it redirects to
(on `githubusercontent.com`); the Trivy vulnerability database and Java
database downloads, from Trivy's default registries (`mirror.gcr.io`, then
`ghcr.io`; we have not measured every host involved, and the registries may
redirect the download of the database layers to further hosts of their own);
the runner's OIDC token service; and the GitHub Actions cache and artifact
services (the database cache and the `seetrex-record.json` upload). The
step that restores the Trivy database cache runs before the Action's own
checks (private repository, push, default branch), so it runs even on a run
that those checks then stop.

## What Seetrex can and cannot do with it

Please read this before installing.

- **Results are never published.** There is no public page, no badge and no
  option to publish. Seetrex does not show the record to third parties. Who
  else sees something: Cloudflare, which fronts `api.seetrex.com`, sees each
  request at the edge; GitHub stores the job summary and the run artifact
  under your repository's own permissions.
- **Seetrex can read what you send.** The record is stored on Seetrex servers
  and is not end-to-end encrypted. It is not sold and it is not shown to
  third parties.
- **What the offline check proves, and what it does not.** `seetrex-verifier
  verify-chain` recomputes every hash link of the `chain` block and the head
  hash, and prints its own banner and a scope statement when they hold. That
  proves the rows in the file are linked in order and none of them was
  altered or reordered. It does not prove, by itself, the date of a row,
  that no row is missing at the end, or that the human-readable columns of a
  row (rule set, outcome) are what the engine produced: those columns are
  not inputs to the link. The first two need an external anchor; anchoring
  of third-party records is planned and not available yet. Seetrex makes no
  claim beyond what the tool prints: it reports what it checked, and you
  read it.
- **Nothing is deleted row by row.** The record is append-only by design. We
  intend to retire the whole record of a repository on request, through a
  procedure we are still building and have not tested yet; until it exists,
  this README makes no deletion promise. When it exists, the request will be
  made from the Action itself (`request-close`), so that it comes from the
  repository and not from an email. What has already been anchored
  externally, if anything, stays as an unlinkable hash.
- **Visibility changes are your call.** If a private repository later becomes
  public, its old runs, their summaries and their artifacts become visible
  with it.
- **No retention period is promised.** Keep your own copy of
  `seetrex-record.json`.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
