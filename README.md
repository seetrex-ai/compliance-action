# Seetrex Compliance Action

**Status: private preview.** The first release, `v1.0.0`, exists and is
immutable: it points at commit `20dc0d2d4877be42203a9b2835486d0bab863b8d`, the
code that was measured end to end on a private test repository on 2026-11-05
and 2026-11-06. There is no Marketplace listing. Access is not open yet: while
we finish the service, the server admits only repositories owned by the
`seetrex-ai` organization, and there is no channel to request access. Nothing
in this README is a promise about a date.

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
are skipped. The Action never fetches a missing file from your remote. A
sparse checkout over a full clone is scanned in full, files outside your
checkout included, since the clone holds every file of the commit. A partial
clone (for example `filter: blob:none` in `actions/checkout`) holds only the
files its checkout wrote: when that checkout covered the whole pushed commit
it is scanned as usual; when it left part of the tree out (for example a
sparse checkout), the files left out are missing from the clone, so the run
stops and nothing is scanned or sent. Seetrex
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
first with `jq .chain seetrex-record.json > chain.json`). When the record
carries an anchor proof, `verify-record` also needs the kit that pins the
Seetrex keys (`--kit kit.json`); without it, or with a kit of the previous
format, the tool exits 2 and says so. The kit for third-party records is not
distributed yet. What that check proves, and what it does not, is stated
below. Keep the file: GitHub expires run artifacts (90 days by
default), and the next push brings the full record again.

The Action does not replace Art. 14 vulnerability reporting, nor a conformity
assessment. It gives you a record of what was measured, when, and what the rule
catalogue said about it.

## Proposals (optional, off by default)

The obligations that read an attestation stay `not_documented` until you
write its file by hand. Two inputs, both `false` by default, add an automatic
reader with citation that proposes those files for you to review. They come
with `v1.1.0`; `v1.0.0` has neither.

- `propose: true`: after the push, deterministic detectors run in your runner
  over the pushed commit (the same tree that is scanned) and look for facts: a
  reporting or disclosure section, a security contact and a "Supported
  Versions" table in `SECURITY.md`, a contact in `.well-known/security.txt`, a
  threat model file, a `CODEOWNERS` file, a Dependabot or Renovate
  configuration, and workflow steps that review dependencies, run a security
  analyzer (on a schedule or not) or sign or attest a release. A fact leaves
  the runner as a detector id, a path, line numbers and the SHA-256 of those
  lines, never as the lines themselves.
- `propose-with-model: true` (it needs `propose: true`; alone, the run stops
  with a fixed line and sends nothing): the Action also sends the whole text
  of the documents of a closed list that exist in the commit, and Seetrex
  passes them to an external LLM provider, which proposes values, each with a
  literal quote of the lines it relies on. The list: `README.md`;
  `SECURITY.md`, `.github/SECURITY.md`, `docs/SECURITY.md`; `PRIVACY.md`;
  `CONTRIBUTING.md`, `.github/CONTRIBUTING.md`, `docs/CONTRIBUTING.md`;
  `SUPPORT.md`, `.github/SUPPORT.md`, `docs/SUPPORT.md`; `THREAT_MODEL.md`,
  `.github/THREAT_MODEL.md`, `docs/THREAT_MODEL.md`, `docs/threat-model.md`;
  `docs/DEPENDENCIES.md`. No other file is ever sent as text.
- `dry-run: true` together with them: the job log lists the facts, the scan
  values and every document that would be sent (path, bytes, SHA-256), and
  nothing is sent: no token is requested and no request is made.

Proposals are asked only for the categories whose obligations the push left
`not_documented`. Each quote of a document is checked three times: by
Seetrex's reading service against the text it received, by Seetrex's server
against the same text before it drops it, and by the Action against the file
in your commit (the SHA-256 of the cited lines). A detector citation must be
exactly a fact this run sent, and its lines are hashed again from your
commit. A citation that fails any check is dropped and its field stays
`false`, "not found".

The result is the run artifact `seetrex-proposals`: per category a
`<category>.json` (every field settled) or a `<category>.json.pending` (fields
left to you), and a `<category>.review.md` that shows each proposed `true` as
`path:lines` with the quoted lines taken from your commit, each `false` as
"not found", and each field left to you as "decide yourself". The job summary
shows only paths and line numbers.

Nothing takes effect until a person commits it. The Action reads only `*.json`
files in `.seetrex/attestations/`, so a proposal counts only once someone
copies it there and commits it; the next push sends it like any other
attestation file. The fields that exempt an obligation, and the others that
only you can decide, are never proposed: they are written at the value that
exempts nothing and listed under "decide yourself". `security_updates_policy`,
whose fields include the placing-on-market date and the end of the support
period, is never proposed at all: you get only its review file. A failed
proposal is a warning in the job (a failed job only with `strict: true`) and
never affects the record of the push.

```yaml
        with:
          propose: true
          propose-with-model: true  # sends the text of the listed documents; read the sections below first
```

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

Pinned by the commit SHA of release `v1.0.0`. There is no moving `v1` tag. In
a private repository the job needs `actions/checkout` and both permissions
below.

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
      - uses: seetrex-ai/compliance-action@a9f6625e6faa5dd4dc50a36e398655b78b9c5dea # v1.1.0
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
  ids, then stores the numeric ids, the branch it tracks (`ref`), the commit sha of each push that
  stores a new document (`source_commit` in `seetrex-record.json`) and, only if a run asks for one, the
  branch and time of a re-pin request or the time of a close request; the name is echoed back there but not stored; the actor's login and id are not read.

With `propose: true` (off by default), after the push, also sent to
`api.seetrex.com`:

- the facts of the detectors: detector id, path, first and last line number,
  and the SHA-256 of those lines; never the lines;
- the scan of the push as three values: the number of findings in the reduced
  report, the number of packages in the SBOM, and the SHA-256 of the report
  exactly as it was sent;
- the categories to propose for, and a fresh OIDC token of the run for each
  request (the same claims as above).

With `propose-with-model: true` as well: the whole text of each document of
the closed list above that exists in the commit, with its path, size and
SHA-256. Each one is listed in the job log (path, bytes, SHA-256) before
anything is requested, and what is listed is exactly what is sent. A document
is left out, and the log says why, when it is empty, over 64 KiB, not UTF-8
text, or when a line looks like a credential (a private key block, a cloud,
forge or service token, a bearer token, a URL with a password, among others);
and past 12 documents or 256 KiB in all. Documents travel whole: a README that
contains code examples, commands or configuration snippets sends them as part
of its text.

Never sent as text, whatever the inputs: your source code files, workflow
files, lockfiles and dependency-manager configuration (the detectors read some
of them in the runner, and only the facts above leave), any file outside the
closed list other than the attestation files above, the identity of the
author or committer (beyond the token's `actor` claims above), commit
messages, your `github.token`, or anything else from the runner.

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
that those checks then stop. The proposal step adds no destination to the
runner: its requests go only to `api.seetrex.com` (after a token from the
runner's OIDC service), and the `seetrex-proposals` upload goes to the GitHub
artifact service. With `propose-with-model: true`, the text of the documents
then travels on from Seetrex to an external LLM provider (next section).

## What Seetrex can and cannot do with it

Please read this before installing.

- **Results are never published.** There is no public page, no badge and no
  option to publish. Seetrex does not show the record to third parties. Who
  else sees something: Cloudflare, which fronts `api.seetrex.com`, sees each
  request at the edge; GitHub stores the job summary and the run artifacts
  under your repository's own permissions (the review files of
  `seetrex-proposals` quote the cited lines of your files); with
  `propose-with-model: true`, an external LLM provider receives the text of
  the documents sent.
- **Seetrex can read what you send.** The record is stored on Seetrex servers
  and is not end-to-end encrypted. It is not sold and it is not shown to
  third parties.
- **Documents are read in memory and not stored.** With
  `propose-with-model: true`, Seetrex's server holds the text of the documents
  in memory only while the proposal is built. Its reading service checks them
  for credentials again (a match is not passed on) and sends the text, with
  the paths and the names of the fields it looks for, to an external LLM
  provider, through Seetrex's own account and under that provider's terms.
  Seetrex's server then checks every citation against the text and drops the
  text. Seetrex does not store it: not in its database, not on disk, not in
  its logs. What Seetrex keeps is a proposals log without text: the numeric
  repository id, the time, and per category the state of the proposal and
  each citation as field, path, line numbers and line hash; for each request
  to the reading service, a hash of the set of documents (their paths and
  SHA-256 values), the number of fields looked for, the path of each document
  left out by the credential check with the names of the patterns that
  matched, and, when the provider was called, the name of the model that
  answered, its stop reason, the token usage and the cost. Seetrex's answer,
  without text, waits in memory for at most 10 minutes for the Action to
  collect it.
- **What the offline check proves, and what it does not.** `seetrex-verifier
  verify-chain` recomputes every hash link of the `chain` block and the head
  hash, and prints its own banner and a scope statement when they hold. That
  proves the rows in the file are linked in order and none of them was
  altered or reordered. It does not prove, by itself, the date of a row,
  that no row is missing at the end, or that the human-readable columns of a
  row (rule set, outcome) are what the engine produced: those columns are
  not inputs to the link. The first two need an external anchor. Since
  2026-11-05 the head of the chain that batches third-party records is
  submitted every hour to a public transparency log (Sigsum), and the proof
  travels inside `seetrex-record.json` (`anchor`). `verify-record --kit`
  checks it offline and prints `ANCHOR: CONFIRMED OFFLINE through ordinal k
  of N`: the rows up to `k` existed when the log's cosigned checkpoint was
  made; the rows after `k` are linked to them and not anchored yet. Measured
  on 2026-11-06 on a private test repository, in a container without network
  access: exit 0, confirmed through ordinal 1 of 4. A confirmed anchor does
  not prove completeness (nobody outside Seetrex can see that a repository
  was left out of a batch), does not detect a chain cut back to the proved
  row, and still says nothing about the human-readable columns. Seetrex makes
  no claim beyond what the tool prints: it reports what it checked, and you
  read it.
- **Nothing is deleted row by row.** The record is append-only by design. We
  intend to retire the whole record of a repository on request, through a
  procedure we are still building and have not tested yet; until it exists,
  this README makes no deletion promise. When it exists, the request will be
  made from the Action itself (`request-close`), so that it comes from the
  repository and not from an email. What has already been anchored
  externally, if anything, stays as an unlinkable hash.
- **Visibility changes are your call.** If a private repository later becomes
  public, we expect its old runs, their summaries and their artifacts to
  become visible with it: that is how GitHub documents repository visibility,
  and we have not measured it ourselves yet.
- **No retention period is promised.** Keep your own copy of
  `seetrex-record.json`.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
