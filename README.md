# Seetrex Compliance Action

**Status: under construction.** Nothing here is released yet; the first tag
will be `v1`.

Two lines in your repository. On every push to your default branch, the Action
measures what can be measured (component inventory, vulnerability scan), picks
up the attestations you keep in `.seetrex/attestations/`, and sends them to
Seetrex, which decides against the Cyber Resilience Act (CRA) catalogue and
appends the result to a hash-chained record for your repository.

```yaml
permissions: { id-token: write }
steps:
  - uses: seetrex-ai/compliance-action@v1
```

The `id-token` permission lets the workflow prove to Seetrex which repository
it runs for; there is no account to create and no secret to copy.

## Private

Your record is **private**: it is stored by Seetrex and never listed anywhere.
There is no public page and no option to publish it. The job summary shows only
how much the record grew, never a result: the summary of a job is visible to
anyone who can see a public repository.

Planned, not available yet:

- **Download.** You will be able to download your record and hand it to whoever
  asks (a customer, an auditor), and they will verify it offline with the
  open-source
  [`seetrex-verifier`](https://github.com/seetrex-hq/seetrex-verifier), without
  asking us.
- **External anchoring.** Records of third-party repositories are not anchored
  in an external log yet.

The Action works on public GitHub repositories; a private repository is refused.

## What leaves your repository

Only what is needed to decide: the generated inventory and scan, and the
attestation files committed in your tree, plus the `owner/repo` name and numeric
id of the repository, which identify your record. No source code and no secrets.
Authentication uses the GitHub OIDC token of the workflow run; there is nothing
to copy or configure.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
