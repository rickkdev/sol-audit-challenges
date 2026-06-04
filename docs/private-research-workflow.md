# Private Candidate Research Workflow

This workflow is for curators who are collecting real candidate incidents or
audit findings. Keep candidate notes, source mappings, vulnerable commits, and
private oracle files out of this public repository history.

## Storage Boundaries

- Public repository: tooling, schemas, fake examples, public manifests, and
  documentation only.
- Private candidate notes: use `research/local/` in this checkout or a separate
  private curator repository.
- Private oracle records: use `ground-truth/` in this checkout or a separate
  private curator repository.
- Generated public artifacts: publish only sanitized snapshots, public
  manifests, and bundles that have passed review.

The committed templates under `templates/` are safe examples. Copy them into an
ignored private path before replacing fake placeholders with real data:

```bash
mkdir -p research/local/candidates ground-truth
cp templates/private-candidate.template.json research/local/candidates/case-0001.candidate.private.json
cp templates/private-oracle.template.json ground-truth/case-0001.private.json
```

## Candidate Intake

For each candidate, record the following in an ignored private candidate file:

- Candidate case id and current verification status.
- Source repository or verified source package.
- Candidate vulnerable commit and optional fixed commit.
- Why the issue is code-auditable from the snapshot alone.
- Source references used for verification.
- Sanitization notes for protocol names, incident names, addresses,
  transaction hashes, audit report filenames, and exploit artifacts.
- Rejection notes if the case depends on private keys, off-chain operations, or
  external state that cannot be represented in the source snapshot.

Do not put real incident names, protocol names, repository URLs, commits,
addresses, or transaction hashes in committed files. The fake public candidate
example in `examples/candidates/` shows the shape of a shareable candidate
summary without ground truth.

## Verification Steps

Before a candidate becomes a private oracle:

1. Confirm the source can be checked out or reconstructed at the vulnerable
   revision.
2. Confirm the vulnerable revision predates the fix or public disclosure.
3. Identify the affected file, function or symbol, and the root cause.
4. Verify that a submitted finding can be judged without giving the evaluator
   web access or the private oracle.
5. List all clue-bearing strings and files that sanitization must remove or
   replace.
6. Run `prepare-case`, `sanitize-case`, and `bundle-case` on a local working
   copy.
7. Validate the private oracle with `sol-audit-challenges validate-private`.
8. Inspect the public snapshot and bundle before publishing.

Only promote a case when the private oracle explains the accepted finding well
enough for maintainer review and the public bundle contains no answer clues.

## Publishing Checklist

- Private files remain under ignored paths such as `ground-truth/` or
  `research/local/`.
- The public manifest contains only anonymized case metadata.
- The public snapshot has no `.git` directory, remotes, branch names, tags,
  commit history, exploit scripts, audit reports, postmortems, or research
  notes.
- Sanitizer reports do not print sensitive replacement `find` values.
- Public examples and fixtures contain fake data only.
