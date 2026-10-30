# hayward-verify

Signed scan verdicts for popular Hugging Face models, published at
**verify.hedgerow.dev** and checked by [Hayward](https://github.com/hedgerow-dev/hayward):

```bash
pip install "hayward[sign]"
hayward verify org/name ./downloaded-snapshot
```

Every week this repo scans the most downloaded models with `hayward hub` at their
current commit, signs each verdict with Sigstore, and publishes it. A verdict is
analysis evidence, not a safety certificate.

## What gets published

- A repo with **no flagged file** is published, with each file's verdict: `clean`,
  `not_verified` (not fully read) or `remote_code` (runs the repo's own Python).
- A repo with a **flagged** file is withheld. It is reviewed by a person first, so a
  false alarm is fixed in Hayward instead, and a real finding is reported privately
  to Hugging Face. A signed "withheld" marker after a 30-day disclosure window is
  planned, not built yet.
- So "no published verdict" means not scanned yet, or withheld. It is never a pass.
- Verdicts are re-signed weekly and stop counting after 30 days.

## Why you can trust a verdict

- **One signer.** Verdicts are signed by `.github/workflows/scan.yml` on `main`,
  started by its weekly schedule. `hayward verify` accepts nothing else: not a manual
  run, not a pull request, not another workflow.
- **Tied to the exact commit.** Each verdict names the repo and commit, and its file
  hashes must match the Hub's.
- **Least privilege.** Scanning (which reads untrusted files) holds only a read-only
  Hugging Face token. Signing holds only its identity token and re-checks every verdict
  against the Hub first. Deploying holds only a keyless login to an isolated Google
  project. No third-party actions; every action is GitHub's own, pinned by commit.
- **Reviewed changes.** `main` is protected: every change needs an approving review.

## Reporting a problem

Use [private vulnerability reporting](https://github.com/hedgerow-dev/hayward-verify/security/advisories/new).
