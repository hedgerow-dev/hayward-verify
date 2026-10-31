# hayward-verify

Signed scan verdicts for popular Hugging Face models, published at
**verify.hedgerow.dev** and checked by [Hayward](https://github.com/hedgerow-dev/hayward):

```bash
pip install "hayward[sign]"
hayward verify org/name ./downloaded-snapshot
```

Every 6 hours this repo scans the most downloaded models with `hayward hub` at their
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
- Verdicts are re-signed every 6 hours and stop counting after 30 days.

## New uploads (dry run)

A second workflow scans the model repos changed on the Hub in the last 6 hours, in
8 shards, with the same locked-down containers. It signs and publishes nothing yet:
it measures run time and the Hub's rate limits first. A flagged repo goes only into
the encrypted review report. Past 20 repos in a run, an uploader's repos wait at the
back of the queue, so one account cannot crowd out the rest.

## The verdict log

Each run also signs one **checkpoint**: the list of verdicts that are current, indexed
by file SHA-256, naming the checkpoint before it. Everything it points to is stored
under its own hash, so nothing can be edited in place, and every checkpoint is in
Sigstore's public log. Check the chain yourself:

```bash
python verify_service.py monitor --known known.json
```

`--known` keeps each checkpoint's digest between runs, so a chain rewritten as a
whole, or a head that went back, is caught too.

- `v1/head.json`: the latest checkpoint number.
- `v1/checkpoints/N.sigstore.json`: checkpoint N, signed.
- `v1/shards/SHA256.json`: file hash to verdicts, one of 256 shards.
- `v1/receipts/SHA256.json`: a scan receipt, by the hash of its bytes.

A verdict is current while a checkpoint lists it. A rescan replaces a repo's verdicts.
A verdict that is not rescanned drops out 30 days after its scan, or at once when the
service moves to a new Hayward release, since the old scan never ran its new rules.

## Why you can trust a verdict

- **One signer.** Verdicts are signed by `.github/workflows/scan.yml` on `main`,
  started by its schedule. `hayward verify` accepts nothing else: not a manual
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
