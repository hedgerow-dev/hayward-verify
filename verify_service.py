"""The hayward-verify service: scan popular Hub models, sign the verdicts, publish them.

    python verify_service.py scan --top 100 --out out          (job 1: HF_TOKEN only)
    python verify_service.py sign --top 100 --scanned scanned.json out site
                                                                (job 2: OIDC identity only)
    python verify_service.py deploy --top 100 --scanned scanned.json site
                                                                (job 3: keyless Google login only)

    python verify_service.py monitor                            (anyone: check the checkpoint chain)

Each deploy keeps the verdicts already published, except those of repos this run
scanned: for those, only what this run signed counts, so a rescan that withholds a
repo also takes down its older verdicts.

The verdict log (hayward docs/specs/verdict-log.md): each receipt is also published
under its own SHA-256, and every file hash is indexed in one of 256 shards. Each run
signs one checkpoint naming the shards and the previous checkpoint; a verdict is
current while a checkpoint lists it. The sign job verifies the published checkpoint
before it signs the next, and refuses to sign if it does not verify.

Each step runs in its own job with only the credential it needs. Scanning handles
untrusted model files, so it holds no signing or deploy credential; signing re-checks
every receipt against the Hub before it signs, so a compromised scan job cannot get a
receipt signed for files that are not in the repo, and never signs a flagged one.

Publishing policy: a repo with no flagged file is published (clean, not_verified and
remote_code verdicts all show as such). A repo with a flagged file is withheld; its
details go only into an age-encrypted report for review, never into the logs. Logs and
anything printed carry counts only.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

HUB = "https://huggingface.co"
REVIEW_KEY = Path(__file__).with_name("review.age.pub")
SCAN_TIMEOUT_SECONDS = 900
SCANNER_IMAGE = "hayward-verify-scanner:local"  # built from ./Dockerfile by the workflow
TOP_SLACK = 20
PUBLISHABLE = frozenset({"clean", "not_verified", "remote_code"})
ENTRY_KEYS = ("verdict", "rules", "coverage_gaps", "read", "hash_source")
RULE_RE = re.compile(r"MFV-[A-Z0-9]+-[0-9]{3}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
REPORT_BLOCK = 256 * 1024  # the withheld report is padded to a multiple of this
CHECKPOINT_TYPE = "https://hedgerow.dev/hayward/checkpoint/v1"
# A verdict not rescanned stays in the checkpoint this long after its scan: the same
# limit the client puts on a per-repo bundle.
KEEP_DAYS = 30

GCP_PROJECT_NUMBER = "1036350257376"
WIF_PROVIDER = (f"//iam.googleapis.com/projects/{GCP_PROJECT_NUMBER}/locations/global/"
                "workloadIdentityPools/github/providers/github")
DEPLOY_ACCOUNT = "verify-deploy@hedgerow-verify.iam.gserviceaccount.com"
SITE = "hedgerow-verify"
HOSTING = "https://firebasehosting.googleapis.com/v1beta1"
POPULATE_BATCH = 1000  # file hashes per populateFiles request, the limit Firebase's deploy guide gives


def _http(url: str, data: bytes | None = None, headers: dict | None = None, method: str | None = None) -> bytes:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("refusing a non-https URL")
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)  # noqa: S310 - https checked
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - same
        return resp.read()


def _json(url: str, body: dict | None = None, token: str | None = None, method: str | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    return json.loads(_http(url, data, headers, method) or b"{}")


# ---- job 1: scan -------------------------------------------------------------------------

def top_repos(count: int) -> list[str]:
    models = _json(f"{HUB}/api/models?sort=downloads&direction=-1&limit={count}")
    return [str(m["id"]) for m in models if isinstance(m, dict) and "id" in m]


def scan_repo(repo: str, work: Path) -> dict | None:
    """Run `hayward hub` on one repo in a throwaway container; return its receipt, or None.

    The container is read-only, runs as nobody with every capability dropped, sees only
    this repo's empty work folder, and gets no environment but the read-only Hugging Face
    token, so a model that exploited the scanner could not reach another repo's verdict,
    the workflow's files, or the next scan. Its output is discarded: it names files and
    repos, and a withheld repo must not appear in a public log.
    """
    out, scratch = work / "out", work / "tmp"
    for folder in (out, scratch):
        folder.mkdir(parents=True)
        folder.chmod(0o777)  # written by the container's nobody user
    cmd = ["docker", "run", "--rm", "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--pids-limit", "256", "--memory", "6g",
           "--user", "65534:65534", "-v", f"{out}:/work", "-v", f"{scratch}:/tmp",
           "-e", "HF_TOKEN", "-e", "HOME=/tmp", SCANNER_IMAGE,
           "hub", repo, "--receipt", "/work/receipt.json", "--quiet"]
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HF_TOKEN": os.environ.get("HF_TOKEN", "")}
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,  # noqa: S603 - fixed argv
                                env=env, timeout=SCAN_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired:
        return None
    receipt = out / "receipt.json"
    if result.returncode not in (0, 1) or not receipt.is_file():
        return None
    statement = json.loads(receipt.read_text(encoding="utf-8"))
    source = statement.get("predicate", {}).get("source", {})
    return statement if source.get("repo") == repo else None


def verdicts(statement: dict) -> list[str]:
    return [str(entry.get("verdict")) for entry in statement["predicate"]["files"].values()]


def encrypt_for_review(report: list[dict], out: Path) -> None:
    """age-encrypt the withheld report to the reviewer's public key. Fails closed: without
    the key nothing is written, since a plaintext report would leak in a public artifact."""
    key = REVIEW_KEY.read_text(encoding="utf-8").strip()
    if not key.startswith("age1"):
        raise SystemExit("review.age.pub is not an age public key; refusing to write the report")
    body = json.dumps(report).encode()
    body = body.ljust((len(body) // REPORT_BLOCK + 1) * REPORT_BLOCK)  # whole blocks of spaces
    subprocess.run(["age", "-r", key, "-o", str(out)], input=body,  # noqa: S603, S607 - fixed argv
                   check=True)


def cmd_scan(args: argparse.Namespace) -> int:
    out = Path(args.out)
    published, withheld, failed = 0, [], 0
    with tempfile.TemporaryDirectory(prefix="verify-") as tmp:
        repos = top_repos(args.top)
        for index, repo in enumerate(repos):
            statement = scan_repo(repo, Path(tmp) / str(index))
            if statement is None:
                failed += 1
                continue
            sha = statement["predicate"]["source"]["revision"]
            if "flagged" in verdicts(statement):
                withheld.append({"repo": repo, "revision": sha, "files": statement["predicate"]["files"]})
                continue
            dest = out / "v1" / "hf" / repo / f"{sha}.intoto.json"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(json.dumps(statement, indent=1) + "\n", encoding="utf-8")
            published += 1
    # Always written, and padded, so neither its presence nor its size says whether
    # anything was withheld.
    encrypt_for_review(withheld, out.parent / "withheld.json.age")
    # Every repo this run scanned, withheld or not: deploy drops their older verdicts.
    # The same public top-N list, so it names nothing the site does not.
    (out.parent / "scanned.json").write_text(json.dumps(repos), encoding="utf-8")
    # The total only: a split into published, withheld and failed, set against the
    # public site and the public top-N list, would name the withheld repos.
    print(f"scanned {published + len(withheld) + failed} repo(s)")
    return 0


# ---- job 2: sign -------------------------------------------------------------------------

def hub_hashes(repo: str, sha: str) -> dict[str, str | None]:
    quoted = urllib.parse.quote(repo, safe="/")
    for attempt in range(5):
        try:
            info = _json(f"{HUB}/api/models/{quoted}/revision/{sha}?blobs=true")
            break
        except urllib.error.HTTPError as exc:
            if exc.code != 429 or attempt == 4:
                raise
            time.sleep(10 * 2 ** attempt)
    if info.get("sha") != sha:
        raise ValueError(f"the Hub did not confirm commit {sha[:12]} of {repo}")
    return {str(s.get("rfilename", "")): (s.get("lfs") or {}).get("sha256") for s in info.get("siblings", [])}


def canonical(statement: dict, version: str, now: datetime) -> dict:
    """Rebuild a receipt from an allowlist of fields, checking each one, or raise ValueError.

    The scan job read untrusted files, so nothing it wrote is signed as is: only these
    fields, in these shapes, from a scan with this very Hayward, made in the last day.
    """
    from hayward import hub, receipt

    def need(ok: bool) -> None:
        if not ok:
            raise ValueError("receipt does not have the expected shape")

    need(statement.get("_type") == receipt.STATEMENT_TYPE
         and statement.get("predicateType") == receipt.PREDICATE_TYPE)
    predicate = statement["predicate"]
    source, scanner = predicate["source"], predicate["scanner"]
    repo, sha = source["repo"], source["revision"]
    need(source.get("host") == "huggingface.co" and isinstance(repo, str) and isinstance(sha, str))
    need(bool(hub.REPO_RE.fullmatch(repo)) and bool(hub.COMMIT_RE.fullmatch(sha)))
    need(scanner.get("name") == "hayward" and scanner.get("version") == version)
    settings = scanner.get("settings")
    need(isinstance(settings, dict) and set(settings) == {"check_signatures", "max_scan_bytes"}
         and isinstance(settings["check_signatures"], bool) and isinstance(settings["max_scan_bytes"], int))
    scanned = datetime.fromisoformat(predicate["scanned"])
    need(scanned.tzinfo is not None and now - timedelta(days=1) <= scanned <= now + timedelta(minutes=5))
    subjects = statement["subject"]
    need(isinstance(subjects, list) and bool(subjects))
    names = [s["name"] for s in subjects]
    need(len(set(names)) == len(names) and all(isinstance(n, str) and hub._safe_relative(n) for n in names))
    digests = [s["digest"]["sha256"] for s in subjects]
    need(all(isinstance(d, str) and SHA256_RE.fullmatch(d) for d in digests))
    files = predicate["files"]
    need(isinstance(files, dict) and set(files) == set(names))
    entries = {}
    for name, entry in files.items():
        need(set(entry) <= set(ENTRY_KEYS))
        need(entry.get("verdict") in PUBLISHABLE)
        for key in ("rules", "coverage_gaps"):
            rules = entry.get(key)
            need(isinstance(rules, list) and all(isinstance(r, str) and RULE_RE.fullmatch(r) for r in rules))
        need(entry.get("read", "header") in ("header", "pickle members") and entry.get("hash_source", "hub") == "hub")
        entries[name] = {k: entry[k] for k in ENTRY_KEYS if k in entry}
    return {
        "_type": receipt.STATEMENT_TYPE,
        "subject": [{"name": s["name"], "digest": {"sha256": s["digest"]["sha256"]}} for s in subjects],
        "predicateType": receipt.PREDICATE_TYPE,
        "predicate": {
            "scanner": {"name": "hayward", "version": version,
                        "settings": {"check_signatures": settings["check_signatures"],
                                     "max_scan_bytes": settings["max_scan_bytes"]}},
            "scanned": scanned.isoformat(timespec="seconds"),
            "note": receipt.NOTE,
            "files": entries,
            "source": {"host": "huggingface.co", "repo": repo, "revision": sha},
        },
    }


def cmd_sign(args: argparse.Namespace) -> int:
    from hayward import __version__, receipt, verify

    src, site = Path(args.src), Path(args.site)
    # Fetched here, not read from the scan job: a compromised scan could otherwise get
    # a receipt for any repo signed, such as an attacker's own. A little slack covers
    # the list moving in the minutes between the two jobs.
    allowed = set(top_repos(args.top + TOP_SLACK))
    now = datetime.now(timezone.utc)
    to_sign, refused = [], 0
    for path in sorted(src.rglob("*")):
        if not path.is_file():
            continue
        try:
            if not path.name.endswith(".intoto.json"):
                raise ValueError("unexpected file")
            statement = canonical(json.loads(path.read_bytes()), __version__, now)
            repo, sha = statement["predicate"]["source"]["repo"], statement["predicate"]["source"]["revision"]
            if repo not in allowed or path.relative_to(src).as_posix() != f"v1/hf/{repo}/{sha}.intoto.json":
                raise ValueError("receipt is not where its repo and commit say")
            if verify.check(statement, repo, sha, hub_hashes(repo, sha)):
                raise ValueError("receipt does not match the Hub")
        except (ValueError, KeyError, TypeError, AttributeError):
            refused += 1
            continue
        to_sign.append((repo, sha, statement))
    if refused:
        # A count only: a refused receipt means the scan job was compromised or broken,
        # and its path could name a withheld repo. Nothing is signed.
        raise SystemExit(f"refused {refused} receipt(s); nothing signed")
    try:
        previous = previous_checkpoint()
    except (ValueError, KeyError, TypeError, receipt.SignatureError, urllib.error.URLError) as exc:
        raise SystemExit(f"the published checkpoint does not verify ({exc}); nothing signed") from None
    # Every repo this run scanned, from the scan job's list and today's: for those, only
    # what this run signed is current, so a rescan that withholds a repo withdraws it.
    rescanned = allowed | set(json.loads(Path(args.scanned).read_text(encoding="utf-8")))
    entries = current(previous[2] if previous else {}, rescanned, now, __version__)
    run = previous[0] + 1 if previous else 0
    if fetch_public(f"v1/checkpoints/{run}.sigstore.json") is not None:
        # head.json is behind what is published: signing would replace a checkpoint.
        raise SystemExit(f"checkpoint {run} is already published; nothing signed")
    for repo, sha, statement in to_sign:
        raw = (json.dumps(statement, indent=1) + "\n").encode()
        digest = hashlib.sha256(raw).hexdigest()
        write(site / "v1" / "receipts" / f"{digest}.json", raw)
        write(site / "v1" / "hf" / repo / f"{sha}.json", json.dumps({"receipt": digest}).encode())
        write(site / "v1" / "hf" / repo / f"{sha}.sigstore.json", receipt._sigstore_sign(raw).encode())
        predicate = statement["predicate"]
        for subject in statement["subject"]:
            name = subject["name"]
            entries.setdefault(subject["digest"]["sha256"], []).append({
                "receipt": digest, "repo": repo, "commit": sha, "name": name,
                "scanned": predicate["scanned"], "scanner": predicate["scanner"]["version"],
                **predicate["files"][name]})
    subjects = []
    for prefix, body in shards(entries).items():
        shard = hashlib.sha256(body).hexdigest()
        write(site / "v1" / "shards" / f"{shard}.json", body)
        subjects.append({"name": prefix, "digest": {"sha256": shard}})
    checkpoint = {
        "_type": receipt.STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": CHECKPOINT_TYPE,
        "predicate": {"run": run, "previous": previous[1] if previous else None,
                      "signed": now.isoformat(timespec="seconds"),
                      "scanner": {"name": "hayward", "version": __version__}},
    }
    raw = (json.dumps(checkpoint, indent=1) + "\n").encode()
    write(site / "v1" / "checkpoints" / f"{run}.sigstore.json", receipt._sigstore_sign(raw).encode())
    write(site / "v1" / "head.json", json.dumps({"checkpoint": run}).encode())
    print(f"signed {len(to_sign)} verdict(s) and checkpoint {run}")
    return 0


def write(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)


def fetch_public(path: str) -> bytes | None:
    """A file from the published site, or None when it is not there."""
    from hayward import verify

    try:
        return _http(f"{verify.SERVICE}/{path}")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def open_checkpoint(raw: bytes) -> tuple[bytes, dict]:
    """The signed payload and statement of a checkpoint bundle, or raise: it must be
    signed by this service's own scheduled workflow, as the client requires."""
    from hayward import receipt, verify

    payload = receipt._sigstore_open(raw, verify.IDENTITY, verify.ISSUER, verify.TRIGGER,
                                     verify.REPOSITORY_ID, verify.OWNER_ID)
    statement = json.loads(payload)
    if statement.get("_type") != receipt.STATEMENT_TYPE or statement.get("predicateType") != CHECKPOINT_TYPE:
        raise ValueError("not a checkpoint")
    return payload, statement


def previous_checkpoint() -> tuple[int, str, dict[str, list[dict]]] | None:
    """The run number, payload digest and entries of the published checkpoint, or None
    before the first one. Raises if what is published does not verify."""
    head = fetch_public("v1/head.json")
    if head is None:
        return None
    run = json.loads(head)["checkpoint"]
    if not valid_run(run):
        raise ValueError("head.json does not name a checkpoint")
    raw = fetch_public(f"v1/checkpoints/{run}.sigstore.json")
    if raw is None:
        raise ValueError("head.json names a missing checkpoint")
    payload, statement = open_checkpoint(raw)
    if statement["predicate"]["run"] != run:
        raise ValueError("the checkpoint is not the one head.json names")
    entries: dict[str, list[dict]] = {}
    for shard in {s["digest"]["sha256"] for s in statement["subject"]}:
        body = fetch_public(f"v1/shards/{shard}.json")
        if body is None or hashlib.sha256(body).hexdigest() != shard:
            raise ValueError("a shard does not match the checkpoint")
        entries.update(json.loads(body))
    return run, hashlib.sha256(payload).hexdigest(), entries


def valid_run(run: object) -> bool:
    return isinstance(run, int) and not isinstance(run, bool) and run >= 0


def current(entries: dict[str, list[dict]], rescanned: set[str], now: datetime,
            version: str) -> dict[str, list[dict]]:
    """The entries that stay current: not of a repo scanned this run, scanned in the last
    KEEP_DAYS days, and by this Hayward, so a release with new rules never vouches for a
    verdict it did not reach."""
    kept = {}
    for digest, items in entries.items():
        left = [e for e in items if e["repo"] not in rescanned and e["scanner"] == version
                and now - datetime.fromisoformat(e["scanned"]) <= timedelta(days=KEEP_DAYS)]
        if left:
            kept[digest] = left
    return kept


def shards(entries: dict[str, list[dict]]) -> dict[str, bytes]:
    """The 256 shard files, by the first two hex digits of the file hashes they hold."""
    by_prefix: dict[str, dict] = {f"{i:02x}": {} for i in range(256)}
    for digest, items in entries.items():
        by_prefix[digest[:2]][digest] = sorted(items, key=lambda e: (e["repo"], e["commit"], e["name"]))
    return {prefix: json.dumps(held, sort_keys=True, separators=(",", ":")).encode()
            for prefix, held in by_prefix.items()}


def cmd_monitor(args: argparse.Namespace) -> int:
    """Walk the published checkpoints from head back to 0: each must verify, carry its
    own run number, and be the one its successor names. Anyone can run this. With
    --known FILE it also keeps each checkpoint's digest from earlier runs, so a chain
    rewritten as a whole, or a head that went back, is caught too."""
    from hayward import receipt

    head = fetch_public("v1/head.json")
    if head is None:
        print("no checkpoint published")
        return 1
    try:
        top = json.loads(head)["checkpoint"]
    except (ValueError, KeyError, TypeError):
        top = None
    if not valid_run(top):
        print("problem: head.json does not name a checkpoint")
        return 1
    known_path = Path(args.known) if getattr(args, "known", None) else None
    known = json.loads(known_path.read_text(encoding="utf-8")) if known_path and known_path.is_file() else {}
    problems, named = [], None  # named: the payload digest the later checkpoint expects
    if any(int(run) > top for run in known):
        problems.append(f"head went back to checkpoint {top}")
    for run in range(top, -1, -1):
        raw = fetch_public(f"v1/checkpoints/{run}.sigstore.json")
        if raw is None:
            problems.append(f"checkpoint {run} is missing")
            named = None
            continue
        try:
            payload, statement = open_checkpoint(raw)
            predicate = statement["predicate"]
            if predicate["run"] != run:
                problems.append(f"checkpoint {run} says it is run {predicate['run']}")
            if named is not None and hashlib.sha256(payload).hexdigest() != named:
                problems.append(f"checkpoint {run} is not the one checkpoint {run + 1} names")
            named = predicate["previous"]
            digest = hashlib.sha256(payload).hexdigest()
            if known.get(str(run), digest) != digest:
                problems.append(f"checkpoint {run} changed since it was last seen")
            known[str(run)] = digest
            if run == 0 and named is not None:
                problems.append("checkpoint 0 names a previous one")
        except (ValueError, KeyError, TypeError, receipt.SignatureError) as exc:
            problems.append(f"checkpoint {run} does not verify: {exc}")
            named = None
    for problem in problems:
        print(f"problem: {problem}")
    if problems:
        return 1
    if known_path:
        known_path.write_text(json.dumps(known, indent=1, sort_keys=True), encoding="utf-8")
    print(f"chain intact: {top + 1} checkpoint(s)")
    return 0


# ---- job 3: deploy -----------------------------------------------------------------------

def google_token() -> str:
    """GitHub OIDC token -> Google STS -> short-lived token for the deploy account. Never printed."""
    request_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    audience = "https:" + WIF_PROVIDER
    github = json.loads(_http(f"{request_url}&audience={urllib.parse.quote(audience)}", headers={
        "Authorization": f"bearer {os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}"}))["value"]
    federated = _json("https://sts.googleapis.com/v1/token", {
        "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
        "audience": WIF_PROVIDER,
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
        "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
        "subjectToken": github,
    })["access_token"]
    return _json(f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{DEPLOY_ACCOUNT}:generateAccessToken",
                 {"scope": ["https://www.googleapis.com/auth/cloud-platform"], "lifetime": "900s"},
                 token=federated)["accessToken"]


def site_files(site: Path) -> dict[str, bytes]:
    """Every file to publish, keyed by its URL path, gzipped as the Hosting API expects."""
    files = {}
    for path in sorted(p for p in site.rglob("*") if p.is_file()):
        files["/" + path.relative_to(site).as_posix()] = gzip.compress(path.read_bytes(), mtime=0)
    return files


def live_files(token: str) -> dict[str, str]:
    """Path -> hash of every file the site serves now; empty before the first release."""
    release = _json(f"{HOSTING}/sites/{SITE}/channels/live", token=token).get("release") or {}
    version = (release.get("version") or {}).get("name")
    files, page = {}, ""
    while version:
        listing = _json(f"{HOSTING}/{version}/files?status=ACTIVE&pageSize=1000"
                        + (f"&pageToken={urllib.parse.quote(page)}" if page else ""), token=token)
        files.update({f["path"]: f["hash"] for f in listing.get("files", [])})
        page = listing.get("nextPageToken")
        if not page:
            break
    return files


def carried(live: dict[str, str], rescanned: set[str]) -> dict[str, str]:
    """The live files to keep: all but the verdicts of repos in this run's list. A repo
    in the list was scanned again, so only what this run signed counts for it, and an
    older verdict cannot outlive a scan that withheld the repo."""
    def repo(path: str) -> str | None:
        parts = path.split("/")
        return "/".join(parts[3:5]) if parts[1:3] == ["v1", "hf"] and len(parts) > 5 else None
    return {path: digest for path, digest in live.items() if repo(path) not in rescanned}


def cmd_deploy(args: argparse.Namespace) -> int:
    files = site_files(Path(args.site))
    # The scan job's own list, plus today's with the sign job's slack in case the scan
    # list is missing a name: dropping a repo it did not scan only removes a verdict,
    # never keeps one.
    rescanned = set(json.loads(Path(args.scanned).read_text(encoding="utf-8")))
    rescanned |= set(top_repos(args.top + TOP_SLACK))
    token = google_token()
    keep = carried(live_files(token), rescanned)
    for path in [p for p in files if p in keep]:
        if path.startswith(("/v1/receipts/", "/v1/shards/")):
            del files[path]  # named by its content, so the live copy is the same file
        elif path.startswith("/v1/checkpoints/"):
            raise SystemExit("this run would replace a published checkpoint; nothing released")
    version = _json(f"{HOSTING}/sites/{SITE}/versions", {"config": {"headers": [
        {"glob": "**", "headers": {"Cache-Control": "max-age=300", "X-Content-Type-Options": "nosniff",
                                   "Access-Control-Allow-Origin": "*"}}]}}, token=token)["name"]
    by_hash = {hashlib.sha256(body).hexdigest(): body for body in files.values()}
    wanted = {**keep, **{path: hashlib.sha256(body).hexdigest() for path, body in files.items()}}
    paths = sorted(wanted)
    for start in range(0, len(paths), POPULATE_BATCH):
        batch = {path: wanted[path] for path in paths[start:start + POPULATE_BATCH]}
        populated = _json(f"{HOSTING}/{version}:populateFiles", {"files": batch}, token=token)
        # Carried files are already on the site, so only this run's files can be asked for.
        for digest in populated.get("uploadRequiredHashes", []):
            if digest not in by_hash:
                raise SystemExit("Hosting asked to re-upload a kept file; nothing released")
            _http(f"{populated['uploadUrl']}/{digest}", by_hash[digest],
                  {"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"}, "POST")
    _json(f"{HOSTING}/{version}?update_mask=status", {"status": "FINALIZED"}, token=token, method="PATCH")
    _json(f"{HOSTING}/sites/{SITE}/releases?versionName={urllib.parse.quote(version, safe='/')}", {}, token=token)
    print(f"deployed {len(files)} new file(s), kept {len(keep)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("--top", type=int, default=100)
    scan.add_argument("--out", required=True)
    sign = sub.add_parser("sign")
    sign.add_argument("--top", type=int, default=100)
    sign.add_argument("--scanned", required=True, help="scanned.json from the scan job")
    sign.add_argument("src")
    sign.add_argument("site")
    deploy = sub.add_parser("deploy")
    deploy.add_argument("--top", type=int, default=100)
    deploy.add_argument("--scanned", required=True, help="scanned.json from the scan job")
    deploy.add_argument("site")
    monitor = sub.add_parser("monitor", help="check the published checkpoint chain")
    monitor.add_argument("--known", help="a file of checkpoint digests seen before, kept up to date")
    args = parser.parse_args(argv)
    return {"scan": cmd_scan, "sign": cmd_sign, "deploy": cmd_deploy, "monitor": cmd_monitor}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
