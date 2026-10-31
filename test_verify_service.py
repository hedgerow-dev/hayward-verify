"""Offline tests for the service script: the Hub, Sigstore, age and Google are faked."""

from __future__ import annotations

import gzip
import json
import shutil
from argparse import Namespace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from hayward import __version__, receipt

import verify_service as vs

SHA = "a" * 40
LFS = "b" * 64


def statement(repo: str, verdict: str = "clean", sha: str = SHA, hours_old: int = 1) -> dict:
    scanned = (datetime.now(timezone.utc) - timedelta(hours=hours_old)).isoformat(timespec="seconds")
    return {
        "_type": receipt.STATEMENT_TYPE,
        "predicateType": receipt.PREDICATE_TYPE,
        "subject": [{"name": "model.safetensors", "digest": {"sha256": LFS}}],
        "predicate": {"scanner": {"name": "hayward", "version": __version__,
                                  "settings": {"check_signatures": False, "max_scan_bytes": 500_000_000}},
                      "scanned": scanned, "note": receipt.NOTE,
                      "source": {"host": "huggingface.co", "repo": repo, "revision": sha},
                      "files": {"model.safetensors": {"verdict": verdict, "rules": [], "coverage_gaps": []}}},
    }


# ---- scan --------------------------------------------------------------------------------

@pytest.fixture
def scanned(monkeypatch, tmp_path):
    results = {"org/clean": statement("org/clean"),
               "org/code": statement("org/code", "remote_code"),
               "evil/secret": statement("evil/secret", "flagged"),
               "org/broken": None}
    encrypted = {}
    monkeypatch.setattr(vs, "top_repos", lambda n: list(results))
    monkeypatch.setattr(vs, "scan_repo", lambda repo, work: results[repo])
    monkeypatch.setattr(vs, "encrypt_for_review", lambda report, out: encrypted.update(report=report, out=out))
    out = tmp_path / "out"
    return out, encrypted


def test_scan_publishes_everything_but_flagged_repos(scanned, capsys):
    out, encrypted = scanned
    assert vs.cmd_scan(Namespace(top=4, out=str(out))) == 0
    written = sorted(p.relative_to(out).as_posix() for p in out.rglob("*.json"))
    assert written == [f"v1/hf/org/clean/{SHA}.intoto.json", f"v1/hf/org/code/{SHA}.intoto.json"]
    assert [w["repo"] for w in encrypted["report"]] == ["evil/secret"]
    scanned_list = json.loads((out.parent / "scanned.json").read_text())
    assert scanned_list == ["org/clean", "org/code", "evil/secret", "org/broken"]


def test_a_repo_with_nothing_scannable_is_not_written(monkeypatch, tmp_path):
    # e.g. only GGUF files over the size cap, or only YAML: the receipt lists no file.
    # The sign job refuses an empty receipt and then signs nothing, so it must not get one.
    empty = statement("org/empty")
    empty["subject"], empty["predicate"]["files"] = [], {}
    results = {"org/clean": statement("org/clean"), "org/empty": empty}
    monkeypatch.setattr(vs, "top_repos", lambda n: list(results))
    monkeypatch.setattr(vs, "scan_repo", lambda repo, work: results[repo])
    monkeypatch.setattr(vs, "encrypt_for_review", lambda report, out: None)
    out = tmp_path / "out"
    vs.cmd_scan(Namespace(top=2, out=str(out)))
    assert [p.relative_to(out).as_posix() for p in out.rglob("*.json")] == [f"v1/hf/org/clean/{SHA}.intoto.json"]


def test_scan_logs_never_name_a_withheld_repo(scanned, capsys):
    out, _ = scanned
    vs.cmd_scan(Namespace(top=4, out=str(out)))
    printed = capsys.readouterr()
    assert "evil" not in printed.out + printed.err
    # only the total: a split would name withheld repos by subtraction
    assert printed.out.strip() == "scanned 4 repo(s)"


def test_the_withheld_report_is_never_written_without_a_key(monkeypatch, tmp_path):
    key = tmp_path / "review.age.pub"
    key.write_text("not a key")
    monkeypatch.setattr(vs, "REVIEW_KEY", key)
    with pytest.raises(SystemExit):
        vs.encrypt_for_review([{"repo": "evil/secret"}], tmp_path / "w.age")
    assert not (tmp_path / "w.age").exists()


def test_a_receipt_for_another_repo_is_not_trusted(monkeypatch, tmp_path):
    def fake_run(cmd, **kwargs):
        (tmp_path / "0" / "out" / "receipt.json").write_text(json.dumps(statement("other/repo")))
        return Namespace(returncode=0)

    monkeypatch.setattr(vs.subprocess, "run", fake_run)
    assert vs.scan_repo("org/clean", tmp_path / "0") is None


def test_a_receipt_that_covers_no_files_is_not_published(monkeypatch, tmp_path):
    # A repo whose files were all too big to scan, or that holds no model files: the
    # sign job refuses an empty receipt, and one refusal blocks every verdict in the run.
    def fake_run(cmd, **kwargs):
        empty = statement("org/clean")
        empty["subject"], empty["predicate"]["files"] = [], {}
        (tmp_path / "0" / "out" / "receipt.json").write_text(json.dumps(empty))
        return Namespace(returncode=0)

    monkeypatch.setattr(vs.subprocess, "run", fake_run)
    assert vs.scan_repo("org/clean", tmp_path / "0") is None


def test_each_scan_runs_in_a_locked_down_container(monkeypatch, tmp_path):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs, cmd=cmd)
        return Namespace(returncode=2)

    monkeypatch.setenv("GITHUB_ENV", "/home/runner/env")
    monkeypatch.setenv("HF_TOKEN", "hf_x")
    monkeypatch.setattr(vs.subprocess, "run", fake_run)
    assert vs.scan_repo("org/x", tmp_path / "0") is None
    cmd = seen["cmd"]
    assert cmd[:3] == ["docker", "run", "--rm"]
    for flag in ("--read-only", "--cap-drop", "no-new-privileges", "65534:65534"):
        assert flag in cmd
    mounts = [cmd[i + 1] for i, part in enumerate(cmd) if part == "-v"]
    assert mounts == [f"{tmp_path / '0' / 'out'}:/work", f"{tmp_path / '0' / 'tmp'}:/tmp"]  # this repo's folder only
    assert set(seen["env"]) == {"PATH", "HF_TOKEN"}  # no GITHUB_ENV or other workflow files
    assert seen["stdout"] is vs.subprocess.DEVNULL and seen["stderr"] is vs.subprocess.DEVNULL


def test_the_withheld_report_is_always_written_and_padded(monkeypatch, tmp_path):
    sizes = []
    monkeypatch.setattr(vs.subprocess, "run", lambda cmd, input, check: sizes.append(len(input)))
    key = tmp_path / "review.age.pub"
    key.write_text("age1examplekey")
    monkeypatch.setattr(vs, "REVIEW_KEY", key)
    vs.encrypt_for_review([], tmp_path / "a")
    vs.encrypt_for_review([{"repo": "x/y", "files": {}}], tmp_path / "b")
    assert sizes[0] == sizes[1] == vs.REPORT_BLOCK


# ---- new uploads -------------------------------------------------------------------------

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)


def model(repo: str, minutes_ago: int, files=("model.safetensors", "config.json"), gated=False) -> dict:
    when = (NOW - timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", ".000Z")
    return {"id": repo, "lastModified": when, "gated": gated, "private": False,
            "siblings": [{"rfilename": f} for f in files]}


@pytest.fixture
def listing(monkeypatch):
    """The Hub's model listing, newest first, served in pages."""
    pages: list[list[dict]] = []
    urls: list[str] = []

    def page(url):
        urls.append(url)
        index = int(url.split("cursor=")[1]) if "cursor=" in url else 0
        nxt = f"{vs.HUB}/api/models?cursor={index + 1}" if index + 1 < len(pages) else None
        return json.dumps(pages[index]).encode(), nxt

    monkeypatch.setattr(vs, "_page", page)
    return pages, urls


def test_new_repos_lists_the_window_and_stops_at_its_edge(listing):
    pages, urls = listing
    pages += [[model("a/one", 5), model("b/two", 200)], [model("c/three", 380), model("d/old", 500)],
              [model("e/never", 600)]]
    assert vs.new_repos(6, NOW) == ["a/one", "b/two", "c/three"]  # 6 h plus 30 min slack
    assert len(urls) == 2 and "sort=lastModified" in urls[0] and "siblings" in urls[0]


def test_new_repos_skips_what_cannot_or_need_not_be_scanned(listing):
    pages, _ = listing
    pages.append([model("a/gated", 1, gated="manual"), model("a/docs", 2, files=("README.md", "logo.png")),
                  model("a/ok", 3)])
    assert vs.new_repos(6, NOW) == ["a/ok"]


def test_one_owner_cannot_crowd_out_the_rest(listing):
    # Past its share, an owner's repos wait at the back of the queue: none is dropped.
    pages, _ = listing
    pages.append([model(f"spam/r{i}", i) for i in range(vs.PER_OWNER_CAP + 5)] + [model("other/r", 50)])
    repos = vs.new_repos(6, NOW)
    assert len(repos) == vs.PER_OWNER_CAP + 6
    assert repos.index("other/r") == vs.PER_OWNER_CAP
    assert repos[-5:] == [f"spam/r{i}" for i in range(vs.PER_OWNER_CAP, vs.PER_OWNER_CAP + 5)]


def test_a_malformed_listing_entry_is_skipped(listing):
    pages, _ = listing
    pages.append(["junk", {"id": "a/b"}, {**model("c/d", 1), "siblings": None}, model("e/f", 2)])
    assert vs.new_repos(6, NOW) == ["e/f"]


def test_a_timed_out_container_is_killed(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            raise vs.subprocess.TimeoutExpired(cmd, 1)
        return vs.subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(vs.subprocess, "run", fake_run)
    assert vs.scan_repo("org/slow", tmp_path / "0") is None
    name = calls[0][calls[0].index("--name") + 1]
    assert calls[1] == ["docker", "kill", name]


def test_the_review_report_is_written_before_and_during_the_scan(scanned, monkeypatch):
    # A shard cut short by a timeout still leaves what it found.
    out, _ = scanned
    reports = []
    monkeypatch.setattr(vs, "encrypt_for_review", lambda report, path: reports.append([w["repo"] for w in report]))
    vs.cmd_scan(Namespace(top=4, out=str(out)))
    assert reports == [[], ["evil/secret"]]


def test_a_shard_scans_its_share_of_the_list(scanned, tmp_path, monkeypatch):
    out, _ = scanned
    repos = ["org/clean", "org/code", "evil/secret", "org/broken"]
    (tmp_path / "new.json").write_text(json.dumps(repos))
    monkeypatch.setattr(vs, "top_repos", lambda n: pytest.fail("a list was given"))
    seen = []
    real = vs.scan_repo
    monkeypatch.setattr(vs, "scan_repo", lambda repo, work: seen.append(repo) or real(repo, work))
    vs.cmd_scan(Namespace(top=100, out=str(out), repos=str(tmp_path / "new.json"), shard="1/2"))
    assert seen == ["org/code", "org/broken"]
    assert json.loads((out.parent / "scanned.json").read_text()) == seen


@pytest.mark.parametrize("bad", ["2/2", "-1/2", "0/0", "a/b", "1"])
def test_a_shard_must_be_i_of_n(bad):
    with pytest.raises(ValueError):
        vs.shard_of(["x"], bad)


# ---- sign --------------------------------------------------------------------------------

@pytest.fixture
def signing(monkeypatch, tmp_path):
    src, site = tmp_path / "out", tmp_path / "site"
    monkeypatch.setattr(vs, "hub_hashes", lambda repo, sha: {"model.safetensors": LFS})
    monkeypatch.setattr(vs, "top_repos", lambda n: ["org/clean", "evil/secret", "other/repo"])
    monkeypatch.setattr(receipt, "_sigstore_sign", lambda raw: json.dumps({"signed": raw.decode()}))
    monkeypatch.setattr(receipt, "_sigstore_open", lambda raw, *pins: json.loads(raw)["signed"].encode())
    (tmp_path / "scanned.json").write_text(json.dumps(["org/clean", "evil/secret", "other/repo"]))
    # The published site, as deploy leaves it: every run's files, carried forward.
    public = tmp_path / "public"
    monkeypatch.setattr(vs, "fetch_public", lambda path: (public / path).read_bytes()
                        if (public / path).is_file() else None)

    def put(repo, st, path=None):
        dest = src / (path or f"v1/hf/{repo}/{SHA}.intoto.json")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(st))

    return src, site, put


def test_sign_writes_a_bundle_where_the_client_looks(signing):
    src, site, put = signing
    put("org/clean", statement("org/clean"))
    assert vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site), scanned=str(src.parent / "scanned.json"))) == 0
    assert (site / f"v1/hf/org/clean/{SHA}.sigstore.json").is_file()


def test_sign_refuses_a_flagged_verdict(signing):
    src, site, put = signing
    put("evil/secret", statement("evil/secret", "flagged"))
    with pytest.raises(SystemExit):
        vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site), scanned=str(src.parent / "scanned.json")))
    assert not site.exists()


def test_sign_refuses_a_receipt_filed_under_another_repo(signing):
    src, site, put = signing
    put("org/clean", statement("other/repo"), path=f"v1/hf/org/clean/{SHA}.intoto.json")
    with pytest.raises(SystemExit):
        vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site), scanned=str(src.parent / "scanned.json")))


def test_sign_refuses_hashes_the_hub_does_not_confirm(signing, monkeypatch):
    src, site, put = signing
    put("org/clean", statement("org/clean"))
    monkeypatch.setattr(vs, "hub_hashes", lambda repo, sha: {"model.safetensors": "c" * 64})
    with pytest.raises(SystemExit):
        vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site), scanned=str(src.parent / "scanned.json")))


def sha256(body: bytes) -> str:
    return vs.hashlib.sha256(body).hexdigest()


def run_sign(signing, tmp_path, run: int, scanned: list[str]) -> Path:
    """Sign what is in the scan output into a fresh site, publish it, and clear the output."""
    src, _, _ = signing
    site = tmp_path / f"site{run}"
    (tmp_path / "scanned.json").write_text(json.dumps(scanned))
    vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site), scanned=str(tmp_path / "scanned.json")))
    shutil.copytree(site, tmp_path / "public", dirs_exist_ok=True)
    shutil.rmtree(src)
    return site


def checkpoint(site: Path, run: int) -> tuple[bytes, dict]:
    payload = json.loads((site / f"v1/checkpoints/{run}.sigstore.json").read_text())["signed"].encode()
    return payload, json.loads(payload)


def lookup(site: Path, run: int, digest: str) -> list[dict]:
    _, cp = checkpoint(site, run)
    shard = {s["name"]: s["digest"]["sha256"] for s in cp["subject"]}[digest[:2]]
    body = (site / f"v1/shards/{shard}.json").read_bytes()
    assert sha256(body) == shard
    return json.loads(body).get(digest, [])


def test_sign_publishes_the_receipt_by_digest_and_a_first_checkpoint(signing, tmp_path):
    _, _, put = signing
    put("org/clean", statement("org/clean"))
    site = run_sign(signing, tmp_path, 0, ["org/clean"])
    pointer = json.loads((site / f"v1/hf/org/clean/{SHA}.json").read_text())["receipt"]
    stored = (site / f"v1/receipts/{pointer}.json").read_bytes()
    assert sha256(stored) == pointer and json.loads(stored)["predicate"]["source"]["repo"] == "org/clean"
    assert json.loads((site / "v1/head.json").read_text()) == {"checkpoint": 0}
    _, cp = checkpoint(site, 0)
    assert cp["predicateType"] == vs.CHECKPOINT_TYPE
    assert [s["name"] for s in cp["subject"]] == [f"{i:02x}" for i in range(256)]
    assert cp["predicate"]["run"] == 0 and cp["predicate"]["previous"] is None
    [entry] = lookup(site, 0, LFS)
    assert entry["receipt"] == pointer and entry["verdict"] == "clean"
    assert (entry["repo"], entry["commit"], entry["name"]) == ("org/clean", SHA, "model.safetensors")


def test_the_next_checkpoint_links_back_and_keeps_repos_not_rescanned(signing, tmp_path, monkeypatch):
    _, _, put = signing
    put("org/clean", statement("org/clean"))
    first = run_sign(signing, tmp_path, 0, ["org/clean"])
    monkeypatch.setattr(vs, "top_repos", lambda n: ["other/repo"])  # org/clean left the top list
    put("other/repo", statement("other/repo"))
    second = run_sign(signing, tmp_path, 1, ["other/repo"])
    payload, _ = checkpoint(first, 0)
    _, cp = checkpoint(second, 1)
    assert cp["predicate"]["run"] == 1 and cp["predicate"]["previous"] == sha256(payload)
    assert {e["repo"] for e in lookup(second, 1, LFS)} == {"org/clean", "other/repo"}


def test_a_rescan_that_publishes_nothing_withdraws_the_old_entry(signing, tmp_path):
    # org/clean scanned again and withheld (no receipt): its older verdict is not current.
    _, _, put = signing
    put("org/clean", statement("org/clean"))
    run_sign(signing, tmp_path, 0, ["org/clean"])
    (tmp_path / "out").mkdir()
    second = run_sign(signing, tmp_path, 1, ["org/clean"])
    assert lookup(second, 1, LFS) == []


def test_an_entry_not_rescanned_drops_out_after_30_days():
    now = datetime.now(timezone.utc)
    old = {"repo": "a/b", "scanned": (now - timedelta(days=31)).isoformat()}
    fresh = {"repo": "c/d", "scanned": (now - timedelta(days=29)).isoformat()}
    old = {**old, "scanner": __version__}
    fresh = {**fresh, "scanner": __version__}
    assert vs.current({LFS: [old, fresh]}, set(), now, __version__) == {LFS: [fresh]}


def test_an_entry_from_another_hayward_is_not_carried_forward():
    # A release may add rules the old scan never ran; only a rescan puts it back.
    now = datetime.now(timezone.utc)
    entry = {"repo": "a/b", "scanned": now.isoformat(), "scanner": "0.0.1"}
    assert vs.current({LFS: [entry]}, set(), now, __version__) == {}


def test_sign_refuses_to_replace_a_published_checkpoint(signing, tmp_path):
    _, _, put = signing
    put("org/clean", statement("org/clean"))
    run_sign(signing, tmp_path, 0, ["org/clean"])
    # head.json rolled back, while checkpoint 0 stays published.
    (tmp_path / "public" / "v1" / "head.json").unlink()
    put("org/clean", statement("org/clean"))
    with pytest.raises(SystemExit, match="already published"):
        run_sign(signing, tmp_path, 1, ["org/clean"])


def test_sign_refuses_when_the_published_checkpoint_does_not_verify(signing, tmp_path, monkeypatch):
    _, _, put = signing
    put("org/clean", statement("org/clean"))
    run_sign(signing, tmp_path, 0, ["org/clean"])

    def forged(raw, *pins):
        raise receipt.SignatureError("not our signer")

    monkeypatch.setattr(receipt, "_sigstore_open", forged)
    put("org/clean", statement("org/clean"))
    with pytest.raises(SystemExit, match="nothing signed"):
        run_sign(signing, tmp_path, 1, ["org/clean"])
    assert not (tmp_path / "site1").exists()


def test_monitor_passes_an_intact_chain_and_flags_a_gap_or_an_edit(signing, tmp_path, capsys):
    _, _, put = signing
    for run in range(3):
        put("org/clean", statement("org/clean"))
        run_sign(signing, tmp_path, run, ["org/clean"])
    assert vs.cmd_monitor(Namespace()) == 0
    assert "3 checkpoint(s)" in capsys.readouterr().out
    public = tmp_path / "public" / "v1" / "checkpoints"
    edited = json.loads((public / "1.sigstore.json").read_text())
    edited["signed"] = edited["signed"].replace('"run": 1', '"run": 1, "x": 1')
    (public / "1.sigstore.json").write_text(json.dumps(edited))
    assert vs.cmd_monitor(Namespace()) == 1
    assert "checkpoint 1 is not the one checkpoint 2 names" in capsys.readouterr().out
    (public / "1.sigstore.json").unlink()
    assert vs.cmd_monitor(Namespace()) == 1
    assert "checkpoint 1 is missing" in capsys.readouterr().out


def test_monitor_remembers_digests_and_catches_a_rewrite_or_a_rollback(signing, tmp_path, capsys):
    _, _, put = signing
    for run in range(2):
        put("org/clean", statement("org/clean"))
        run_sign(signing, tmp_path, run, ["org/clean"])
    known = tmp_path / "known.json"
    assert vs.cmd_monitor(Namespace(known=str(known))) == 0
    record = json.loads(known.read_text())
    assert set(record) == {"0", "1"}
    known.write_text(json.dumps({**record, "0": "f" * 64}))
    assert vs.cmd_monitor(Namespace(known=str(known))) == 1
    assert "checkpoint 0 changed since it was last seen" in capsys.readouterr().out
    known.write_text(json.dumps({**record, "5": "f" * 64}))
    assert vs.cmd_monitor(Namespace(known=str(known))) == 1
    assert "head went back" in capsys.readouterr().out


def test_monitor_rejects_a_head_that_names_no_checkpoint(signing, tmp_path, capsys):
    public = tmp_path / "public" / "v1"
    public.mkdir(parents=True)
    for bad in ('{"checkpoint": "9"}', '{"checkpoint": true}', "[]", "nonsense"):
        (public / "head.json").write_text(bad)
        assert vs.cmd_monitor(Namespace()) == 1
    assert "does not name a checkpoint" in capsys.readouterr().out


# ---- deploy ------------------------------------------------------------------------------

def test_site_files_are_gzipped_under_their_url_paths(tmp_path):
    (tmp_path / "v1").mkdir()
    (tmp_path / "v1" / "x.json").write_text("{}")
    files = vs.site_files(tmp_path)
    assert list(files) == ["/v1/x.json"] and gzip.decompress(files["/v1/x.json"]) == b"{}"


def test_deploy_never_prints_a_token(monkeypatch, tmp_path, capsys):
    (tmp_path / "a.json").write_text("{}")
    (tmp_path / "scanned.json").write_text("[]")
    monkeypatch.setattr(vs, "top_repos", lambda n: [])
    monkeypatch.setattr(vs, "google_token", lambda: "SECRET-TOKEN")
    calls = []

    def fake_json(url, body=None, token=None, method=None):
        calls.append(url)
        if url.endswith("/versions"):
            return {"name": "sites/hedgerow-verify/versions/v1"}
        if url.endswith(":populateFiles"):
            return {"uploadRequiredHashes": list({vs.hashlib.sha256(gzip.compress(b"{}", mtime=0)).hexdigest()}),
                    "uploadUrl": "https://upload-firebasehosting.googleapis.com/upload/x"}
        return {}

    monkeypatch.setattr(vs, "_json", fake_json)
    monkeypatch.setattr(vs, "_http", lambda *a, **k: b"")
    assert vs.cmd_deploy(Namespace(site=str(tmp_path), top=100, scanned=str(tmp_path / "scanned.json"))) == 0
    assert "SECRET-TOKEN" not in capsys.readouterr().out
    assert any("releases" in c for c in calls)


def gz_hash(body: bytes) -> str:
    return vs.hashlib.sha256(gzip.compress(body, mtime=0)).hexdigest()


@pytest.fixture
def hosting(monkeypatch, tmp_path):
    """A fake Hosting API whose live version holds ``live`` (path -> hash), served in
    pages of two. Returns (site dir, live, populated batches, uploaded hashes)."""
    live: dict[str, str] = {}
    populated: list[dict] = []
    uploaded: list[str] = []
    monkeypatch.setattr(vs, "google_token", lambda: "t")
    monkeypatch.setattr(vs, "top_repos", lambda n: ["org/top"])
    (tmp_path / "scanned.json").write_text(json.dumps(["org/top"]))
    site = tmp_path / "site"
    site.mkdir()

    def fake_json(url, body=None, token=None, method=None):
        if url.endswith("/channels/live"):
            return {"release": {"version": {"name": "sites/s/versions/old"}}} if live else {}
        if "/versions/old/files?" in url:
            paths = sorted(live)
            start = int(url.split("pageToken=")[1]) if "pageToken=" in url else 0
            page = {"files": [{"path": p, "hash": live[p], "status": "uploaded"} for p in paths[start:start + 2]]}
            if start + 2 < len(paths):
                page["nextPageToken"] = str(start + 2)
            return page
        if url.endswith("/versions"):
            return {"name": "sites/s/versions/new"}
        if url.endswith(":populateFiles"):
            populated.append(body["files"])
            return {"uploadRequiredHashes": [h for h in body["files"].values() if h not in live.values()],
                    "uploadUrl": "https://upload-firebasehosting.googleapis.com/upload/x"}
        return {}

    def fake_http(url, data=None, headers=None, method=None):
        uploaded.append(url.rsplit("/", 1)[1])
        return b""

    monkeypatch.setattr(vs, "_json", fake_json)
    monkeypatch.setattr(vs, "_http", fake_http)
    return site, live, populated, uploaded


def deployed(populated: list[dict]) -> dict[str, str]:
    return {path: digest for batch in populated for path, digest in batch.items()}


def test_deploy_keeps_earlier_verdicts_without_uploading_them(hosting):
    site, live, populated, uploaded = hosting
    live.update({"/v1/hf/gone/repo/1.sigstore.json": "1" * 64, "/v1/hf/gone/repo/2.sigstore.json": "2" * 64,
                 "/v1/hf/gone/other/3.sigstore.json": "3" * 64})
    (site / "new.json").write_text("{}")
    assert vs.cmd_deploy(Namespace(site=str(site), top=100, scanned=str(site.parent / "scanned.json"))) == 0
    assert deployed(populated) == {**live, "/new.json": gz_hash(b"{}")}
    assert uploaded == [gz_hash(b"{}")]


def test_deploy_drops_old_verdicts_of_a_repo_scanned_this_run(hosting):
    # A repo in this run's list was rescanned: only what this run signed counts, so an
    # older clean verdict cannot outlive a scan that withheld the repo.
    site, live, populated, _ = hosting
    live.update({"/v1/hf/org/top/old.sigstore.json": "1" * 64, "/v1/hf/gone/repo/x.sigstore.json": "2" * 64})
    (site / "keep.json").write_text("{}")
    vs.cmd_deploy(Namespace(site=str(site), top=100, scanned=str(site.parent / "scanned.json")))
    assert "/v1/hf/org/top/old.sigstore.json" not in deployed(populated)
    assert "/v1/hf/gone/repo/x.sigstore.json" in deployed(populated)


def test_a_new_file_replaces_the_old_one_at_its_path(hosting):
    site, live, populated, _ = hosting
    live["/v1/hf/gone/repo/x.sigstore.json"] = "1" * 64
    (site / "v1" / "hf" / "gone" / "repo").mkdir(parents=True)
    (site / "v1" / "hf" / "gone" / "repo" / "x.sigstore.json").write_text("new")
    vs.cmd_deploy(Namespace(site=str(site), top=100, scanned=str(site.parent / "scanned.json")))
    assert deployed(populated)["/v1/hf/gone/repo/x.sigstore.json"] == gz_hash(b"new")


def test_the_first_deploy_has_nothing_to_carry(hosting):
    site, _, populated, _ = hosting
    (site / "a.json").write_text("{}")
    assert vs.cmd_deploy(Namespace(site=str(site), top=100, scanned=str(site.parent / "scanned.json"))) == 0
    assert deployed(populated) == {"/a.json": gz_hash(b"{}")}


def test_files_are_populated_in_batches_of_at_most_1000(hosting, monkeypatch):
    site, live, populated, _ = hosting
    for i in range(2500):
        live[f"/v1/hf/gone/repo/{i}.sigstore.json"] = f"{i:064x}"
    (site / "a.json").write_text("{}")
    vs.cmd_deploy(Namespace(site=str(site), top=100, scanned=str(site.parent / "scanned.json")))
    assert max(len(batch) for batch in populated) <= 1000 and len(deployed(populated)) == 2501


def test_a_repo_scanned_this_run_is_dropped_even_after_leaving_the_top_list(hosting):
    # Scanned (and maybe withheld) hours ago, out of the top list by deploy time.
    site, live, populated, _ = hosting
    (site.parent / "scanned.json").write_text(json.dumps(["org/top", "org/slipped"]))
    live.update({"/v1/hf/org/slipped/old.sigstore.json": "1" * 64, "/v1/hf/org/top2/x.sigstore.json": "2" * 64})
    (site / "a.json").write_text("{}")
    vs.cmd_deploy(Namespace(site=str(site), top=100, scanned=str(site.parent / "scanned.json")))
    # org/top2 shares a prefix with org/top but was not scanned, so it is kept.
    assert set(deployed(populated)) == {"/a.json", "/v1/hf/org/top2/x.sigstore.json"}


def test_a_live_release_without_a_version_carries_nothing(monkeypatch):
    monkeypatch.setattr(vs, "_json", lambda url, body=None, token=None, method=None: {"release": {"name": "r"}})
    assert vs.live_files("t") == {}


def test_deploy_stops_if_a_kept_file_must_be_uploaded_again(hosting, monkeypatch):
    site, live, _, _ = hosting
    live["/v1/hf/gone/repo/x.sigstore.json"] = "1" * 64
    (site / "a.json").write_text("{}")
    fake = vs._json

    def forgetful(url, body=None, token=None, method=None):
        result = fake(url, body, token, method)
        if url.endswith(":populateFiles"):
            result["uploadRequiredHashes"] = list(body["files"].values())
        return result

    monkeypatch.setattr(vs, "_json", forgetful)
    with pytest.raises(SystemExit, match="nothing released"):
        vs.cmd_deploy(Namespace(site=str(site), top=100, scanned=str(site.parent / "scanned.json")))


def test_deploy_keeps_the_live_copy_of_a_content_named_file(hosting):
    site, live, populated, uploaded = hosting
    live["/v1/shards/abc.json"] = "1" * 64
    (site / "v1" / "shards").mkdir(parents=True)
    (site / "v1" / "shards" / "abc.json").write_text("{}")
    vs.cmd_deploy(Namespace(site=str(site), top=100, scanned=str(site.parent / "scanned.json")))
    assert deployed(populated) == {"/v1/shards/abc.json": "1" * 64} and uploaded == []


def test_deploy_never_replaces_a_published_checkpoint(hosting):
    site, live, _, _ = hosting
    live["/v1/checkpoints/0.sigstore.json"] = "1" * 64
    (site / "v1" / "checkpoints").mkdir(parents=True)
    (site / "v1" / "checkpoints" / "0.sigstore.json").write_text("{}")
    with pytest.raises(SystemExit, match="replace a published checkpoint"):
        vs.cmd_deploy(Namespace(site=str(site), top=100, scanned=str(site.parent / "scanned.json")))


def test_only_https_is_ever_requested():
    with pytest.raises(ValueError):
        vs._http("http://example.com")


def test_sign_refuses_a_repo_outside_the_scanned_list(signing):
    src, site, put = signing
    put("attacker/trojan", statement("attacker/trojan"))
    with pytest.raises(SystemExit):
        vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site), scanned=str(src.parent / "scanned.json")))
    assert not site.exists()


@pytest.mark.parametrize("tamper", [
    lambda st: st["predicate"]["files"]["model.safetensors"].update(verdict="Flagged"),
    lambda st: st["predicate"].update(scanned=(datetime.now(timezone.utc) + timedelta(days=30)).isoformat()),
    lambda st: st["predicate"]["scanner"].update(version="0.0.1"),
    lambda st: st["predicate"]["files"].update({"extra.bin": {"verdict": "clean", "rules": [], "coverage_gaps": []}}),
    lambda st: st["predicate"]["source"].update(revision="../../x"),
    lambda st: st["predicate"]["files"]["model.safetensors"].update(note="anything"),
])
def test_sign_refuses_a_receipt_that_does_not_have_the_expected_shape(signing, tamper):
    src, site, put = signing
    st = statement("org/clean")
    tamper(st)
    put("org/clean", st)
    with pytest.raises(SystemExit):
        vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site), scanned=str(src.parent / "scanned.json")))
    assert not site.exists()


def test_sign_signs_a_canonical_copy_not_the_scan_jobs_bytes(signing):
    src, site, put = signing
    st = statement("org/clean")
    st["predicate"]["extra"] = "ignored"
    put("org/clean", st)
    vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site), scanned=str(src.parent / "scanned.json")))
    signed = json.loads(json.loads((site / f"v1/hf/org/clean/{SHA}.sigstore.json").read_text())["signed"])
    assert "extra" not in signed["predicate"]


def test_a_refusal_never_names_the_repo(signing, capsys):
    src, site, put = signing
    put("evil/secret", statement("evil/secret", "flagged"))
    with pytest.raises(SystemExit) as exc:
        vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site), scanned=str(src.parent / "scanned.json")))
    assert "evil" not in str(exc.value)


def test_sign_refuses_an_unexpected_file_in_the_artifact(signing, tmp_path):
    src, site, put = signing
    put("org/clean", statement("org/clean"))
    (src / "index.html").write_text("<script>")
    with pytest.raises(SystemExit):
        vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site), scanned=str(src.parent / "scanned.json")))
