"""Offline tests for the service script: the Hub, Sigstore, age and Google are faked."""

from __future__ import annotations

import gzip
import json
from argparse import Namespace
from datetime import datetime, timedelta, timezone

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


# ---- sign --------------------------------------------------------------------------------

@pytest.fixture
def signing(monkeypatch, tmp_path):
    src, site = tmp_path / "out", tmp_path / "site"
    monkeypatch.setattr(vs, "hub_hashes", lambda repo, sha: {"model.safetensors": LFS})
    monkeypatch.setattr(vs, "top_repos", lambda n: ["org/clean", "evil/secret", "other/repo"])
    monkeypatch.setattr(receipt, "_sigstore_sign", lambda raw: json.dumps({"signed": raw.decode()}))

    def put(repo, st, path=None):
        dest = src / (path or f"v1/hf/{repo}/{SHA}.intoto.json")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(st))

    return src, site, put


def test_sign_writes_a_bundle_where_the_client_looks(signing):
    src, site, put = signing
    put("org/clean", statement("org/clean"))
    assert vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site))) == 0
    assert (site / f"v1/hf/org/clean/{SHA}.sigstore.json").is_file()


def test_sign_refuses_a_flagged_verdict(signing):
    src, site, put = signing
    put("evil/secret", statement("evil/secret", "flagged"))
    with pytest.raises(SystemExit):
        vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site)))
    assert not site.exists()


def test_sign_refuses_a_receipt_filed_under_another_repo(signing):
    src, site, put = signing
    put("org/clean", statement("other/repo"), path=f"v1/hf/org/clean/{SHA}.intoto.json")
    with pytest.raises(SystemExit):
        vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site)))


def test_sign_refuses_hashes_the_hub_does_not_confirm(signing, monkeypatch):
    src, site, put = signing
    put("org/clean", statement("org/clean"))
    monkeypatch.setattr(vs, "hub_hashes", lambda repo, sha: {"model.safetensors": "c" * 64})
    with pytest.raises(SystemExit):
        vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site)))


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


def test_only_https_is_ever_requested():
    with pytest.raises(ValueError):
        vs._http("http://example.com")


def test_sign_refuses_a_repo_outside_the_scanned_list(signing):
    src, site, put = signing
    put("attacker/trojan", statement("attacker/trojan"))
    with pytest.raises(SystemExit):
        vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site)))
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
        vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site)))
    assert not site.exists()


def test_sign_signs_a_canonical_copy_not_the_scan_jobs_bytes(signing):
    src, site, put = signing
    st = statement("org/clean")
    st["predicate"]["extra"] = "ignored"
    put("org/clean", st)
    vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site)))
    signed = json.loads(json.loads((site / f"v1/hf/org/clean/{SHA}.sigstore.json").read_text())["signed"])
    assert "extra" not in signed["predicate"]


def test_a_refusal_never_names_the_repo(signing, capsys):
    src, site, put = signing
    put("evil/secret", statement("evil/secret", "flagged"))
    with pytest.raises(SystemExit) as exc:
        vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site)))
    assert "evil" not in str(exc.value)


def test_sign_refuses_an_unexpected_file_in_the_artifact(signing, tmp_path):
    src, site, put = signing
    put("org/clean", statement("org/clean"))
    (src / "index.html").write_text("<script>")
    with pytest.raises(SystemExit):
        vs.cmd_sign(Namespace(top=100, src=str(src), site=str(site)))
