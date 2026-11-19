"""Offline fixtures for the CI gate. No real archive or verifier is invoked."""

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import runpy
import subprocess
from types import SimpleNamespace

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/ci_toolchain.py"
TOOLCHAIN = SimpleNamespace(**runpy.run_path(str(SCRIPT)))


def test_exact_toolchain_pins():
    assert vars(TOOLCHAIN.UV) == {
        "repository": "astral-sh/uv",
        "tag": "0.13.9",
        "source_commit": "6b2d39dcc390293d51c9c0d2bbcd650f4bcbfdce",
        "name": "uv-x86_64-unknown-linux-gnu.tar.gz",
        "sha256": "a7fbaff2b9a271d85c1bdb540941090fd1ce011797b4abeb48e4dcd39c2471d5",
    }
    assert vars(TOOLCHAIN.PYTHON) == {
        "repository": "astral-sh/python-build-standalone",
        "tag": "20261110",
        "source_commit": "9244801782b78e4c4afc5c82a4524aa2101d3298",
        "name": "cpython-3.12.16+20261110-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
        "sha256": "6a9e62dad033790aef722dbd370e0ce76ce17b73627ba3ae679f537049350b39",
    }


@pytest.mark.parametrize("failure", [
    None, "sha256", "missing-attestation", "malformed-attestation", "signer-repo",
    "signer-workflow", "release-ref", "source-ref", "wrong-platform", "verifier-error",
])
def test_gate_stops_before_extraction_on_invalid_evidence(monkeypatch, tmp_path, failure):
    # Allow uv to pass in every case, so a Python verification failure also
    # proves the first archive is not extracted prematurely.
    uv_bytes, python_bytes = b"synthetic uv archive", b"synthetic python archive"
    uv = replace(TOOLCHAIN.UV, sha256=sha256(uv_bytes).hexdigest())
    python = replace(TOOLCHAIN.PYTHON, sha256=sha256(python_bytes).hexdigest())
    namespace = TOOLCHAIN.provision.__globals__
    monkeypatch.setitem(namespace, "require_verifier", lambda: "/usr/bin/gh")
    monkeypatch.setitem(namespace, "UV", uv)
    monkeypatch.setitem(namespace, "PYTHON", python)
    calls = []

    def run(command, *, check, timeout, **kwargs):
        assert check is True and timeout == 120
        calls.append(command)
        if command[0] == "tar":
            assert failure is None
            assert len(calls) >= 7
            path = (
                tmp_path / "uv-x86_64-unknown-linux-gnu/uv"
                if command[command.index("--file") + 1].endswith(uv.name)
                else tmp_path / "python/bin/python3.12"
            )
            path.parent.mkdir(parents=True)
            path.touch(mode=0o700)
            return
        repo = command[command.index("--repo") + 1]
        artifact, data = (uv, uv_bytes) if repo == uv.repository else (python, python_bytes)
        assert repo == artifact.repository
        archive = tmp_path / artifact.name
        if command[1:3] == ["release", "download"]:
            assert command == [
                "/usr/bin/gh", "release", "download", artifact.tag, "--repo", repo,
                "--pattern", artifact.name, "--dir", str(tmp_path),
            ]
            if artifact == python and failure == "wrong-platform":
                (tmp_path / python.name.replace("x86_64", "aarch64")).write_bytes(data)
            else:
                archive.write_bytes(b"mismatched" if artifact == python and failure == "sha256" else data)
        elif command[1:3] == ["release", "verify-asset"]:
            assert command == ["/usr/bin/gh", "release", "verify-asset", artifact.tag, str(archive), "--repo", repo]
            if artifact == python and failure == "release-ref":
                raise subprocess.CalledProcessError(1, command)
        else:
            identity_flags = {"--cert-identity", "--cert-identity-regex", "--signer-repo", "--signer-workflow"}
            assert identity_flags.intersection(command) == {"--signer-workflow"}
            assert command == [
                "/usr/bin/gh", "attestation", "verify", str(archive), "--repo", repo,
                "--predicate-type", "https://slsa.dev/provenance/v1",
                "--signer-workflow", f"{repo}/.github/workflows/release.yml@refs/heads/main",
                "--source-ref", "refs/heads/main", "--source-digest", artifact.source_commit,
            ]
            if artifact == python and failure == "verifier-error":
                raise subprocess.TimeoutExpired(command, timeout)
            if artifact == python and failure in {
                "missing-attestation", "malformed-attestation", "signer-repo",
                "signer-workflow", "source-ref",
            }:
                raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(subprocess, "run", run)
    if failure is None:
        uv_dir, interpreter = TOOLCHAIN.provision(tmp_path)
        assert (uv_dir / "uv").is_file() and interpreter.is_file()
        assert [command[0] for command in calls] == ["/usr/bin/gh"] * 6 + ["tar"] * 2
    else:
        stop_error = {
            "sha256": ValueError, "wrong-platform": FileNotFoundError,
            "verifier-error": subprocess.TimeoutExpired,
        }.get(failure, subprocess.CalledProcessError)
        with pytest.raises(stop_error):
            TOOLCHAIN.provision(tmp_path)
        assert all(command[0] != "tar" for command in calls)
        assert not (tmp_path / "python/bin/python3.12").exists()
        assert not (tmp_path / "uv-x86_64-unknown-linux-gnu/uv").exists()



@pytest.mark.parametrize(("version", "unavailable", "error"), [
    ("gh version 2.102.0 (2026-09-30)", None, None),
    ("gh version 2.103.3", None, None),
    ("gh version 2.101.0", None, RuntimeError),
    ("gh version 2.102.0-rc.1", None, RuntimeError),
    ("unknown", None, RuntimeError),
    (None, None, RuntimeError),
    ("gh version 2.103.3", "verify-asset", subprocess.CalledProcessError),
    ("gh version 2.103.3", "verify", subprocess.CalledProcessError),
])
def test_verifier_preflight_blocks_downloads(tmp_path, monkeypatch, version, unavailable, error):
    path = "/usr/bin/gh"
    calls = []

    def which(name, *, path):
        assert name == "gh" and path == TOOLCHAIN.os.defpath
        return "/usr/bin/gh" if version is not None else None

    def run(command, **kwargs):
        calls.append(command)
        assert command[0] == path
        if command[1:] == ["--version"]:
            return SimpleNamespace(stdout=version + "\n")
        assert command[-1] == "--help"
        assert "GH_TOKEN" not in kwargs["env"]
        if command[-2] == unavailable:
            raise subprocess.CalledProcessError(1, command)
        return SimpleNamespace()

    monkeypatch.setattr(TOOLCHAIN.shutil, "which", which)
    monkeypatch.setattr(subprocess, "run", run)
    if error is None:
        assert TOOLCHAIN.require_verifier() == path
        assert [command[1:] for command in calls] == [
            ["--version"], ["release", "verify-asset", "--help"], ["attestation", "verify", "--help"],
        ]
    else:
        with pytest.raises(error):
            TOOLCHAIN.provision(tmp_path)
        assert all(command[1:] == ["--version"] or command[-1] == "--help" for command in calls)
        assert list(tmp_path.iterdir()) == []
