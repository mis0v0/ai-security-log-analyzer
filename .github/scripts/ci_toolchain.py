"""Verify the exact Ubuntu CI toolchain archives before extracting either one."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile


@dataclass(frozen=True)
class Artifact:
    repository: str
    tag: str
    source_commit: str
    name: str
    sha256: str


UV = Artifact(
    "astral-sh/uv",
    "0.13.9",
    "6b2d39dcc390293d51c9c0d2bbcd650f4bcbfdce",
    "uv-x86_64-unknown-linux-gnu.tar.gz",
    "a7fbaff2b9a271d85c1bdb540941090fd1ce011797b4abeb48e4dcd39c2471d5",
)
PYTHON = Artifact(
    "astral-sh/python-build-standalone",
    "20261110",
    "9244801782b78e4c4afc5c82a4524aa2101d3298",
    "cpython-3.12.16+20261110-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
    "6a9e62dad033790aef722dbd370e0ce76ce17b73627ba3ae679f537049350b39",
)


def require_verifier() -> str:
    # Use the runner's system-installed CLI. Do not bootstrap or trust a
    # checkout-relative PATH entry for the root of this verification chain.
    gh = shutil.which("gh", path=os.defpath)
    if gh is None:
        raise RuntimeError("Runner GitHub CLI is missing")
    env = {"PATH": os.defpath, "GH_NO_UPDATE_NOTIFIER": "1", "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1"}
    version = subprocess.run(
        [gh, "--version"], check=True, timeout=10, capture_output=True, text=True, env=env,
    ).stdout.partition("\n")[0]
    match = re.fullmatch(r"gh version ([0-9]+)\.([0-9]+)\.([0-9]+)(?: \(\d{4}-\d{2}-\d{2}\))?", version)
    # GHSA-wjmr-j3rp-mh2g and the source-ref matching fix shipped in 2.102.0.
    if match is None or tuple(map(int, match.groups())) < (2, 102, 0):
        raise RuntimeError("Runner GitHub CLI must be a stable version 2.102.0 or newer")
    for command in (("release", "verify-asset"), ("attestation", "verify")):
        subprocess.run(
            [gh, *command, "--help"], check=True, timeout=10, stdout=subprocess.DEVNULL, env=env,
        )
    print(f"Verified runner CLI version floor: {version}", flush=True)
    return gh


def fetch_and_verify(gh: str, artifact: Artifact, directory: Path) -> Path:
    archive = directory / artifact.name
    repo = artifact.repository
    subprocess.run([
        gh, "release", "download", artifact.tag, "--repo", repo,
        "--pattern", artifact.name, "--dir", str(directory),
    ], check=True, timeout=120)
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != artifact.sha256:
            raise ValueError(f"Toolchain archive SHA-256 mismatch: {artifact.name}")

    # GitHub's release attestation binds these bytes to the exact release tag.
    subprocess.run([
        gh, "release", "verify-asset", artifact.tag, str(archive), "--repo", repo,
    ], check=True, timeout=120)
    # The publisher's build attestation binds those same bytes to the release
    # workflow and exact source commit. Both upstream workflows ran from main.
    subprocess.run([
        gh, "attestation", "verify", str(archive), "--repo", repo,
        "--predicate-type", "https://slsa.dev/provenance/v1",
        "--signer-workflow", f"{repo}/.github/workflows/release.yml@refs/heads/main",
        "--source-ref", "refs/heads/main", "--source-digest", artifact.source_commit,
    ], check=True, timeout=120)
    return archive


def provision(directory: Path) -> tuple[Path, Path]:
    # Verify the full set before extracting either archive. No fallback path.
    gh = require_verifier()
    archives = [fetch_and_verify(gh, artifact, directory) for artifact in (UV, PYTHON)]
    for archive in archives:
        subprocess.run([
            "tar", "--extract", "--gzip", "--no-same-owner", "--no-same-permissions",
            "--file", str(archive), "--directory", str(directory),
        ], check=True, timeout=120, env={"PATH": os.defpath})
    uv_dir = directory / "uv-x86_64-unknown-linux-gnu"
    python = directory / "python" / "bin" / "python3.12"
    for executable in (uv_dir / "uv", python):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("Verified archive is missing the expected executable")
    return uv_dir, python


def main() -> None:
    release = platform.freedesktop_os_release()
    if (
        platform.system() != "Linux" or platform.machine() != "x86_64"
        or release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04"
    ):
        raise SystemExit("Unsupported CI toolchain platform")

    directory = Path(tempfile.mkdtemp(prefix="verified-toolchain-", dir=os.environ["RUNNER_TEMP"]))
    uv_dir, python = provision(directory)
    with open(os.environ["GITHUB_PATH"], "a", encoding="utf-8") as output:
        output.write(f"{uv_dir}\n")
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
        output.write(
            f"UV_PYTHON={python}\nUV_PYTHON_DOWNLOADS=never\n"
            "UV_LOCKED=1\nUV_NO_BUILD=1\nUV_NO_CACHE=1\n"
        )


if __name__ == "__main__":
    main()
