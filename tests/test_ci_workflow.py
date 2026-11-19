import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_NODE_SHA = "949feb2413d6458794dcd2491c4babbbce0c15c1"


def _text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _top_level_block(name: str) -> str:
    lines = _text().splitlines()
    start = lines.index(f"{name}:") + 1
    block = []
    for line in lines[start:]:
        if line and not line.startswith("  "):
            break
        block.append(line)
    return "\n".join(block)


def test_ci_workflow_exists_and_uses_expected_triggers():
    assert WORKFLOW.is_file()
    triggers = _top_level_block("on")
    assert re.search(r"(?m)^  pull_request:$", triggers)
    assert re.search(r"(?m)^  push:$", triggers)
    assert re.search(r"(?m)^      - main$", triggers)
    assert re.search(r"(?m)^  workflow_dispatch:$", triggers)
    for forbidden in (
        "pull_request_target",
        "schedule:",
        "release:",
        "deployment:",
        "workflow_run:",
    ):
        assert forbidden not in triggers


def test_ci_permissions_are_contents_read_only():
    permissions = [
        line.strip()
        for line in _top_level_block("permissions").splitlines()
        if line.strip()
    ]
    assert permissions == ["contents: read"]
    assert "write" not in _top_level_block("permissions")


def test_ci_has_one_bounded_github_hosted_linux_job():
    jobs = _top_level_block("jobs")
    job_keys = [
        line.strip()[:-1]
        for line in jobs.splitlines()
        if re.fullmatch(r"  [A-Za-z0-9_-]+:", line)
    ]
    assert job_keys == ["test"]
    assert "runs-on: ubuntu-24.04" in jobs
    assert "timeout-minutes: 15" in jobs
    assert "matrix:" not in jobs
    assert "container:" not in jobs
    assert "services:" not in jobs


def test_ci_cancels_obsolete_runs_for_the_same_ref_or_pull_request():
    concurrency = _top_level_block("concurrency")
    assert "github.workflow" in concurrency
    assert "github.event.pull_request.number || github.ref" in concurrency
    assert "cancel-in-progress: true" in concurrency
    assert "secrets." not in concurrency


def test_ci_actions_are_full_sha_pinned_with_reviewed_tags():
    text = _text()
    uses = re.findall(r"(?m)^\s*uses:\s*([^\s#]+)(?:\s+#\s*(\S+))?$", text)
    assert uses == [
        (f"actions/checkout@{CHECKOUT_SHA}", "v7.0.1"),
        (f"actions/setup-node@{SETUP_NODE_SHA}", "v7.1.0"),
    ]
    for reference, _tag in uses:
        assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", reference)


def test_ci_pins_python_uv_and_disables_dependency_cache():
    text = _text()
    assert "run: python3 -I .github/scripts/ci_toolchain.py" in text
    assert 'test "$(uv --version | cut -d \' \' -f 2)" = "0.13.9"' in text
    assert "sys.version_info[:3] == (3, 12, 16)" in text
    assert "UV_NO_CACHE=1" in (ROOT / ".github/scripts/ci_toolchain.py").read_text()
    assert "package-manager-cache: false" in text
    assert "actions/cache@" not in text
    assert "setup-uv@" not in text
    assert "persist-credentials: false" in text


def test_ci_runs_the_complete_locked_validation_sequence():
    text = _text()
    commands = (
        "run: python3 -I .github/scripts/ci_toolchain.py",
        "uv lock --check",
        'uv sync --dev --locked --no-build --no-python-downloads --python "$UV_PYTHON"',
        "uv run python -m compileall -q app tests main.py",
        "uv run pytest -q",
    )
    positions = [text.index(command) for command in commands]
    assert positions == sorted(positions)
    assert "continue-on-error" not in text
    assert "--disable-warnings" not in text


def test_ci_checks_staged_unstaged_and_tracked_status_after_tests():
    text = _text()
    mutation_check = text.index("Verify tests did not modify tracked files")
    assert mutation_check > text.index("uv run pytest -q")
    assert "git diff --exit-code" in text
    assert "git diff --cached --exit-code" in text
    assert "git status --porcelain --untracked-files=no" in text


def test_ci_has_no_secrets_privileged_install_or_deployment_commands():
    text = _text().lower()
    for forbidden in (
        "${{ secrets.",
        "sudo ",
        "curl ",
        "wget ",
        "systemctl",
        "journalctl",
        "uvicorn",
        "nginx",
        "docker",
        "kubectl",
        "printenv",
        "set -x",
        "upload-artifact",
        "tojson(github)",
        "git remote -v",
    ):
        assert forbidden not in text
    assert re.search(r"(?m)^(?:env:|  env:|    env:)\s*$", text) is None
    assert re.findall(r"(?m)^        env:\s*$", text) == ["        env:"] * 3
    assert "tz: utc" in text
    assert re.search(r"(?m)^\s*[a-z-]+:\s*write\s*$", text) is None


def test_ci_provisions_verified_chrome_before_running_accessibility_checks():
    text = _text()
    steps = (
        "npm ci --ignore-scripts --no-audit --no-fund",
        "sha256(package).hexdigest() != expected",
        'dpkg-deb --extract "$TEST_CHROME_DIR/chrome.deb" "$TEST_CHROME_DIR"',
        "npm run test:a11y --silent",
    )
    positions = [text.index(step) for step in steps]
    assert positions == sorted(positions)
    assert "https://dl.google.com/linux/chrome/deb/" in text
    assert re.search(r'google-chrome-stable_[0-9.]+-1_amd64\.deb"', text)
    assert re.search(r'expected = "[0-9a-f]{64}"', text)
    assert "ASLA_TEST_CHROME: ${{ runner.temp }}/asla-chrome/opt/google/chrome/chrome" in text
    for forbidden in ("playwright install", "PLAYWRIGHT_BROWSERS_PATH", "--no-sandbox"):
        assert forbidden not in text

    launcher = (ROOT / "tests" / "a11y_browser.mjs").read_text(encoding="utf-8")
    assert "chromiumSandbox: true" in launcher
    assert "executablePath," in launcher
    assert "--no-sandbox" not in launcher
    for name in ("ui_accessibility_axe_pilot_28_1.mjs", "ui_json_access_mapping_real_log_3.mjs"):
        entrypoint = (ROOT / "tests" / name).read_text(encoding="utf-8")
        assert "await launchTestChrome()" in entrypoint


def test_ci_contains_no_sensitive_or_machine_local_literals():
    text = _text()
    assert re.search(
        r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])",
        text,
    ) is None
    for forbidden in (
        "/Users/",
        "/home/",
        "Authorization: Bearer ",
        "BEGIN PRIVATE KEY",
        "PRIVACY_CANARY",
        "type=SYSCALL msg=audit(",
    ):
        assert forbidden not in text
