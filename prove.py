#!/usr/bin/env python3
"""HDAR Cross-Platform Proof — one-command verification.

Clones the repo, runs the verifier against all published evidence, and
reports the result. No arguments needed.

Usage:
    python3 prove.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.resolve()

EVIDENCE = [
    ("evidence/codespaces/host_b_report.json", "evidence/codespaces/capsule_epoch_2"),
    ("evidence/github-actions/ubuntu-22.04/host_b_report.json", "evidence/github-actions/ubuntu-22.04/capsule_epoch_2"),
    ("evidence/github-actions/ubuntu-24.04/host_b_report.json", "evidence/github-actions/ubuntu-24.04/capsule_epoch_2"),
    ("evidence/github-actions/macos-14/host_b_report.json", "evidence/github-actions/macos-14/capsule_epoch_2"),
]


def main() -> int:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "verify_all.py"),
        "--host-a-dir", str(REPO_ROOT),
    ]
    for report, capsule in EVIDENCE:
        cmd.extend(["--host-b-report", str(REPO_ROOT / report)])
        cmd.extend(["--e2-capsule", str(REPO_ROOT / capsule)])
    cmd.extend(["--out", str(REPO_ROOT / "evidence" / "verifier_report_latest.json")])

    print("Running: verify_all.py against 4 Host B evidence sets")
    print()
    result = subprocess.run(cmd, cwd=str(REPO_ROOT))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
