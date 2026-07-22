#!/usr/bin/env python3
"""HDAR Cross-Platform Proof — one-command verification.

Clones the repo, runs the verifier against all published evidence, and
reports the result. No arguments needed.

Runs BOTH the Python verifier (verify_all.py) and the independent Rust
verifier (rust_verifier/) against the same evidence. Both must pass.
The audit stated: "Publish both verifiers and require both to pass on the
same evidence."

Usage:
    python3 prove.py
    python3 prove.py --python-only    # skip Rust verifier
"""
from __future__ import annotations

import argparse
import re
import shutil
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


def run_python_verifier() -> tuple[int, str]:
    """Run the Python verifier against all published evidence.
    Returns (exit_code, stdout_output)."""
    cmd = [
        sys.executable,
        str(REPO_ROOT / "verify_all.py"),
        "--host-a-dir", str(REPO_ROOT),
    ]
    for report, capsule in EVIDENCE:
        cmd.extend(["--host-b-report", str(REPO_ROOT / report)])
        cmd.extend(["--e2-capsule", str(REPO_ROOT / capsule)])
    cmd.extend(["--out", str(REPO_ROOT / "evidence" / "verifier_report_latest.json")])

    print("=" * 70)
    print("Python Verifier (verify_all.py)")
    print("=" * 70)
    result = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result.returncode, result.stdout


def run_rust_verifier() -> tuple[int, str]:
    """Run the independent Rust verifier against all published evidence.
    Returns (exit_code, stdout_output)."""
    rust_binary = REPO_ROOT / "rust_verifier" / "target" / "release" / "hdar-verify"

    # Build if not present
    if not rust_binary.exists():
        print("=" * 70)
        print("Building Rust verifier (first run)...")
        print("=" * 70)
        build = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=str(REPO_ROOT / "rust_verifier"),
        )
        if build.returncode != 0:
            print("ERROR: Rust verifier build failed — cannot verify implementation independence")
            print("  (Install Rust from https://rustup.rs to enable independent verification)")
            return 1, ""  # FAIL the proof — implementation independence is a required claim

    if not rust_binary.exists():
        print("ERROR: Rust binary not found after build — cannot verify implementation independence")
        return 1, ""

    print()
    print("=" * 70)
    print("Independent Rust Verifier (rust_verifier/)")
    print("=" * 70)
    all_pass = True
    all_output = []
    for report, capsule in EVIDENCE:
        platform_name = Path(report).parts[-2] if len(Path(report).parts) > 1 else "unknown"
        print(f"\n--- {platform_name} ---")
        result = subprocess.run([
            str(rust_binary),
            "--host-a-dir", str(REPO_ROOT),
            "--host-b-report", str(REPO_ROOT / report),
            "--e2-capsule", str(REPO_ROOT / capsule),
        ], cwd=str(REPO_ROOT), capture_output=True, text=True)
        print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        all_output.append(result.stdout)
        if result.returncode != 0:
            all_pass = False

    return (0 if all_pass else 1), "\n".join(all_output)


def extract_check_counts(output: str) -> tuple[int, int]:
    """Extract (passed, total) check counts from verifier output.
    Looks for patterns like '21/21 passed' or '84/84'."""
    # Look for "N/N passed" pattern (per-platform)
    per_platform = re.findall(r'(\d+)/(\d+)\s+passed', output)
    if per_platform:
        total_passed = sum(int(p) for p, _ in per_platform)
        total_checks = sum(int(t) for _, t in per_platform)
        return total_passed, total_checks
    # Fallback: look for standalone "N/N" pattern
    counts = re.findall(r'(\d+)/(\d+)', output)
    if counts:
        return int(counts[-1][0]), int(counts[-1][1])
    return -1, -1  # unknown


def main() -> int:
    ap = argparse.ArgumentParser(description="HDAR Cross-Platform Proof")
    ap.add_argument("--python-only", action="store_true",
                    help="Skip the Rust verifier (not recommended — loses implementation independence)")
    args = ap.parse_args()

    py_code, py_output = run_python_verifier()
    if py_code != 0:
        print("\nPython verifier FAILED — aborting")
        return py_code

    rust_code, rust_output = 0, ""
    if not args.python_only:
        rust_code, rust_output = run_rust_verifier()
        if rust_code != 0:
            print("\nRust verifier FAILED — implementation-independent verification gap")
            return rust_code

    # Extract actual check counts from verifier output (not hardcoded)
    py_passed, py_total = extract_check_counts(py_output)
    rust_passed, rust_total = extract_check_counts(rust_output)

    print()
    print("=" * 70)
    print("COMBINED VERIFICATION RESULT")
    print("=" * 70)
    if args.python_only:
        py_str = f"PASS ({py_passed}/{py_total})" if py_total > 0 else "PASS (count unknown)"
        print(f"  Python verifier: {py_str}")
        print("  Rust verifier: SKIPPED (--python-only)")
    else:
        py_str = f"PASS ({py_passed}/{py_total})" if py_total > 0 else "PASS (count unknown)"
        rust_str = f"PASS ({rust_passed}/{rust_total})" if rust_total > 0 else "PASS (count unknown)"
        print(f"  Python verifier: {py_str}")
        print(f"  Rust verifier: {rust_str}")
        # Verify both verifiers checked the same number of checks
        if py_total > 0 and rust_total > 0 and py_total != rust_total:
            print(f"  WARNING: check count mismatch — Python={py_total} Rust={rust_total}")
            print("  Implementation independence: CHECK COUNT MISMATCH")
            return 1
        print("  Implementation independence: CONFIRMED (two independent codebases agree)")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
