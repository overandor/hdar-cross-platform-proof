#!/usr/bin/env python3
"""HDAR End-to-End Pipeline Test (cryptographic chain only — NOT cross-platform).

This test exercises the cryptographic pipeline — not just verification of
pre-committed evidence. It:

1. Runs host_a_seal.py to generate a FRESH Epoch 1 capsule with a new keypair
2. Runs the generated run_host_b.py to continue E1 → E2
3. Verifies the fresh E2 with verify_all.py
4. Checks that all cryptographic and structural checks pass

This catches defects that static-evidence verification cannot:
- host_a_seal.py producing invalid manifests/signatures
- run_host_b.py producing invalid E2 capsules
- Lineage breaking between fresh E1 and E2
- Content block corruption during the pipeline
- Receipt hash computation errors

IMPORTANT — what this test does NOT prove:
  This test runs Host A and Host B on the SAME machine. It does NOT prove
  cross-platform continuation. Platform separation (Host A ≠ Host B) will
  FAIL because both run locally. This is expected and excluded from the
  pass/fail verdict.

  Cross-platform continuation requires Host B to run on a genuinely
  different platform — Colab, Codespaces, HuggingFace, or E2B Sandbox.
  That is tested by the reproduction_matrix.yml workflow on real
  GitHub Actions runners, not by this local test.

  This test proves: the cryptographic chain mechanics work end-to-end.
  This test does NOT prove: cross-platform continuation.

Usage:
    python3 test_end_to_end.py
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).parent.resolve()

# Checks that require different platforms — cannot pass when both
# Host A and Host B run on the same machine (which is the case in CI
# and local testing). These are verified by the reproduction matrix
# workflow on actual different runners.
PLATFORM_DEPENDENT_CHECKS = {
    "Platform separation (Host A ≠ Host B)",
    "Host B report confirms platform separation",
}


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 60) -> tuple[int, str]:
    """Run a command and return (exit_code, combined_output)."""
    result = subprocess.run(cmd, cwd=str(cwd) if cwd else None,
                           capture_output=True, text=True, timeout=timeout)
    return result.returncode, result.stdout + result.stderr


def main() -> int:
    print("=" * 70)
    print("HDAR End-to-End Pipeline Test")
    print("=" * 70)
    print()
    print("This test generates FRESH evidence (not pre-committed) and verifies it.")
    print("It exercises: host_a_seal.py → run_host_b.py → verify_all.py")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        host_a_dir = tmp / "host_a"
        host_b_dir = tmp / "host_b"

        # Step 1: Seal Epoch 1 on Host A
        print("-" * 70)
        print("[1/4] Running host_a_seal.py — generating fresh E1 capsule...")
        print("-" * 70)
        code, output = run([sys.executable, str(REPO / "host_a_seal.py"),
                           "--out", str(host_a_dir)], timeout=60)
        print(output, end="")
        if code != 0:
            print(f"\nFAIL: host_a_seal.py exited with code {code}")
            return 1

        # Verify Host A artifacts exist
        required = ["host_a_report.json", "owner_public_key.txt",
                    "capsule_epoch_1/manifest.json", "run_host_b.py"]
        for f in required:
            if not (host_a_dir / f).exists():
                print(f"\nFAIL: host_a_seal.py did not produce {f}")
                return 1
        print("[PASS] Host A artifacts present")
        print()

        # Step 2: Run Host B to continue E1 → E2
        print("-" * 70)
        print("[2/4] Running run_host_b.py — continuing to E2...")
        print("-" * 70)
        code, output = run([sys.executable, str(host_a_dir / "run_host_b.py"),
                           "--out", str(host_b_dir),
                           "--host-label", "e2e-test-host-b"], timeout=60)
        print(output, end="")
        if code != 0:
            print(f"\nFAIL: run_host_b.py exited with code {code}")
            return 1

        # Verify Host B artifacts exist
        required_b = ["host_b_report.json", "capsule_epoch_2/manifest.json"]
        for f in required_b:
            if not (host_b_dir / f).exists():
                print(f"\nFAIL: run_host_b.py did not produce {f}")
                return 1
        print("[PASS] Host B artifacts present")
        print()

        # Step 3: Verify the fresh E2 with verify_all.py
        print("-" * 70)
        print("[3/4] Running verify_all.py against fresh evidence...")
        print("-" * 70)
        code, output = run([sys.executable, str(REPO / "verify_all.py"),
                           "--host-a-dir", str(host_a_dir),
                           "--host-b-report", str(host_b_dir / "host_b_report.json"),
                           "--e2-capsule", str(host_b_dir / "capsule_epoch_2")],
                          timeout=30)
        print(output, end="")

        # Step 4: Analyze results
        print("-" * 70)
        print("[4/4] Analyzing verification results...")
        print("-" * 70)

        # Parse the output to find [PASS] and [FAIL] lines
        passes = []
        failures = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("[PASS]"):
                check_name = line[6:].strip()
                passes.append(check_name)
            elif line.startswith("[FAIL]"):
                # Extract check name (before the " —" or " —" separator)
                check_part = line[6:].split(" — ")[0].strip()
                failures.append(check_part)

        # Classify failures
        platform_failures = [f for f in failures if f in PLATFORM_DEPENDENT_CHECKS]
        real_failures = [f for f in failures if f not in PLATFORM_DEPENDENT_CHECKS]

        print(f"  Total checks: {len(passes) + len(failures)}")
        print(f"  Passed: {len(passes)}")
        print(f"  Failed (platform-expected): {len(platform_failures)}")
        print(f"  Failed (real defects): {len(real_failures)}")
        print()

        if platform_failures:
            print("  Platform-expected failures (Host A and Host B on same machine):")
            for f in platform_failures:
                print(f"    - {f}")
            print()

        if real_failures:
            print("  REAL FAILURES — pipeline produced invalid evidence:")
            for f in real_failures:
                print(f"    - {f}")
            print()
            print("  VERDICT: END-TO-END PIPELINE FAILED")
            return 1

        # Verify the critical cryptographic checks specifically passed
        critical_checks = [
            "E1 manifest hash valid",
            "E1 Ed25519 owner signature valid",
            "E1 receipt hash valid",
            "E2 manifest hash valid",
            "E2 receipt hash valid",
            "Cryptographic lineage E1→E2",
            "Epoch advancement 1→2",
            "Owner public key consistent",
            "E1 receipt workspace hash matches manifest",
            "E2 receipt workspace hash matches manifest",
            "E2 workspace differs from E1",
            "E2 workspace grew",
            "Source workspace files preserved in E2",
            "Pipeline output hash recomputed from E2 workspace matches report",
            "E2 content blocks all valid",
        ]

        missing_critical = []
        for c in critical_checks:
            if not any(p.startswith(c) for p in passes):
                missing_critical.append(c)
        if missing_critical:
            print("  CRITICAL CHECKS NOT PASSED:")
            for c in missing_critical:
                print(f"    - {c}")
            print()
            print("  VERDICT: END-TO-END PIPELINE FAILED (missing critical checks)")
            return 1

        print("  All critical cryptographic checks passed on fresh evidence.")
        print()
        print("=" * 70)
        print("CRYPTOGRAPHIC CHAIN TEST: PASSED (same-machine — NOT cross-platform)")
        print("=" * 70)
        print()
        print(f"  Fresh E1 sealed, E2 continued, cryptographic chain verified.")
        print(f"  {len(passes)}/{len(passes) + len(failures)} checks passed")
        print(f"  ({len(platform_failures)} platform-separation checks skipped — same machine)")
        print()
        print("  NOTE: This does NOT prove cross-platform continuation.")
        print("  Host B ran on the same machine as Host A.")
        print("  Cross-platform proof requires Host B on Colab/Codespaces/HF/E2B.")
        print("  Use reproduction_matrix.yml for real cross-platform verification.")
        print()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
