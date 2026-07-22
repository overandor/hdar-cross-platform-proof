#!/usr/bin/env python3
"""HDAR Failure-Injection Tests — prove the verifier rejects tampered evidence.

The audit (TRUST_BOUNDARY.md, boundary 4) stated:

    "The current proof assumes a cooperative Host B. A malicious Host B could:
     - Fabricate platform strings and nonces
     - Run a modified pipeline and report a fabricated output hash
     - Sign a fraudulent E2 with an ephemeral key

     Roadmap: Add failure-injection tests: deliberately corrupt the workspace,
     modify the runner, and tamper with the capsule; confirm the verifier
     rejects each. Publish the failure-injection results as evidence."

This script creates copies of the published evidence, applies specific
tampering to each copy, and confirms the verifier REJECTS every tampered
variant. If any tampered evidence passes, that's a security gap.

Tests:
  1. Corrupt E1 manifest hash → verifier must reject
  2. Corrupt E1 owner signature → verifier must reject
  3. Corrupt E2 manifest hash → verifier must reject
  4. Corrupt E2 content block → verifier must reject
  5. Break E1→E2 lineage (change parent_manifest_hash) → verifier must reject
  6. Swap E2 from a different E1 (wrong parent) → verifier must reject
  7. Fabricate platform string (make Host B = Host A) → verifier must reject
  8. Corrupt receipt hash → verifier must reject
  9. Modify workspace file in E2 (change content hash) → verifier must reject
 10. Remove a content block from E2 → verifier must reject

Usage:
    python3 test_failure_injection.py

Exit code 0 = all tampered evidence was correctly rejected (PASS)
Exit code 1 = some tampered evidence passed the verifier (SECURITY GAP)
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CHUNK_SIZE = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def run_verifier(host_a_dir: Path, host_b_report: Path, e2_capsule: Path) -> tuple[int, str]:
    """Run verify_all.py and return (exit_code, output)."""
    cmd = [
        sys.executable, "verify_all.py",
        "--host-a-dir", str(host_a_dir),
        "--host-b-report", str(host_b_report),
        "--e2-capsule", str(e2_capsule),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.returncode, result.stdout + result.stderr


def setup_test_env(base_dir: Path) -> tuple[Path, Path, Path]:
    """Copy published evidence to a temp dir for tampering."""
    repo = Path(__file__).parent.resolve()
    host_a_dir = base_dir / "host_a"
    host_a_dir.mkdir(parents=True, exist_ok=True)

    # Copy Host A artifacts
    shutil.copy2(repo / "host_a_report.json", host_a_dir / "host_a_report.json")
    shutil.copy2(repo / "owner_public_key.txt", host_a_dir / "owner_public_key.txt")
    shutil.copytree(repo / "capsule_epoch_1", host_a_dir / "capsule_epoch_1")

    # Copy Host B evidence (Codespaces — first platform)
    evidence_dir = repo / "evidence" / "codespaces"
    host_b_report = base_dir / "host_b_report.json"
    e2_capsule = base_dir / "capsule_epoch_2"
    shutil.copy2(evidence_dir / "host_b_report.json", host_b_report)
    shutil.copytree(evidence_dir / "capsule_epoch_2", e2_capsule)

    return host_a_dir, host_b_report, e2_capsule


def test_name_to_func(name: str) -> callable:
    """Map test name to function."""
    return TESTS.get(name)


def test_1_corrupt_e1_manifest_hash(base: Path) -> tuple[str, Path, Path, Path, str]:
    """Corrupt E1 manifest hash → verifier must reject."""
    host_a, report, e2 = setup_test_env(base)
    manifest_path = host_a / "capsule_epoch_1" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    # Flip a character in the manifest hash
    original = manifest["manifest_hash"]
    manifest["manifest_hash"] = original[:10] + ("0" if original[10] != "0" else "1") + original[11:]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return "Corrupt E1 manifest hash", host_a, report, e2, "E1 manifest hash valid"


def test_2_corrupt_e1_owner_signature(base: Path) -> tuple[str, Path, Path, Path, str]:
    """Corrupt E1 owner signature → verifier must reject."""
    host_a, report, e2 = setup_test_env(base)
    manifest_path = host_a / "capsule_epoch_1" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    sig = manifest["owner_signature"]
    manifest["owner_signature"] = sig[:10] + ("0" if sig[10] != "0" else "1") + sig[11:]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return "Corrupt E1 owner signature", host_a, report, e2, "E1 Ed25519 owner signature valid"


def test_3_corrupt_e2_manifest_hash(base: Path) -> tuple[str, Path, Path, Path, str]:
    """Corrupt E2 manifest hash → verifier must reject."""
    host_a, report, e2 = setup_test_env(base)
    manifest_path = e2 / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    original = manifest["manifest_hash"]
    manifest["manifest_hash"] = original[:10] + ("0" if original[10] != "0" else "1") + original[11:]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return "Corrupt E2 manifest hash", host_a, report, e2, "E2 manifest hash valid"


def test_4_corrupt_e2_content_block(base: Path) -> tuple[str, Path, Path, Path, str]:
    """Corrupt an E2 content block → verifier must reject."""
    host_a, report, e2 = setup_test_env(base)
    manifest = json.loads((e2 / "manifest.json").read_text())
    # Find a content block and corrupt it
    entry = manifest["workspace_manifest"]["files"][0]
    digest = entry["sha256"]
    block_path = e2 / "blocks" / digest[:2] / digest
    if block_path.exists():
        data = bytearray(block_path.read_bytes())
        if len(data) > 0:
            data[0] ^= 0xFF  # Flip all bits in first byte
            block_path.write_bytes(bytes(data))
    return "Corrupt E2 content block", host_a, report, e2, "E2 content blocks all valid"


def test_5_break_lineage(base: Path) -> tuple[str, Path, Path, Path, str]:
    """Break E1→E2 lineage → verifier must reject."""
    host_a, report, e2 = setup_test_env(base)
    manifest_path = e2 / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    # Change parent_manifest_hash to a fake value
    manifest["parent_manifest_hash"] = "0" * 64
    # Recompute manifest hash (without host_b_signature) to keep it internally consistent
    signing = {k: v for k, v in manifest.items() if k not in ("manifest_hash", "host_b_signature")}
    manifest["manifest_hash"] = sha256_bytes(canonical_json(signing))
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return "Break E1→E2 lineage", host_a, report, e2, "Cryptographic lineage"


def test_6_fabricate_platform(base: Path) -> tuple[str, Path, Path, Path, str]:
    """Fabricate platform string to match Host A → verifier must reject."""
    host_a, report, e2 = setup_test_env(base)
    host_a_report = json.loads((host_a / "host_a_report.json").read_text())
    host_a_platform = host_a_report["host_a_platform"]
    # Modify Host B report to claim it's on the same platform
    hb_report = json.loads(report.read_text())
    hb_report["host_b_platform"] = host_a_platform
    hb_report["platforms_differ"] = False
    report.write_text(json.dumps(hb_report, indent=2, sort_keys=True))
    return "Fabricate platform string (Host B = Host A)", host_a, report, e2, "Platform separation"


def test_7_corrupt_receipt_hash(base: Path) -> tuple[str, Path, Path, Path, str]:
    """Corrupt E1 receipt hash → verifier must reject."""
    host_a, report, e2 = setup_test_env(base)
    receipt_path = host_a / "capsule_epoch_1" / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    original = receipt["receipt_hash"]
    receipt["receipt_hash"] = original[:10] + ("0" if original[10] != "0" else "1") + original[11:]
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True))
    return "Corrupt E1 receipt hash", host_a, report, e2, "receipt hash"


def test_8_remove_content_block(base: Path) -> tuple[str, Path, Path, Path, str]:
    """Remove a content block from E2 → verifier must reject."""
    host_a, report, e2 = setup_test_env(base)
    manifest = json.loads((e2 / "manifest.json").read_text())
    entry = manifest["workspace_manifest"]["files"][0]
    digest = entry["sha256"]
    block_path = e2 / "blocks" / digest[:2] / digest
    if block_path.exists():
        block_path.unlink()
    return "Remove E2 content block", host_a, report, e2, "E2 content blocks all valid"


def test_9_fabricate_output_hash(base: Path) -> tuple[str, Path, Path, Path, str]:
    """Fabricate pipeline output hash in report → verifier must reject."""
    host_a, report, e2 = setup_test_env(base)
    hb_report = json.loads(report.read_text())
    # Change the output hash to a fake value
    hb_report["pipeline_result"]["output_hash"] = "0" * 64
    report.write_text(json.dumps(hb_report, indent=2, sort_keys=True))
    return "Fabricate pipeline output hash", host_a, report, e2, "Pipeline output hash recomputed"


def test_10_swap_owner_key(base: Path) -> tuple[str, Path, Path, Path, str]:
    """Swap owner public key file → verifier must reject."""
    host_a, report, e2 = setup_test_env(base)
    # Write a fake owner public key
    fake_key = "11" * 32
    (host_a / "owner_public_key.txt").write_text(fake_key + "\n")
    return "Swap owner public key", host_a, report, e2, "owner public key"


# Registry of all failure-injection tests
TESTS = {
    "corrupt_e1_manifest": test_1_corrupt_e1_manifest_hash,
    "corrupt_e1_signature": test_2_corrupt_e1_owner_signature,
    "corrupt_e2_manifest": test_3_corrupt_e2_manifest_hash,
    "corrupt_e2_block": test_4_corrupt_e2_content_block,
    "break_lineage": test_5_break_lineage,
    "fabricate_platform": test_6_fabricate_platform,
    "corrupt_receipt": test_7_corrupt_receipt_hash,
    "remove_block": test_8_remove_content_block,
    "fabricate_output": test_9_fabricate_output_hash,
    "swap_owner_key": test_10_swap_owner_key,
}


def main() -> int:
    print("=" * 70)
    print("HDAR Failure-Injection Tests")
    print("=" * 70)
    print("  Proves the verifier REJECTS tampered evidence.")
    print("  If any tampered evidence passes, that's a security gap.")
    print()

    repo = Path(__file__).parent.resolve()
    os.chdir(repo)

    # First, confirm the UNTAMPERED evidence passes (baseline)
    print("  [BASELINE] Untampered evidence should PASS...")
    with tempfile.TemporaryDirectory() as base_dir:
        base = Path(base_dir)
        host_a, report, e2 = setup_test_env(base)
        code, output = run_verifier(host_a, report, e2)
        baseline_pass = code == 0
        print(f"  [{'PASS' if baseline_pass else 'FAIL'}] Baseline: untampered evidence {'passes' if baseline_pass else 'FAILS'}")
        if not baseline_pass:
            print("  FATAL: Baseline evidence doesn't pass — cannot run failure-injection tests")
            return 1
    print()

    # Run each failure-injection test
    all_rejected = True
    results = []

    for test_id, test_func in TESTS.items():
        with tempfile.TemporaryDirectory() as base_dir:
            base = Path(base_dir)
            try:
                name, host_a, report, e2, expected_keyword = test_func(base)
            except Exception as e:
                print(f"  [ERROR] {test_id}: setup failed: {e}")
                results.append({"test": test_id, "name": test_id, "rejected": False, "error": str(e)})
                all_rejected = False
                continue

            code, output = run_verifier(host_a, report, e2)
            rejected = code != 0
            keyword_found = expected_keyword.lower() in output.lower() if expected_keyword else True

            status = "REJECTED" if rejected else "ACCEPTED"
            keyword_status = "matched" if keyword_found else "not matched"
            test_pass = rejected and keyword_found
            print(f"  [{'PASS' if test_pass else 'FAIL!!!'}] {name}")
            print(f"           Verifier exit code: {code} ({status})")
            print(f"           Expected failure keyword '{expected_keyword}': {keyword_status}")
            if rejected and not keyword_found:
                print(f"           WARNING: verifier rejected but for wrong reason — expected check did not fire")
            print()

            results.append({
                "test": test_id,
                "name": name,
                "rejected": rejected,
                "keyword_found": keyword_found,
                "exit_code": code,
            })

            if not rejected or not keyword_found:
                all_rejected = False

    # Summary
    print("=" * 70)
    print("FAILURE-INJECTION SUMMARY")
    print("=" * 70)
    rejected_count = sum(1 for r in results if r["rejected"])
    accepted_count = sum(1 for r in results if not r["rejected"])
    keyword_mismatch_count = sum(1 for r in results if r["rejected"] and not r["keyword_found"])
    print(f"  Tests: {len(results)}")
    print(f"  Tampered evidence correctly REJECTED: {rejected_count}")
    print(f"  Tampered evidence INCORRECTLY ACCEPTED: {accepted_count}")
    print(f"  Rejected for wrong reason (keyword mismatch): {keyword_mismatch_count}")
    print(f"  Verdict: {'ALL TAMPERED EVIDENCE REJECTED — verifier is robust' if all_rejected else 'SECURITY GAP — some tampered evidence passed or was rejected for the wrong reason'}")
    print()
    return 0 if all_rejected else 1


if __name__ == "__main__":
    raise SystemExit(main())
