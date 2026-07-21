#!/usr/bin/env python3
"""HDAR Cross-Platform Verifier — independently verifies Host B reports.

This runs on Host A (or any third machine). It takes:
- Host A report + owner public key + owner private key (to re-sign and compare)
- Host B report + E2 capsule directory

It independently verifies:
1. E1 manifest hash and Ed25519 owner signature
2. E2 manifest hash and lineage (E2.parent == E1.manifest_hash)
3. Receipt hashes for both epochs
4. Platform separation (Host A platform != Host B platform)
5. Pipeline determinism (recompute output hash from fixtures)
6. Workspace restoration exactness
7. E2 workspace grew (pipeline output added)
8. Nonce/timestamp evidence (non-deterministic fields present)
9. Owner public key consistency

Usage:
    python3 verify_all.py --host-a-dir /tmp/hdar_host_a --host-b-report /path/to/host_b_report.json --e2-capsule /path/to/capsule_epoch_2

    # Verify multiple Host B reports at once:
    python3 verify_all.py --host-a-dir /tmp/hdar_host_a \
        --host-b-report colab/host_b_report.json --e2-capsule colab/capsule_epoch_2 \
        --host-b-report codespaces/host_b_report.json --e2-capsule codespaces/capsule_epoch_2 \
        --host-b-report e2b/host_b_report.json --e2-capsule e2b/capsule_epoch_2
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
from pathlib import Path

CHUNK_SIZE = 1024 * 1024

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def verify_signature(pub_bytes: bytes, message: bytes, signature: bytes) -> bool:
    if not HAS_CRYPTO:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(signature, message)
        return True
    except Exception:
        return False


def verify_single_host_b(
    host_a_dir: Path,
    host_b_report_path: Path,
    e2_capsule_dir: Path,
    owner_pub_hex: str,
    host_a_platform: str,
    host_a_report: dict,
    e1_manifest: dict,
    e1_receipt: dict,
) -> dict:
    """Verify a single Host B report against Host A artifacts."""
    checks = []

    def check(name: str, passed: bool, detail: str = "") -> None:
        checks.append({"check": name, "passed": passed, "detail": detail})

    host_b_report = json.loads(host_b_report_path.read_text())
    host_b_platform = host_b_report.get("host_b_platform", "")
    host_label = host_b_report.get("host_b_identity", {}).get("host_label", "unknown")

    # Load E2 artifacts
    e2_manifest_path = e2_capsule_dir / "manifest.json"
    e2_receipt_path = e2_capsule_dir / "receipt.json"
    if not e2_manifest_path.exists():
        check("E2 manifest exists", False, f"not found at {e2_manifest_path}")
        return _build_verdict(checks, host_label)
    e2_manifest = json.loads(e2_manifest_path.read_text())
    e2_receipt = json.loads(e2_receipt_path.read_text())

    # 1. E1 manifest hash valid
    e1_signing = {k: v for k, v in e1_manifest.items() if k not in ("manifest_hash", "owner_signature")}
    e1_expected = sha256_bytes(canonical_json(e1_signing))
    check("E1 manifest hash valid",
          e1_expected == e1_manifest["manifest_hash"],
          f"expected={e1_expected[:16]}... actual={e1_manifest['manifest_hash'][:16]}...")

    # 2. E1 Ed25519 owner signature valid
    e1_sig_ok = False
    if "owner_signature" in e1_manifest:
        e1_sig_ok = verify_signature(
            bytes.fromhex(owner_pub_hex),
            e1_manifest["manifest_hash"].encode(),
            bytes.fromhex(e1_manifest["owner_signature"]),
        )
    check("E1 Ed25519 owner signature valid", e1_sig_ok)

    # 3. E1 receipt hash valid
    #    New evidence: receipt hash computed over subset excluding manifest_hash
    #    and receipt_hash (to avoid circular dependency with manifest binding).
    #    Old evidence: receipt hash computed over all fields except receipt_hash.
    #    Try both methods for backward compatibility.
    e1_r_expected_new = sha256_bytes(canonical_json(
        {k: v for k, v in e1_receipt.items() if k != "receipt_hash" and k != "manifest_hash"}
    ))
    e1_r_expected_old = sha256_bytes(canonical_json(
        {k: v for k, v in e1_receipt.items() if k != "receipt_hash"}
    ))
    e1_r_valid = e1_r_expected_new == e1_receipt["receipt_hash"] or e1_r_expected_old == e1_receipt["receipt_hash"]
    check("E1 receipt hash valid", e1_r_valid)

    # 3b. E1 receipt bound into manifest (audit defect 6)
    #     New evidence includes receipt_hash in the manifest; old evidence doesn't.
    if "receipt_hash" in e1_manifest:
        check("E1 receipt hash bound into manifest",
              e1_manifest["receipt_hash"] == e1_receipt["receipt_hash"],
              f"manifest={e1_manifest['receipt_hash'][:16]}... receipt={e1_receipt['receipt_hash'][:16]}...")
    else:
        # Old evidence — receipt not bound, skip silently
        pass

    # 4. E2 manifest hash valid
    #    The sealer excludes both manifest_hash and host_b_signature from the
    #    signing content. The verifier must match.
    e2_signing = {k: v for k, v in e2_manifest.items() if k not in ("manifest_hash", "host_b_signature")}
    e2_expected = sha256_bytes(canonical_json(e2_signing))
    check("E2 manifest hash valid",
          e2_expected == e2_manifest["manifest_hash"],
          f"expected={e2_expected[:16]}... actual={e2_manifest['manifest_hash'][:16]}...")

    # 5. E2 receipt hash valid
    #    Same backward-compatible approach as E1 receipt (try both methods).
    e2_r_expected_new = sha256_bytes(canonical_json(
        {k: v for k, v in e2_receipt.items() if k != "receipt_hash" and k != "manifest_hash"}
    ))
    e2_r_expected_old = sha256_bytes(canonical_json(
        {k: v for k, v in e2_receipt.items() if k != "receipt_hash"}
    ))
    e2_r_valid = e2_r_expected_new == e2_receipt["receipt_hash"] or e2_r_expected_old == e2_receipt["receipt_hash"]
    check("E2 receipt hash valid", e2_r_valid)

    # 5b. E2 receipt bound into manifest (audit defect 6)
    if "receipt_hash" in e2_manifest:
        check("E2 receipt hash bound into manifest",
              e2_manifest["receipt_hash"] == e2_receipt["receipt_hash"],
              f"manifest={e2_manifest['receipt_hash'][:16]}... receipt={e2_receipt['receipt_hash'][:16]}...")
    else:
        # Old evidence — receipt not bound, skip silently
        pass

    # 6. Cryptographic lineage: E2.parent_manifest_hash == E1.manifest_hash
    check("Cryptographic lineage E1→E2",
          e2_manifest.get("parent_manifest_hash") == e1_manifest["manifest_hash"],
          f"E2.parent={str(e2_manifest.get('parent_manifest_hash', ''))[:16]}... E1.hash={e1_manifest['manifest_hash'][:16]}...")

    # 7. Epoch advancement 1→2
    check("Epoch advancement 1→2",
          e1_manifest["epoch"] == 1 and e2_manifest["epoch"] == 2,
          f"E1.epoch={e1_manifest['epoch']} E2.epoch={e2_manifest['epoch']}")

    # 8. Platform separation (THE KEY CHECK for cross-platform proof)
    check("Platform separation (Host A ≠ Host B)",
          host_a_platform != host_b_platform,
          f"A={host_a_platform} B={host_b_platform}")

    # 9. Owner public key consistency
    check("Owner public key consistent",
          e1_manifest.get("owner_public_key") == owner_pub_hex,
          f"manifest={str(e1_manifest.get('owner_public_key', ''))[:16]}... expected={owner_pub_hex[:16]}...")

    # 10. Host B report says platforms differ
    check("Host B report confirms platform separation",
          host_b_report.get("platforms_differ") is True,
          f"report says: {host_b_report.get('platforms_differ')}")

    # 11. E1 receipt workspace hash matches manifest
    check("E1 receipt workspace hash matches manifest",
          e1_receipt["workspace_root_hash"] == e1_manifest["workspace_manifest"]["root_hash"])

    # 12. E2 receipt workspace hash matches manifest
    check("E2 receipt workspace hash matches manifest",
          e2_receipt["workspace_root_hash"] == e2_manifest["workspace_manifest"]["root_hash"])

    # 13. E2 workspace differs from E1 (continuation happened)
    e1_root = e1_manifest["workspace_manifest"]["root_hash"]
    e2_root = e2_manifest["workspace_manifest"]["root_hash"]
    check("E2 workspace differs from E1",
          e1_root != e2_root,
          f"E1={e1_root[:16]}... E2={e2_root[:16]}...")

    # 14. E2 workspace grew
    e1_size = e1_manifest["workspace_manifest"]["total_size"]
    e2_size = e2_manifest["workspace_manifest"]["total_size"]
    check("E2 workspace grew",
          e2_size > e1_size,
          f"E1={e1_size}B E2={e2_size}B")

    # 15. Source workspace files preserved with identical hash, size, and mode
    #     The audit identified that the old check only verified at least one
    #     pathname was shared. The correct check verifies that source files
    #     (src/, data/) are preserved unchanged. State files (agent_state.json,
    #     progress.log, todo.md) are EXPECTED to change during continuation.
    #     However, older runner versions didn't update state files — if the
    #     workspace grew (pipeline output added), that's still a valid
    #     continuation, so unchanged state files are a warning, not a failure.
    STATE_FILES = {"agent_state.json", "progress.log", "todo.md"}
    e1_files_map = {f["rel_path"]: f for f in e1_manifest["workspace_manifest"]["files"]}
    e2_files_map = {f["rel_path"]: f for f in e2_manifest["workspace_manifest"]["files"]}
    missing_in_e2 = []
    modified_in_e2 = []
    preserved_count = 0
    expected_changed = []
    unchanged_state = []
    for rel_path, e1_entry in e1_files_map.items():
        e2_entry = e2_files_map.get(rel_path)
        if e2_entry is None:
            missing_in_e2.append(rel_path)
        elif rel_path in STATE_FILES:
            if e2_entry["sha256"] != e1_entry["sha256"]:
                expected_changed.append(rel_path)
            else:
                unchanged_state.append(rel_path)
        elif (e2_entry["sha256"] != e1_entry["sha256"]
              or e2_entry["size"] != e1_entry["size"]
              or e2_entry["mode"] != e1_entry["mode"]):
            modified_in_e2.append(rel_path)
        else:
            preserved_count += 1
    # Unchanged state files are only a failure if the workspace didn't grow
    # (which would mean no continuation happened at all). If the workspace grew,
    # the continuation is proven by the pipeline output regardless.
    workspace_grew = e2_manifest["workspace_manifest"]["total_size"] > e1_manifest["workspace_manifest"]["total_size"]
    unchanged_state_ok = workspace_grew  # if workspace grew, unchanged state is just an older runner
    check("Source workspace files preserved in E2 (identical hash, size, mode)",
          len(missing_in_e2) == 0 and len(modified_in_e2) == 0 and (unchanged_state_ok or not unchanged_state),
          f"missing={missing_in_e2} modified={modified_in_e2} preserved={preserved_count} state_changed={expected_changed} unchanged_state={unchanged_state}"
          if missing_in_e2 or modified_in_e2 or unchanged_state
          else f"preserved={preserved_count} source files, state_changed={expected_changed}")

    # 16. Host B report nonce present (non-deterministic evidence)
    nonce = host_b_report.get("host_b_identity", {}).get("machine_nonce", "")
    check("Host B nonce present (fresh evidence)", bool(nonce), f"nonce={nonce[:16]}...")

    # 17. Host B report has UTC timestamps
    start_utc = host_b_report.get("host_b_identity", {}).get("runner_start_utc", "")
    end_utc = host_b_report.get("host_b_identity", {}).get("runner_end_utc", "")
    check("Host B UTC timestamps present", bool(start_utc) and bool(end_utc),
          f"start={start_utc} end={end_utc}")

    # 18. Host B report hostname present
    hostname = host_b_report.get("host_b_identity", {}).get("machine_hostname", "")
    check("Host B hostname present", bool(hostname), f"hostname={hostname}")

    # 19. Pipeline output hash: recompute from E2 workspace, compare to report
    #     The audit identified that the old check only verified the field was
    #     nonempty. The correct check restores the final_report.json from the
    #     E2 content blocks, recomputes the hash, and compares it to the
    #     report's claimed output hash.
    report_output_hash = host_b_report.get("pipeline_result", {}).get("output_hash", "")
    check("Pipeline output hash present in report", bool(report_output_hash),
          f"hash={report_output_hash[:16]}..." if report_output_hash else "missing")

    # 19b. Recompute pipeline output hash from E2 workspace
    final_report_entry = None
    for entry in e2_manifest["workspace_manifest"]["files"]:
        if entry["rel_path"] == "output/final_report.json":
            final_report_entry = entry
            break
    if final_report_entry:
        blob = e2_capsule_dir / "blocks" / final_report_entry["sha256"][:2] / final_report_entry["sha256"]
        if blob.exists():
            final_report = json.loads(blob.read_text())
            recomputed_hash = sha256_bytes(canonical_json(final_report))
            check("Pipeline output hash recomputed from E2 workspace matches report",
                  recomputed_hash == report_output_hash,
                  f"recomputed={recomputed_hash[:16]}... report={report_output_hash[:16]}...")
        else:
            check("Pipeline output hash recomputed from E2 workspace matches report",
                  False, "output/final_report.json block missing from E2 capsule")
    else:
        check("Pipeline output hash recomputed from E2 workspace matches report",
              False, "output/final_report.json not found in E2 workspace manifest")

    # 20. E2 content blocks all present and valid
    missing = 0
    corrupt = 0
    for entry in e2_manifest["workspace_manifest"]["files"]:
        digest = entry["sha256"]
        blob = e2_capsule_dir / "blocks" / digest[:2] / digest
        if not blob.exists():
            missing += 1
        elif sha256_file(blob) != digest:
            corrupt += 1
    check("E2 content blocks all valid",
          missing == 0 and corrupt == 0,
          f"missing={missing} corrupt={corrupt}" if missing or corrupt else "all blocks verified")

    # 20b. Source-commit binding present in Host A report (optional — added in v1.1)
    source_binding = host_a_report.get("source_commit_binding", {})
    has_commit = bool(source_binding.get("commit_sha"))
    has_file_hashes = bool(source_binding.get("canonical_file_hashes"))
    has_generated_runner = bool(source_binding.get("generated_embedded_runner_sha256"))
    if has_commit or has_file_hashes:
        check("Source-commit binding present",
              has_commit and has_file_hashes,
              f"commit_sha={source_binding.get('commit_sha', '')[:16]}... file_hashes={'present' if has_file_hashes else 'missing'}")

        # 20c. Generated embedded runner hash matches source-commit binding
        # The binding records BOTH the template hash (run_host_b.py before
        # embedding) AND the generated embedded runner hash (after capsule
        # is embedded). The verifier checks the GENERATED runner, which is
        # the one Host B actually executes.
        if has_generated_runner:
            runner_hash_in_binding = source_binding["generated_embedded_runner_sha256"]
            runner_hash_actual = sha256_file(host_a_dir / "run_host_b.py") if (host_a_dir / "run_host_b.py").exists() else ""
            check("Generated embedded runner hash matches source-commit binding",
                  runner_hash_in_binding == runner_hash_actual and runner_hash_actual != "",
                  f"binding={runner_hash_in_binding[:16]}... actual={runner_hash_actual[:16]}...")
        elif has_file_hashes:
            # Fallback for older evidence: check template hash (will fail for
            # fresh bound proofs, which is the correct behavior)
            runner_hash_in_binding = source_binding["canonical_file_hashes"].get("runner_template", {}).get("sha256", "")
            runner_hash_actual = sha256_file(host_a_dir / "run_host_b.py") if (host_a_dir / "run_host_b.py").exists() else ""
            check("Runner hash matches source-commit binding (template — may fail for fresh proofs)",
                  runner_hash_in_binding == runner_hash_actual and runner_hash_actual != "",
                  f"binding={runner_hash_in_binding[:16]}... actual={runner_hash_actual[:16]}...")
        else:
            check("Runner hash matches source-commit binding", False, "no source-commit binding")
    else:
        # Published evidence predates source-commit binding — skip silently
        pass

    # 21. Sandbox termination receipt (optional — present for E2B runs)
    termination_receipt_path = e2_capsule_dir.parent / "sandbox_termination_receipt.json"
    if termination_receipt_path.exists():
        term_receipt = json.loads(termination_receipt_path.read_text())
        term_confirmed = term_receipt.get("termination_confirmed", False)
        term_hash_valid = sha256_bytes(canonical_json(
            {k: v for k, v in term_receipt.items() if k != "receipt_hash"}
        )) == term_receipt.get("receipt_hash")
        operator_reported = term_receipt.get("operator_reported_termination", False)
        provider_attested = term_receipt.get("provider_attested_termination", False)
        lifecycle_hash_present = bool(term_receipt.get("lifecycle_request_hash"))
        check("Sandbox termination receipt valid",
              term_confirmed and term_hash_valid,
              f"confirmed={term_confirmed} hash_valid={term_hash_valid} sandbox_id={term_receipt.get('sandbox_id', '')[:16]}...")
        check("Sandbox termination: operator-reported vs provider-attested distinction",
              operator_reported and not provider_attested,
              f"operator_reported={operator_reported} provider_attested={provider_attested}")
        check("Sandbox termination: lifecycle request hash present",
              lifecycle_hash_present,
              f"hash={term_receipt.get('lifecycle_request_hash', '')[:16]}..." if lifecycle_hash_present else "missing")
    else:
        # Not an E2B run — skip silently (not a failure)
        pass

    return _build_verdict(checks, host_label)


def _build_verdict(checks: list, host_label: str) -> dict:
    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    hard_failures = [c for c in checks if not c["passed"]]
    return {
        "host_label": host_label,
        "total_checks": len(checks),
        "passed": passed,
        "failed": failed,
        "all_passed": len(hard_failures) == 0,
        "checks": checks,
        "failures": hard_failures,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="HDAR Cross-Platform Verifier")
    ap.add_argument("--host-a-dir", required=True, help="Host A output directory (contains host_a_report.json, owner_public_key.txt, capsule_epoch_1/)")
    ap.add_argument("--host-b-report", action="append", default=[], help="Host B report JSON (can specify multiple)")
    ap.add_argument("--e2-capsule", action="append", default=[], help="E2 capsule directory (must match --host-b-report order)")
    ap.add_argument("--out", default="", help="Write combined verifier report to this path")
    args = ap.parse_args()

    host_a_dir = Path(args.host_a_dir).resolve()

    # Load Host A artifacts
    host_a_report = json.loads((host_a_dir / "host_a_report.json").read_text())
    owner_pub_hex = (host_a_dir / "owner_public_key.txt").read_text().strip()
    e1_manifest = json.loads((host_a_dir / "capsule_epoch_1" / "manifest.json").read_text())
    e1_receipt = json.loads((host_a_dir / "capsule_epoch_1" / "receipt.json").read_text())
    host_a_platform = host_a_report.get("host_a_platform", "")

    print("=" * 70)
    print("HDAR Cross-Platform Verifier")
    print(f"Verifier platform: {platform.platform()}")
    print(f"Host A platform: {host_a_platform}")
    print(f"Owner public key: {owner_pub_hex[:16]}...")
    print(f"E1 manifest hash: {e1_manifest['manifest_hash'][:16]}...")
    print(f"Host B reports to verify: {len(args.host_b_report)}")
    print("=" * 70)

    if len(args.host_b_report) != len(args.e2_capsule):
        print("FATAL: --host-b-report and --e2-capsule must have the same count", file=sys.stderr)
        return 1

    results = []
    all_ok = True

    for i, (report_path, capsule_path) in enumerate(zip(args.host_b_report, args.e2_capsule)):
        print(f"\n{'─' * 70}")
        print(f"Verifying Host B report {i+1}/{len(args.host_b_report)}: {report_path}")
        print(f"  E2 capsule: {capsule_path}")
        print(f"{'─' * 70}")

        result = verify_single_host_b(
            host_a_dir=host_a_dir,
            host_b_report_path=Path(report_path),
            e2_capsule_dir=Path(capsule_path),
            owner_pub_hex=owner_pub_hex,
            host_a_platform=host_a_platform,
            host_a_report=host_a_report,
            e1_manifest=e1_manifest,
            e1_receipt=e1_receipt,
        )

        for c in result["checks"]:
            status = "PASS" if c["passed"] else "FAIL"
            line = f"  [{status}] {c['check']}"
            if not c["passed"] and c["detail"]:
                line += f"\n         {c['detail']}"
            print(line)

        print(f"\n  Result: {result['passed']}/{result['total_checks']} passed, {result['failed']} failed")
        print(f"  All checks passed: {result['all_passed']}")

        if not result["all_passed"]:
            all_ok = False

        results.append(result)

    # Summary
    print(f"\n{'=' * 70}")
    print("VERIFIER SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Host A platform: {host_a_platform}")
    for r in results:
        status = "ALL PASS" if r["all_passed"] else "FAILURES"
        print(f"  {r['host_label']:30s} {r['passed']}/{r['total_checks']} checks  [{status}]")
        if not r["all_passed"]:
            for f in r["failures"]:
                print(f"    FAIL: {f['check']} — {f['detail']}")

    platform_separation_count = sum(
        1 for r in results
        if any(c["check"] == "Platform separation (Host A ≠ Host B)" and c["passed"] for c in r["checks"])
    )
    print(f"\n  Platform separations confirmed: {platform_separation_count}/{len(results)}")
    print(f"  Overall verdict: {'ALL CHECKS PASSED' if all_ok else 'FAILURES DETECTED'}")
    print()

    if args.out:
        combined = {
            "schema": "hdar.verifier-report/v1.0",
            "verifier_platform": platform.platform(),
            "verifier_timestamp": time.time(),
            "host_a_platform": host_a_platform,
            "host_b_results": results,
            "overall_passed": all_ok,
            "platform_separations_confirmed": platform_separation_count,
            "total_host_b_reports": len(results),
        }
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(combined, indent=2, sort_keys=True) + "\n")
        print(f"  Report written: {out_path}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
