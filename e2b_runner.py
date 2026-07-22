#!/usr/bin/env python3
"""HDAR Host B — E2B Sandbox Runner

Runs the HDAR Host B protocol inside an E2B sandbox for isolated, reproducible
execution on a separate Linux instance.

Prerequisites:
    pip install e2b

Usage:
    python3 e2b_runner.py --runner /path/to/run_host_b.py

The runner script (with embedded capsule) is uploaded to the E2B sandbox,
executed, and the artifacts are downloaded back.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="HDAR Host B — E2B Sandbox Runner")
    ap.add_argument("--runner", required=True, help="Path to run_host_b.py (with embedded capsule)")
    ap.add_argument("--out", default="./e2b_output", help="Local output directory for downloaded artifacts")
    ap.add_argument("--host-label", default="", help="Host label (auto-detected if empty)")
    args = ap.parse_args()

    runner_path = Path(args.runner).resolve()
    if not runner_path.exists():
        print(f"FATAL: runner not found: {runner_path}", file=sys.stderr)
        return 1

    try:
        from e2b import Sandbox, FileType
    except ImportError:
        print("E2B package not installed. Install: pip install e2b", file=sys.stderr)
        print("Also set E2B_API_KEY environment variable.", file=sys.stderr)
        return 1

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    host_label = args.host_label or "e2b-sandbox"

    print("=" * 60)
    print("HDAR Host B — E2B Sandbox")
    print("=" * 60)

    # Start sandbox
    print("\n[1/5] Starting E2B sandbox...")
    sandbox = Sandbox.create()
    print(f"  Sandbox ID: {sandbox.sandbox_id}")
    print(f"  Sandbox started")

    try:
        # Upload runner
        print("\n[2/5] Uploading run_host_b.py to sandbox...")
        sandbox.files.write("/home/user/run_host_b.py", runner_path.read_text())
        print(f"  Uploaded: {runner_path.stat().st_size} bytes")

        # Install cryptography
        print("\n[3/5] Installing cryptography in sandbox...")
        result = sandbox.commands.run(
            "pip install cryptography -q",
            timeout=60,
        )
        print(f"  pip install: exit={result.exit_code}")

        # Check platform
        result = sandbox.commands.run("python3 -c 'import platform; print(platform.platform())'")
        sandbox_platform = result.stdout.strip()
        print(f"  Sandbox platform: {sandbox_platform}")

        # Run Host B
        print("\n[4/5] Running Host B in sandbox...")
        result = sandbox.commands.run(
            f"cd /home/user && python3 run_host_b.py --out /home/user/host_b_output --host-label {host_label} --operator e2b-sandbox",
            timeout=120,
        )
        print(f"  Exit code: {result.exit_code}")
        if result.stdout:
            print(f"  stdout (last 500 chars): ...{result.stdout[-500:]}")
        if result.stderr:
            print(f"  stderr: {result.stderr[-500:]}")

        if result.exit_code != 0:
            print("FATAL: Host B failed in sandbox", file=sys.stderr)
            return 1

        # Download artifacts
        print("\n[5/5] Downloading artifacts from sandbox...")

        # Download host_b_report.json
        report_content = sandbox.files.read("/home/user/host_b_output/host_b_report.json")
        report_path = out_dir / "host_b_report.json"
        report_path.write_text(report_content)
        print(f"  Downloaded: {report_path}")

        # Download capsule_epoch_2 directory
        e2_dir = out_dir / "capsule_epoch_2"
        e2_dir.mkdir(parents=True, exist_ok=True)

        # List and download all files in capsule_epoch_2
        def download_dir(remote_path: str, local_path: Path) -> int:
            downloaded = 0
            try:
                entries = sandbox.files.list(remote_path)
            except Exception as e:
                print(f"  ERROR listing {remote_path}: {e}", file=sys.stderr)
                return 0
            if not entries:
                print(f"  WARNING: {remote_path} is empty or does not exist", file=sys.stderr)
                return 0
            for entry in entries:
                remote_full = f"{remote_path}/{entry.name}"
                local_full = local_path / entry.name
                if entry.type == FileType.DIR:
                    local_full.mkdir(parents=True, exist_ok=True)
                    downloaded += download_dir(remote_full, local_full)
                else:
                    try:
                        content = sandbox.files.read(remote_full)
                        local_full.write_bytes(content if isinstance(content, bytes) else content.encode())
                        print(f"  Downloaded: {local_full} ({local_full.stat().st_size} bytes)")
                        downloaded += 1
                    except Exception as e:
                        print(f"  ERROR downloading {remote_full}: {e}", file=sys.stderr)
            return downloaded

        capsule_file_count = download_dir("/home/user/host_b_output/capsule_epoch_2", e2_dir)
        print(f"  Capsule files downloaded: {capsule_file_count}")

        if capsule_file_count == 0:
            print("FATAL: No capsule files downloaded — sandbox will be killed but evidence is incomplete", file=sys.stderr)
            # Don't return yet — still kill sandbox and generate receipt

        # Verify downloaded files actually exist on disk
        local_files = list(e2_dir.rglob("*"))
        local_files = [f for f in local_files if f.is_file()]
        print(f"  Local capsule files on disk: {len(local_files)}")
        if len(local_files) != capsule_file_count:
            print(f"  WARNING: Mismatch — downloaded {capsule_file_count} but found {len(local_files)} on disk", file=sys.stderr)

        # Also download the E2 tar
        try:
            e2_tar_content = sandbox.files.read("/home/user/host_b_output/transport_capsule_epoch_2.tar.gz")
            e2_tar_path = out_dir / "transport_capsule_epoch_2.tar.gz"
            e2_tar_path.write_bytes(e2_tar_content if isinstance(e2_tar_content, bytes) else e2_tar_content.encode())
            print(f"  Downloaded: {e2_tar_path} ({e2_tar_path.stat().st_size} bytes)")
        except Exception as e:
            print(f"  WARNING: Could not download transport tar: {e}", file=sys.stderr)

    finally:
        # Kill sandbox and generate termination receipt
        print("\n  Terminating sandbox...")
        termination_requested_utc = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
        sandbox.kill()
        print(f"  Sandbox {sandbox.sandbox_id} terminated.")

        termination_confirmed = True
        try:
            _ = sandbox.commands.run("echo alive", timeout=5)
            termination_confirmed = False
        except Exception:
            pass

        termination_receipt = {
            "schema": "hdar.sandbox-termination-receipt/v1.0",
            "sandbox_id": sandbox.sandbox_id,
            "termination_requested": True,
            "termination_confirmed": termination_confirmed,
            "confirmed_state": "killed",
            "termination_requested_utc": termination_requested_utc,
            "termination_confirmed_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "verification_method": "post-kill command execution attempt (exception = confirmed dead)",
            "operator_reported_termination": True,
            "provider_attested_termination": False,
            "provider_attestation_note": "E2B API does not expose a signed termination attestation; operator reports kill() call and post-kill confirmation",
            "lifecycle_request_hash": __import__("hashlib").sha256(
                f"{sandbox.sandbox_id}:{termination_requested_utc}".encode()
            ).hexdigest(),
        }
        receipt_hash = __import__("hashlib").sha256(
            __import__("json").dumps(
                {k: v for k, v in termination_receipt.items()},
                sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
        ).hexdigest()
        termination_receipt["receipt_hash"] = receipt_hash
        receipt_path = out_dir / "sandbox_termination_receipt.json"
        receipt_path.write_text(__import__("json").dumps(termination_receipt, indent=2, sort_keys=True) + "\n")
        print(f"  Termination receipt: {receipt_path}")
        print(f"  Confirmed dead: {termination_confirmed}")

    # Post-kill evidence verification
    print("\n" + "=" * 60)
    print(f"E2B Host B complete. Artifacts in: {out_dir}")
    print("=" * 60)

    report_exists = report_path.exists()
    capsule_files = [f for f in e2_dir.rglob("*") if f.is_file()] if e2_dir.exists() else []
    tar_exists = (out_dir / "transport_capsule_epoch_2.tar.gz").exists()

    print(f"  host_b_report.json: {'PRESENT' if report_exists else 'MISSING'}")
    print(f"  capsule_epoch_2/: {len(capsule_files)} files")
    for f in capsule_files:
        print(f"    {f.relative_to(e2_dir)} ({f.stat().st_size} bytes)")
    print(f"  transport_capsule_epoch_2.tar.gz: {'PRESENT' if tar_exists else 'MISSING'}")

    if not report_exists or len(capsule_files) == 0:
        print("\nFATAL: Evidence incomplete — report or capsule files missing.", file=sys.stderr)
        print("The sandbox was killed but artifacts were not fully downloaded.", file=sys.stderr)
        return 1

    print()
    print("Verify on Host A:")
    print(f"  python3 verify_all.py --host-a-dir <host_a_dir> \\")
    print(f"    --host-b-report {report_path} \\")
    print(f"    --e2-capsule {e2_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
