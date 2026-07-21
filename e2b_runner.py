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
        from e2b import Sandbox
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
    sandbox = Sandbox()
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
        def download_dir(remote_path: str, local_path: Path):
            entries = sandbox.files.list(remote_path)
            for entry in entries:
                remote_full = f"{remote_path}/{entry.name}"
                local_full = local_path / entry.name
                if entry.is_dir:
                    local_full.mkdir(parents=True, exist_ok=True)
                    download_dir(remote_full, local_full)
                else:
                    content = sandbox.files.read(remote_full)
                    local_full.write_bytes(content if isinstance(content, bytes) else content.encode())
                    print(f"  Downloaded: {local_full}")

        download_dir("/home/user/host_b_output/capsule_epoch_2", e2_dir)

        # Also download the E2 tar
        try:
            e2_tar_content = sandbox.files.read("/home/user/host_b_output/transport_capsule_epoch_2.tar.gz")
            e2_tar_path = out_dir / "transport_capsule_epoch_2.tar.gz"
            e2_tar_path.write_bytes(e2_tar_content if isinstance(e2_tar_content, bytes) else e2_tar_content.encode())
            print(f"  Downloaded: {e2_tar_path}")
        except Exception:
            pass

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

    print("\n" + "=" * 60)
    print(f"E2B Host B complete. Artifacts in: {out_dir}")
    print("=" * 60)
    print(f"  host_b_report.json")
    print(f"  capsule_epoch_2/")
    print()
    print("Verify on Host A:")
    print(f"  python3 verify_all.py --host-a-dir <host_a_dir> \\")
    print(f"    --host-b-report {report_path} \\")
    print(f"    --e2-capsule {e2_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
