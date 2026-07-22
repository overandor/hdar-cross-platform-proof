#!/usr/bin/env python3
"""HDAR Webhook Receiver — collects evidence from Colab notebook via GitHub Gist.

The Colab VM can make outbound HTTP but the macOS CI runner is behind NAT.
This script uses a GitHub Gist as a dead drop:

  1. CI creates a Gist with a placeholder file
  2. CI passes the Gist URL to the notebook (via Burchi typing it into a cell)
  3. Notebook posts evidence JSON to the Gist via GitHub API
  4. CI polls the Gist for evidence
  5. CI downloads and saves evidence locally

Usage:
    python3 webhook_receiver.py --gist-id <id> --out evidence/colab --timeout 300
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def create_gist() -> str:
    """Create a GitHub Gist for evidence exchange. Returns gist ID."""
    result = subprocess.run(
        ["gh", "gist", "create", "--public", "-"],
        input="HDAR evidence placeholder — will be replaced by Colab notebook output.\n",
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"FATAL: Failed to create gist: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    gist_url = result.stdout.strip()
    gist_id = gist_url.split("/")[-1]
    print(f"Created gist: {gist_url} (id: {gist_id})")
    return gist_id


def poll_gist(gist_id: str, timeout: int = 300) -> dict | None:
    """Poll gist for evidence JSON. Returns parsed evidence or None.

    The notebook PATCHes the gist to add an 'evidence.json' file.
    We poll via gh gist view --raw which returns all file contents.
    """
    deadline = time.time() + timeout
    poll_interval = 10

    while time.time() < deadline:
        result = subprocess.run(
            ["gh", "gist", "view", gist_id, "--raw"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"  Polling gist... (error: {result.stderr[:100]})")
            time.sleep(poll_interval)
            continue

        content = result.stdout.strip()
        # The gist may have multiple files. Look for evidence.json content.
        # gh gist view --raw concatenates all files with separators.
        # We search for the JSON payload containing host_b_report.
        if "host_b_report" in content:
            # Try to extract the JSON object from the concatenated output
            try:
                # First try: the whole content might be JSON
                evidence = json.loads(content)
                print(f"  Evidence received from gist!")
                return evidence
            except json.JSONDecodeError:
                # Second try: find the JSON block in the content
                start = content.find('{"host_b_report"')
                if start == -1:
                    start = content.find("{\n  \"host_b_report\"")
                if start >= 0:
                    # Find matching closing brace
                    depth = 0
                    for i in range(start, len(content)):
                        if content[i] == '{':
                            depth += 1
                        elif content[i] == '}':
                            depth -= 1
                            if depth == 0:
                                try:
                                    evidence = json.loads(content[start:i+1])
                                    print(f"  Evidence received from gist!")
                                    return evidence
                                except json.JSONDecodeError:
                                    break

        elapsed = int(time.time() - (deadline - timeout))
        print(f"  Polling gist... ({elapsed}s / {timeout}s)")
        time.sleep(poll_interval)

    return None


def save_evidence(evidence: dict, out_dir: Path) -> bool:
    """Save evidence JSON to local files for verification."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # Save host_b_report.json
    report = evidence.get("host_b_report")
    if not report:
        print("FATAL: No host_b_report in evidence", file=sys.stderr)
        return False

    report_path = out_dir / "host_b_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(f"  Saved: {report_path} ({report_path.stat().st_size} bytes)")

    # Extract and save capsule_epoch_2
    capsule_b64 = evidence.get("capsule_epoch_2_tar_b64")
    if capsule_b64:
        tar_path = out_dir / "capsule_epoch_2.tar.gz"
        tar_path.write_bytes(base64.b64decode(capsule_b64))
        print(f"  Saved: {tar_path} ({tar_path.stat().st_size} bytes)")

        # Extract capsule
        capsule_dir = out_dir / "capsule_epoch_2"
        if capsule_dir.exists():
            import shutil
            shutil.rmtree(capsule_dir)
        subprocess.run(
            ["tar", "xzf", str(tar_path), "-C", str(out_dir)],
            check=True,
        )
        print(f"  Extracted: {capsule_dir}")

    return True


def delete_gist(gist_id: str) -> None:
    """Delete the temporary gist."""
    result = subprocess.run(
        ["gh", "gist", "delete", gist_id, "--yes"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print(f"  Cleaned up gist: {gist_id}")
    else:
        print(f"  WARNING: Could not delete gist {gist_id}: {result.stderr}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description="HDAR webhook receiver via GitHub Gist")
    ap.add_argument("--gist-id", help="Existing gist ID (skip creation)")
    ap.add_argument("--out", default="./evidence/colab", help="Output directory")
    ap.add_argument("--timeout", type=int, default=300, help="Poll timeout in seconds")
    ap.add_argument("--keep-gist", action="store_true", help="Don't delete gist after")
    args = ap.parse_args()

    out_dir = Path(args.out).resolve()

    # Create or reuse gist
    gist_id = args.gist_id or create_gist()

    print(f"\nWaiting for Colab notebook to post evidence to gist {gist_id}...")
    print(f"Timeout: {args.timeout}s")

    evidence = poll_gist(gist_id, timeout=args.timeout)

    if not evidence:
        print("FATAL: Timed out waiting for evidence from Colab", file=sys.stderr)
        if not args.keep_gist:
            delete_gist(gist_id)
        return 1

    # Save evidence
    print(f"\nSaving evidence to {out_dir}...")
    if not save_evidence(evidence, out_dir):
        if not args.keep_gist:
            delete_gist(gist_id)
        return 1

    # Cleanup
    if not args.keep_gist:
        delete_gist(gist_id)

    print(f"\nEvidence saved to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
