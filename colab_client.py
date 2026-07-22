#!/usr/bin/env python3
"""HDAR Colab Client — calls the Gradio server running on Colab.

This is the CI/CD side. It sends run_host_b.py to the Colab Gradio server,
receives the evidence (host_b_report.json + capsule_epoch_2), and saves it
locally for verification.

The Colab server must be running (browser tab open on any machine).
The Gradio public URL is the "synthetic API key" — set it as
COLAB_GRADIO_URL in GitHub Actions secrets.

Usage:
    python3 colab_client.py \\
        --url https://abc123.gradio.live \\
        --runner /path/to/run_host_b.py \\
        --out evidence/colab

In CI (with secret):
    COLAB_GRADIO_URL = ${{ secrets.COLAB_GRADIO_URL }}
    python3 colab_client.py --url "$COLAB_GRADIO_URL" --runner run_host_b.py --out evidence/colab
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import tarfile
import io
from pathlib import Path


def call_colab_server(url: str, runner_b64: str, timeout: int = 180) -> dict:
    """Call the Gradio API on Colab and return the result dict."""
    try:
        from gradio_client import Client
    except ImportError:
        print("ERROR: gradio_client not installed. Install: pip install gradio_client", file=sys.stderr)
        sys.exit(1)

    # Gradio Client connects to the public URL
    client = Client(url)

    # Call the run_host_b API endpoint
    # The fn_index or api_name maps to the function we exposed
    result = client.predict(
        runner_b64,
        api_name="/run_host_b",
    )

    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="HDAR Colab Client — call Gradio server on Colab")
    ap.add_argument("--url", required=True,
                    help="Gradio public URL (e.g. https://abc123.gradio.live)")
    ap.add_argument("--runner", required=True,
                    help="Path to run_host_b.py (with embedded capsule)")
    ap.add_argument("--out", default="./evidence/colab",
                    help="Output directory for evidence")
    ap.add_argument("--timeout", type=int, default=180,
                    help="Timeout in seconds for the API call")
    args = ap.parse_args()

    # Read and encode the runner script
    runner_path = Path(args.runner).resolve()
    if not runner_path.exists():
        print(f"FATAL: runner not found: {runner_path}", file=sys.stderr)
        return 1

    runner_code = runner_path.read_text()
    runner_b64 = base64.b64encode(runner_code.encode()).decode()
    print(f"Runner encoded: {len(runner_code)} bytes → {len(runner_b64)} base64 chars")

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Call the Colab server
    print(f"Connecting to Colab Gradio server: {args.url}")
    print("Sending runner script and waiting for Host B execution...")

    result = call_colab_server(args.url, runner_b64, timeout=args.timeout)

    if not result or not result.get("success"):
        error = result.get("error", "unknown error") if result else "no response"
        print(f"FATAL: Colab Host B failed: {error}", file=sys.stderr)
        if result and result.get("stderr"):
            print(f"stderr: {result['stderr'][-500:]}", file=sys.stderr)
        return 1

    # Decode and save the report
    report_b64 = result.get("report_b64", "")
    if not report_b64:
        print("FATAL: No report_b64 in response", file=sys.stderr)
        return 1

    report_json = base64.b64decode(report_b64).decode()
    report_path = out_dir / "host_b_report.json"
    report_path.write_text(report_json)
    print(f"Report saved: {report_path}")

    # Decode and extract the capsule
    capsule_b64 = result.get("capsule_b64", "")
    if not capsule_b64:
        print("FATAL: No capsule_b64 in response", file=sys.stderr)
        return 1

    capsule_bytes = base64.b64decode(capsule_b64)
    capsule_dir = out_dir / "capsule_epoch_2"
    capsule_dir.mkdir(parents=True, exist_ok=True)

    with tarfile.open(fileobj=io.BytesIO(capsule_bytes), mode="r:gz") as tar:
        tar.extractall(out_dir)

    print(f"Capsule extracted: {capsule_dir}")

    # Print platform info
    print(f"\nColab platform: {result.get('platform', 'unknown')}")
    print(f"Colab hostname: {result.get('hostname', 'unknown')}")
    print(f"Python version: {result.get('python_version', 'unknown')}")

    if result.get("stdout"):
        print(f"\nHost B stdout (last 500 chars):")
        print(result["stdout"][-500:])

    print(f"\n{'=' * 60}")
    print(f"Colab Host B complete. Evidence in: {out_dir}")
    print(f"{'=' * 60}")
    print(f"\nVerify on Host A:")
    print(f"  python3 verify_all.py \\")
    print(f"    --host-a-dir <host_a_dir> \\")
    print(f"    --host-b-report {report_path} \\")
    print(f"    --e2-capsule {capsule_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
