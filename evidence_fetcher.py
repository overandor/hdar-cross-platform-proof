#!/usr/bin/env python3
"""HDAR Evidence Fetcher — downloads evidence from Colab via ngrok tunnel.

The Colab notebook starts an HTTP server + ngrok tunnel and prints the
tunnel URL in cell output. Burchi extracts the URL from the page.
This script takes the tunnel URL and downloads evidence files directly.

Architecture:
  1. Colab notebook starts HTTP server on port 8080 + ngrok tunnel
  2. Notebook prints HDAR_TUNNEL_URL=<url> in cell output
  3. Burchi extracts the URL from the page (digest/markdown)
  4. This script fetches /manifest.json, then downloads each file
  5. Evidence is saved locally for verification

Usage:
    python3 evidence_fetcher.py --tunnel-url https://abc123.ngrok.io --out evidence/colab --timeout 300
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import requests


def extract_tunnel_url(raw_output: str) -> str | None:
    """Extract ngrok tunnel URL from Burchi raw output or page text."""
    # Look for HDAR_TUNNEL_URL=<url> pattern
    match = re.search(r"HDAR_TUNNEL_URL=(https?://[^\s]+)", raw_output)
    if match:
        return match.group(1)

    # Fallback: look for any ngrok.io URL
    match = re.search(r"(https?://[a-z0-9-]+\.ngrok(?:\.io|\.app)[^\s]*)", raw_output)
    if match:
        return match.group(1)

    # Fallback: look for any URL followed by /manifest.json
    match = re.search(r"(https?://[^\s]+)/manifest\.json", raw_output)
    if match:
        return match.group(1)

    return None


def wait_for_tunnel_url(raw_file: Path, timeout: int = 120) -> str | None:
    """Poll a file for the tunnel URL (written by Burchi driver)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if raw_file.exists():
            content = raw_file.read_text()
            url = extract_tunnel_url(content)
            if url:
                return url
        time.sleep(5)
    return None


def fetch_evidence(tunnel_url: str, out_dir: Path, timeout: int = 300) -> bool:
    """Download evidence files from the tunnel URL."""
    out_dir.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + timeout
    poll_interval = 10

    while time.time() < deadline:
        try:
            resp = requests.get(f"{tunnel_url}/manifest.json", timeout=15)
            if resp.status_code == 200:
                manifest = resp.json()
                print(f"  Manifest received: {manifest.get('files', [])}")
                print(f"  Platform: {manifest.get('platform', 'unknown')}")
                print(f"  Hostname: {manifest.get('hostname', 'unknown')}")

                all_ok = True
                for filename in manifest.get("files", []):
                    file_url = f"{tunnel_url}/{filename}"
                    print(f"  Downloading {filename}...", end=" ")
                    file_resp = requests.get(file_url, timeout=60)
                    if file_resp.status_code == 200:
                        dest = out_dir / filename
                        dest.write_bytes(file_resp.content)
                        print(f"({len(file_resp.content)} bytes) ✓")
                    else:
                        print(f"HTTP {file_resp.status_code} ✗")
                        all_ok = False

                if all_ok:
                    # Save manifest alongside evidence
                    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
                    return True
            else:
                elapsed = int(time.time() - (deadline - timeout))
                print(f"  Waiting for tunnel... ({elapsed}s / {timeout}s) HTTP {resp.status_code}")
        except requests.exceptions.RequestException as e:
            elapsed = int(time.time() - (deadline - timeout))
            print(f"  Waiting for tunnel... ({elapsed}s / {timeout}s) {type(e).__name__}")

        time.sleep(poll_interval)

    return False


def extract_capsule(out_dir: Path) -> None:
    """Extract the capsule tarball if present."""
    tar_path = out_dir / "capsule_epoch_2.tar.gz"
    if tar_path.exists():
        capsule_dir = out_dir / "capsule_epoch_2"
        if capsule_dir.exists():
            import shutil
            shutil.rmtree(capsule_dir)
        subprocess.run(["tar", "xzf", str(tar_path), "-C", str(out_dir)], check=True)
        print(f"  Extracted: {capsule_dir}")


def main() -> int:
    ap = argparse.ArgumentParser(description="HDAR evidence fetcher via ngrok tunnel")
    ap.add_argument("--tunnel-url", default="", help="ngrok tunnel URL (if known)")
    ap.add_argument("--raw-file", default="", help="Path to Burchi raw output file to extract URL from")
    ap.add_argument("--out", default="./evidence/colab", help="Output directory")
    ap.add_argument("--timeout", type=int, default=300, help="Poll timeout in seconds")
    args = ap.parse_args()

    out_dir = Path(args.out).resolve()

    tunnel_url = args.tunnel_url
    if not tunnel_url and args.raw_file:
        raw_path = Path(args.raw_file).resolve()
        print(f"Waiting for tunnel URL in {raw_path}...")
        tunnel_url = wait_for_tunnel_url(raw_path, timeout=args.timeout)

    if not tunnel_url:
        print("FATAL: No tunnel URL provided or found in raw output", file=sys.stderr)
        print("Usage: --tunnel-url <url> OR --raw-file <path>", file=sys.stderr)
        return 1

    print(f"\nFetching evidence from tunnel: {tunnel_url}")
    print(f"Timeout: {args.timeout}s")

    if not fetch_evidence(tunnel_url, out_dir, timeout=args.timeout):
        print("FATAL: Timed out waiting for evidence from tunnel", file=sys.stderr)
        return 1

    # Extract capsule
    extract_capsule(out_dir)

    print(f"\nEvidence saved to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
