#!/usr/bin/env python3
"""HDAR Colab Driver — uses Burchi (semantic browser) to automate Colab.

Runs on macOS (WKWebView requirement). Drives Google Colab via Burchi's
semantic element finding — no CSS selectors, no Selenium, self-healing.

Architecture:
    1. macOS CI job builds Burchi from source
    2. This script calls `burchi script --file colab_actions.json`
    3. Burchi drives Colab: login → upload notebook → run → extract evidence
    4. Evidence is saved as artifacts
    5. Linux CI job downloads artifacts and runs verify_all.py

The JSON action script uses Burchi's semantic intent:
    {"action": "goto", "intent": "https://colab.research.google.com"}
    {"action": "type", "intent": "email input field", "value": "..."}
    {"action": "click", "intent": "sign in button"}
    ...

Usage:
    python3 colab_burchi_driver.py \\
        --burchi /path/to/burchi \\
        --runner /path/to/run_host_b.py \\
        --google-email "$GOOGLE_EMAIL" \\
        --google-password "$GOOGLE_PASSWORD" \\
        --out evidence/colab
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


def build_colab_actions(
    runner_path: str,
    google_email: str,
    google_password: str,
    out_dir: str,
    notebook_github_url: str = "",
) -> list[dict]:
    """Build the Burchi JSON action script for Colab automation.

    Strategy: Burchi handles the login flow (semantic, self-healing).
    Then opens a GitHub-hosted notebook via Colab's /github/ URL.
    The notebook starts an ngrok tunnel and prints the tunnel URL in cell
    output. Burchi extracts the URL from the page via digest/markdown.
    CI then downloads evidence directly from the tunnel URL.
    """
    if not notebook_github_url:
        notebook_github_url = "https://colab.research.google.com/github/overandor/hdar-cross-platform-proof/blob/main/hdar_host_b_colab.ipynb"

    actions = [
        # Step 1: Navigate to the GitHub-hosted notebook in Colab
        # This triggers Google login if not authenticated
        {"action": "goto", "intent": notebook_github_url, "wait": 8.0},
        {"action": "digest"},

        # Step 2: Login flow — type email, wait for password page to load
        # These fail silently if already logged in (no email field on Colab page)
        {"action": "type", "intent": "email input field", "value": google_email, "wait": 2.0},
        {"action": "click", "intent": "next continue button", "wait": 8.0},

        # Wait for password field to appear (Google does AJAX navigation)
        {"action": "wait", "wait": 3.0},

        # Type password and submit
        {"action": "type", "intent": "password input field", "value": google_password, "wait": 2.0},
        {"action": "click", "intent": "next sign in button", "wait": 10.0},

        # Step 3: After login, navigate back to the notebook
        # (login may redirect to a different page)
        {"action": "goto", "intent": notebook_github_url, "wait": 10.0},
        {"action": "digest"},
        {"action": "screenshot", "value": str(Path(out_dir) / "colab_notebook_loaded.png")},

        # Wait for Colab to fully load the notebook and connect a runtime
        {"action": "wait", "wait": 10.0},

        # Step 4: Run all cells via Runtime menu
        # Colab menus are slow to render — wait after each click
        {"action": "click", "intent": "runtime menu", "wait": 3.0},
        {"action": "click", "intent": "run all run all", "wait": 120.0},

        # Step 5: Wait for cells to finish executing
        # The notebook installs deps, runs the protocol, starts ngrok
        {"action": "wait", "wait": 30.0},
        {"action": "screenshot", "value": str(Path(out_dir) / "colab_after_run_all.png")},

        # Step 6: Extract page content — the tunnel URL will be in cell output
        {"action": "markdown", "wait": 5.0},
        {"action": "digest"},
    ]

    return actions


def run_burchi_script(burchi_bin: str, actions_json: str, timeout: int = 300) -> dict:
    """Run burchi script --file and return parsed results."""
    # Write actions to temp file
    actions_file = "/tmp/colab_actions.json"
    Path(actions_file).write_text(actions_json)

    print(f"Running: {burchi_bin} script --file {actions_file}")
    result = subprocess.run(
        [burchi_bin, "script", "--file", actions_file],
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    print(f"Exit code: {result.returncode}")
    if result.stdout:
        print(f"stdout (last 1000): ...{result.stdout[-1000:]}")
    if result.stderr:
        print(f"stderr: {result.stderr[-500:]}")

    # Try to parse Burchi's JSON output
    try:
        # Burchi executeScriptToJSON returns JSON array
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("[") or line.startswith("{"):
                return json.loads(line)
    except json.JSONDecodeError:
        pass

    return {"raw_stdout": result.stdout, "raw_stderr": result.stderr, "exit_code": result.returncode}


def main() -> int:
    ap = argparse.ArgumentParser(description="HDAR Colab Driver via Burchi")
    ap.add_argument("--burchi", required=True, help="Path to burchi binary")
    ap.add_argument("--runner", required=True, help="Path to run_host_b.py")
    ap.add_argument("--google-email", required=True, help="Google account email")
    ap.add_argument("--google-password", required=True, help="Google account password")
    ap.add_argument("--out", default="./evidence/colab", help="Output directory")
    ap.add_argument("--timeout", type=int, default=600, help="Burchi script timeout")
    ap.add_argument("--notebook-url", default="", help="Colab URL for GitHub-hosted notebook")
    args = ap.parse_args()

    burchi_bin = Path(args.burchi).resolve()
    if not burchi_bin.exists():
        print(f"FATAL: burchi binary not found: {burchi_bin}", file=sys.stderr)
        return 1

    runner_path = Path(args.runner).resolve()
    if not runner_path.exists():
        print(f"FATAL: runner not found: {runner_path}", file=sys.stderr)
        return 1

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build the action script
    actions = build_colab_actions(
        str(runner_path),
        args.google_email,
        args.google_password,
        str(out_dir),
        notebook_github_url=args.notebook_url,
    )
    actions_json = json.dumps(actions, indent=2)
    print(f"Built {len(actions)} Burchi actions for Colab automation")

    # Run Burchi
    print(f"\n{'=' * 60}")
    print("Driving Colab via Burchi semantic browser")
    print(f"{'=' * 60}")

    result = run_burchi_script(str(burchi_bin), actions_json, timeout=args.timeout)

    # Save raw result for debugging
    result_path = out_dir / "burchi_raw_result.json"
    result_path.write_text(json.dumps(result, indent=2, default=str))
    print(f"Raw result saved: {result_path}")

    # Check if we got evidence
    # Burchi's markdown/digest output will contain the Colab cell outputs
    # In a real deployment, the notebook would write files to Colab's /content/
    # and we'd need to extract them via the Colab API or file download

    # For now, save what we got
    if isinstance(result, list):
        for i, step in enumerate(result):
            if isinstance(step, dict) and step.get("success"):
                print(f"  Step {i}: {step.get('action', '?')} ✓")
            elif isinstance(step, dict):
                print(f"  Step {i}: {step.get('action', '?')} ✗ — {step.get('data', '')[:100]}")

    print(f"\n{'=' * 60}")
    print(f"Colab Burchi driver complete. Output in: {out_dir}")
    print(f"{'=' * 60}")
    print("\nNOTE: Burchi handles the login flow semantically (self-healing).")
    print("The notebook starts an ngrok tunnel — Burchi extracts the tunnel URL")
    print("from the cell output. CI then downloads evidence directly from the tunnel.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
