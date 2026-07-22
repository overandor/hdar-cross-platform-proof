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
    gist_id: str = "",
) -> list[dict]:
    """Build the Burchi JSON action script for Colab automation.

    Burchi can: navigate, find elements by meaning, type, click, extract text.
    Burchi cannot: handle native file upload dialogs or download files from
    Colab's remote VM filesystem.

    Strategy: Burchi handles the login flow (semantic, self-healing).
    The notebook posts evidence to a GitHub Gist via the gist ID.
    """
    actions = [
        # Step 1: Navigate to Colab
        {"action": "goto", "intent": "https://colab.research.google.com", "wait": 3.0},
        {"action": "digest"},

        # Step 2: Login flow — semantic, survives UI changes
        {"action": "find", "intent": "sign in login button"},
        {"action": "click", "intent": "sign in", "wait": 3.0},

        # Google login page — type email
        {"action": "type", "intent": "email input field", "value": google_email},
        {"action": "click", "intent": "next continue button", "wait": 3.0},

        # Google login — type password
        {"action": "type", "intent": "password input field", "value": google_password},
        {"action": "click", "intent": "next sign in button", "wait": 5.0},

        # Step 3: After login, open a new notebook
        {"action": "goto", "intent": "https://colab.research.google.com/#create=true", "wait": 5.0},

        # Step 4: Type the gist ID into the first code cell so the notebook
        # can post evidence back. The notebook code is pre-loaded via the
        # generate_colab_notebook.py output, but for automation we type
        # the gist ID into a cell and run it.
    ]

    if gist_id:
        # Type a cell that sets HDAR_WEBHOOK_URL environment variable
        # The notebook's webhook cell reads this to post evidence
        gist_url = f"https://gist.github.com/{gist_id}"
        actions.append({"action": "type", "intent": "code cell input", "value": f"import os; os.environ['HDAR_GIST_ID'] = '{gist_id}'"})
        actions.append({"action": "click", "intent": "run cell play button", "wait": 2.0})

    actions.extend([
        # Step 5: Run all cells
        {"action": "find", "intent": "runtime run all"},
        {"action": "click", "intent": "runtime menu", "wait": 1.0},
        {"action": "click", "intent": "run all cells", "wait": 30.0},

        # Step 6: Extract page content (cell outputs visible on page)
        {"action": "markdown"},
        {"action": "digest"},
    ])

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
    ap.add_argument("--gist-id", default="", help="GitHub Gist ID for evidence exchange")
    ap.add_argument("--out", default="./evidence/colab", help="Output directory")
    ap.add_argument("--timeout", type=int, default=300, help="Burchi script timeout")
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
        gist_id=args.gist_id,
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
    print("The notebook must post evidence via HTTP webhook — Burchi cannot")
    print("download files from Colab's remote VM filesystem via WKWebView.")
    print("The notebook should include: requests.post(webhook_url, json=evidence)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
