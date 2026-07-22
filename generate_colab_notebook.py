#!/usr/bin/env python3
"""Generates a Google Colab notebook (.ipynb) for running HDAR Host B.

Usage:
    python3 generate_colab_notebook.py --runner /path/to/run_host_b.py --out hdar_host_b_colab.ipynb

Then upload the notebook to Google Colab and run all cells.
"""
import argparse
import json
import base64
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate Colab notebook for HDAR Host B")
    ap.add_argument("--runner", required=True, help="Path to run_host_b.py (with embedded capsule)")
    ap.add_argument("--out", default="hdar_host_b_colab.ipynb", help="Output notebook path")
    args = ap.parse_args()

    runner_code = Path(args.runner).read_text()

    cells = [
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "# HDAR Host B — Cross-Platform Continuation Proof\n",
                "\n",
                "This notebook runs the HDAR Host B protocol on Google Colab.\n",
                "\n",
                "**What it does:**\n",
                "1. Installs the `cryptography` package\n",
                "2. Writes the embedded `run_host_b.py` runner to disk\n",
                "3. Executes it — restoring the capsule, verifying the Ed25519 signature, running the pipeline, sealing Epoch 2\n",
                "4. Downloads the Host B report and E2 capsule\n",
                "\n",
                "**Platform evidence:** Colab runs on Linux (Ubuntu). This is real platform separation from Host A (macOS)."
            ],
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "!pip install cryptography -q\n",
                "import platform\n",
                "print(f'Platform: {platform.platform()}')\n",
                "print(f'Python: {platform.python_version()}')"
            ],
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## Write runner script\n",
                "\n",
                "The `run_host_b.py` script has the Epoch 1 capsule embedded as base64."
            ],
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                f"runner_code = {repr(runner_code)}\n",
                "with open('run_host_b.py', 'w') as f:\n",
                "    f.write(runner_code)\n",
                "print(f'Runner written: {{len(runner_code)}} bytes')"
            ],
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## Run Host B\n",
                "\n",
                "This restores the capsule, verifies the signature, executes the pipeline, and seals Epoch 2."
            ],
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "!python3 run_host_b.py --out ./host_b_output --host-label colab-$(hostname) --operator colab-user"
            ],
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## Show the Host B report"
            ],
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "import json\n",
                "with open('./host_b_output/host_b_report.json') as f:\n",
                "    report = json.load(f)\n",
                "print(json.dumps(report, indent=2))"
            ],
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## Post evidence via HTTP webhook\n",
                "\n",
                "Posts the Host B report and E2 capsule back to the CI job.\n",
                "This replaces files.download() which doesn't work in automated browser sessions."
            ],
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "import requests, json, base64, os, shutil\n",
                "\n",
                "GIST_ID = os.environ.get('HDAR_GIST_ID', '')\n",
                "GH_TOKEN = os.environ.get('HDAR_GH_TOKEN', '')\n",
                "if not GIST_ID:\n",
                "    GIST_ID = input('Enter gist ID for evidence exchange (or press Enter to skip): ').strip()\n",
                "if not GH_TOKEN and GIST_ID:\n",
                "    GH_TOKEN = input('Enter GitHub token (gist scope): ').strip()\n",
                "\n",
                "if GIST_ID and GH_TOKEN:\n",
                "    # Read host_b_report.json\n",
                "    with open('./host_b_output/host_b_report.json') as f:\n",
                "        report = json.load(f)\n",
                "\n",
                "    # Pack E2 capsule as base64 tarball\n",
                "    shutil.make_archive('/tmp/capsule_epoch_2', 'gztar', './host_b_output/capsule_epoch_2')\n",
                "    with open('/tmp/capsule_epoch_2.tar.gz', 'rb') as f:\n",
                "        capsule_b64 = base64.b64encode(f.read()).decode()\n",
                "\n",
                "    payload = {\n",
                "        'host_b_report': report,\n",
                "        'capsule_epoch_2_tar_b64': capsule_b64,\n",
                "        'platform': __import__('platform').platform(),\n",
                "        'hostname': __import__('socket').gethostname(),\n",
                "    }\n",
                "\n",
                "    # Post evidence to GitHub Gist via API\n",
                "    print(f'Posting evidence to gist {GIST_ID}...')\n",
                "    resp = requests.patch(\n",
                "        f'https://api.github.com/gists/{GIST_ID}',\n",
                "        json={'files': {'evidence.json': {'content': json.dumps(payload, indent=2)}}},\n",
                "        headers={\n",
                "            'Accept': 'application/vnd.github.v3+json',\n",
                "            'Authorization': f'token {GH_TOKEN}',\n",
                "        },\n",
                "        timeout=30,\n",
                "    )\n",
                "    print(f'Gist API response: {resp.status_code}')\n",
                "    if resp.status_code == 200:\n",
                "        print('Evidence posted to gist successfully.')\n",
                "    else:\n",
                "        print(f'ERROR: {resp.text[:200]}')\n",
                "        print('FALLBACK: Evidence JSON below — copy manually:')\n",
                "        print(json.dumps(payload, indent=2))\n",
                "else:\n",
                "    print('No gist ID or token — falling back to files.download()')\n",
                "    from google.colab import files\n",
                "    shutil.make_archive('capsule_epoch_2', 'gztar', './host_b_output/capsule_epoch_2')\n",
                "    files.download('./host_b_output/host_b_report.json')\n",
                "    files.download('capsule_epoch_2.tar.gz')"
            ],
        },
    ]

    notebook = {
        "nbformat": 4,
        "nbformat_minor": 0,
        "metadata": {
            "colab": {
                "name": "HDAR Host B.ipynb",
                "provenance": [],
            },
            "kernelspec": {
                "name": "python3",
                "display_name": "Python 3",
            },
            "language_info": {
                "name": "python",
            },
        },
        "cells": cells,
    }

    out_path = Path(args.out)
    out_path.write_text(json.dumps(notebook, indent=2))
    print(f"Colab notebook written: {out_path} ({out_path.stat().st_size} bytes)")
    print(f"Upload to: https://colab.research.google.com")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
