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
                "## Serve evidence via ngrok tunnel\n",
                "\n",
                "Starts a local HTTP server on the Colab VM and exposes it via ngrok.\n",
                "The tunnel URL is printed below — CI uses it to download evidence directly.\n",
                "This replaces files.download() which doesn't work in automated browser sessions."
            ],
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "!pip install pyngrok -q\n",
                "import shutil, os, http.server, threading, json\n",
                "from pyngrok import ngrok\n",
                "\n",
                "# Pack E2 capsule as tarball\n",
                "shutil.make_archive('/tmp/capsule_epoch_2', 'gztar', './host_b_output/capsule_epoch_2')\n",
                "\n",
                "# Copy evidence files to a serve directory\n",
                "serve_dir = '/tmp/hdar_evidence'\n",
                "os.makedirs(serve_dir, exist_ok=True)\n",
                "shutil.copy('./host_b_output/host_b_report.json', f'{serve_dir}/host_b_report.json')\n",
                "shutil.copy('/tmp/capsule_epoch_2.tar.gz', f'{serve_dir}/capsule_epoch_2.tar.gz')\n",
                "\n",
                "# Write a manifest so CI knows what's available\n",
                "manifest = {\n",
                "    'files': ['host_b_report.json', 'capsule_epoch_2.tar.gz'],\n",
                "    'platform': __import__('platform').platform(),\n",
                "    'hostname': __import__('socket').gethostname(),\n",
                "}\n",
                "with open(f'{serve_dir}/manifest.json', 'w') as f:\n",
                "    json.dump(manifest, f, indent=2)\n",
                "\n",
                "# Start a simple HTTP server in a background thread\n",
                "os.chdir(serve_dir)\n",
                "server = http.server.HTTPServer(('0.0.0.0', 8080), http.server.SimpleHTTPRequestHandler)\n",
                "thread = threading.Thread(target=server.serve_forever, daemon=True)\n",
                "thread.start()\n",
                "print('HTTP server started on port 8080')\n",
                "\n",
                "# Open ngrok tunnel\n",
                "tunnel = ngrok.connect(8080)\n",
                "tunnel_url = tunnel.public_url\n",
                "print(f'HDAR_TUNNEL_URL={tunnel_url}')\n",
                "print(f'Evidence available at: {tunnel_url}/manifest.json')\n",
                "print(f'Report: {tunnel_url}/host_b_report.json')\n",
                "print(f'Capsule: {tunnel_url}/capsule_epoch_2.tar.gz')"
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
