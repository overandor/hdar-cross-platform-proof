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
                "## Download artifacts\n",
                "\n",
                "Download the Host B report and E2 capsule to verify on Host A."
            ],
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "from google.colab import files\n",
                "import shutil\n",
                "\n",
                "# Zip the E2 capsule for easy download\n",
                "shutil.make_archive('capsule_epoch_2', 'gztar', './host_b_output/capsule_epoch_2')\n",
                "\n",
                "files.download('./host_b_output/host_b_report.json')\n",
                "files.download('capsule_epoch_2.tar.gz')\n",
                "print('Downloads triggered. Check your browser downloads folder.')"
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
