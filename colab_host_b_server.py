#!/usr/bin/env python3
"""Generates a Google Colab notebook that runs a Gradio server.

This turns Colab into a programmatically accessible endpoint — no Google
API key needed. The notebook:

1. Installs gradio + cryptography
2. Starts a Gradio server with a public URL
3. Exposes an API endpoint that accepts a runner script (base64)
4. Executes it on Colab's Linux runtime
5. Returns the host_b_report.json + capsule_epoch_2 as base64

The public Gradio URL acts as the "synthetic API key" — anyone with the
URL can call the API. The browser must stay open on any machine to keep
Colab alive, but your machine doesn't need to be involved.

Usage:
    python3 colab_host_b_server.py --out hdar_colab_server.ipynb

Then:
    1. Upload hdar_colab_server.ipynb to colab.research.google.com
    2. Run all cells
    3. Copy the public URL printed by Gradio
    4. Set it as COLAB_GRADIO_URL in GitHub Actions secrets
    5. CI can now call Colab as a Host B provider
"""
import argparse
import json
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate Colab Gradio server notebook")
    ap.add_argument("--out", default="hdar_colab_server.ipynb", help="Output notebook path")
    args = ap.parse_args()

    cells = [
        # ─── Markdown: Title ───
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "# HDAR Host B — Colab Gradio Server\n",
                "\n",
                "This notebook turns Google Colab into a programmatically accessible Host B endpoint.\n",
                "\n",
                "**Architecture:**\n",
                "- Colab runs a Gradio server with a public URL\n",
                "- The URL acts as a synthetic API key — no Google credentials needed to call it\n",
                "- CI/CD sends the runner script via the Gradio API\n",
                "- Colab executes it on Google's Linux infrastructure\n",
                "- Results (host_b_report.json + capsule_epoch_2) are returned as base64\n",
                "\n",
                "**Requirements:**\n",
                "- Browser tab must stay open (on any machine) to keep Colab alive\n",
                "- Colab free tier: ~12h runtime. Pro: ~24h.\n",
                "- The Gradio public URL changes each time the notebook restarts.\n",
                "  Update COLAB_GRADIO_URL in GitHub Actions secrets when it changes.\n",
                "\n",
                "**Platform evidence:** Colab runs Ubuntu Linux on Google Cloud.\n",
                "This is real platform separation from Host A (macOS)."
            ],
        },
        # ─── Install dependencies ───
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "!pip install gradio cryptography -q\n",
                "import platform\n",
                "print(f'Platform: {platform.platform()}')\n",
                "print(f'Python: {platform.python_version()}')\n",
                "print(f'Hostname: {platform.node()}')"
            ],
        },
        # ─── Markdown: Server code ───
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## Start Gradio Server\n",
                "\n",
                "This exposes a public API endpoint. The URL printed below is your\n",
                "`COLAB_GRADIO_URL` — set it in GitHub Actions secrets.\n",
                "\n",
                "API endpoint: `POST /api/predict` (or `/call/run_host_b`)\n",
                "\n",
                "Input: `runner_script_b64` — base64-encoded run_host_b.py\n",
                "Output: `report_b64`, `capsule_b64`, `platform`, `hostname`, `stdout`, `stderr`"
            ],
        },
        # ─── Gradio server ───
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "import gradio as gr\n",
                "import base64\n",
                "import json\n",
                "import os\n",
                "import subprocess\n",
                "import shutil\n",
                "import tempfile\n",
                "import platform\n",
                "import tarfile\n",
                "import io\n",
                "\n",
                "def run_host_b(runner_script_b64: str) -> dict:\n",
                "    \"\"\"Execute HDAR Host B on Colab and return evidence as base64.\n",
                "\n",
                "    Args:\n",
                "        runner_script_b64: base64-encoded run_host_b.py (with embedded capsule)\n",
                "\n",
                "    Returns:\n",
                "        JSON with report_b64, capsule_b64, platform, hostname, stdout, stderr\n",
                "    \"\"\"\n",
                "    try:\n",
                "        # Decode runner\n",
                "        runner_code = base64.b64decode(runner_script_b64).decode('utf-8')\n",
                "\n",
                "        # Write runner to temp dir\n",
                "        work_dir = tempfile.mkdtemp(prefix='hdar_colab_')\n",
                "        runner_path = os.path.join(work_dir, 'run_host_b.py')\n",
                "        with open(runner_path, 'w') as f:\n",
                "            f.write(runner_code)\n",
                "\n",
                "        # Run Host B\n",
                "        host_label = f'colab-{platform.node()}'\n",
                "        out_dir = os.path.join(work_dir, 'host_b_output')\n",
                "        result = subprocess.run(\n",
                "            ['python3', runner_path, '--out', out_dir,\n",
                "             '--host-label', host_label, '--operator', 'colab-gradio'],\n",
                "            capture_output=True, text=True, timeout=120\n",
                "        )\n",
                "\n",
                "        if result.returncode != 0:\n",
                "            return {\n",
                "                'error': f'Host B exited with code {result.returncode}',\n",
                "                'stderr': result.stderr[-2000:],\n",
                "                'stdout': result.stdout[-2000:],\n",
                "            }\n",
                "\n",
                "        # Read report\n",
                "        report_path = os.path.join(out_dir, 'host_b_report.json')\n",
                "        with open(report_path, 'r') as f:\n",
                "            report_json = f.read()\n",
                "        report_b64 = base64.b64encode(report_json.encode()).decode()\n",
                "\n",
                "        # Pack capsule_epoch_2 into tar.gz\n",
                "        capsule_dir = os.path.join(out_dir, 'capsule_epoch_2')\n",
                "        tar_buffer = io.BytesIO()\n",
                "        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:\n",
                "            tar.add(capsule_dir, arcname='capsule_epoch_2')\n",
                "        capsule_b64 = base64.b64encode(tar_buffer.getvalue()).decode()\n",
                "\n",
                "        # Clean up\n",
                "        shutil.rmtree(work_dir, ignore_errors=True)\n",
                "\n",
                "        return {\n",
                "            'report_b64': report_b64,\n",
                "            'capsule_b64': capsule_b64,\n",
                "            'platform': platform.platform(),\n",
                "            'hostname': platform.node(),\n",
                "            'python_version': platform.python_version(),\n",
                "            'stdout': result.stdout[-2000:],\n",
                "            'stderr': result.stderr[-2000:],\n",
                "            'success': True,\n",
                "        }\n",
                "    except Exception as e:\n",
                "        return {\n",
                "            'error': str(e),\n",
                "            'success': False,\n",
                "        }\n",
                "\n",
                "# Create Gradio interface\n",
                "with gr.Blocks(title='HDAR Host B Server') as demo:\n",
                "    gr.Markdown('# HDAR Host B — Colab Server')\n",
                "    gr.Markdown('Send a base64-encoded runner script to execute Host B on Colab.')\n",
                "\n",
                "    with gr.Row():\n",
                "        runner_input = gr.Textbox(\n",
                "            label='Runner Script (base64)',\n",
                "            placeholder='Paste base64-encoded run_host_b.py here...',\n",
                "            lines=5,\n",
                "        )\n",
                "\n",
                "    run_btn = gr.Button('Run Host B', variant='primary')\n",
                "\n",
                "    output_json = gr.JSON(label='Result')\n",
                "\n",
                "    run_btn.click(\n",
                "        fn=run_host_b,\n",
                "        inputs=runner_input,\n",
                "        outputs=output_json,\n",
                "        api_name='run_host_b',\n",
                "    )\n",
                "\n",
                "# Launch with public link — this URL is your COLAB_GRADIO_URL\n",
                "demo.launch(share=True, debug=True)"
            ],
        },
        # ─── Markdown: How to use ───
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## Using the API from CI/CD\n",
                "\n",
                "After running the cell above, Gradio prints a public URL like:\n",
                "```\n",
                "Running on public URL: https://abc123.gradio.live\n",
                "```\n",
                "\n",
                "Set that URL as `COLAB_GRADIO_URL` in GitHub Actions secrets.\n",
                "\n",
                "Then CI calls it with `colab_client.py`:\n",
                "```bash\n",
                "python3 colab_client.py \\\n",
                "  --url https://abc123.gradio.live \\\n",
                "  --runner /path/to/run_host_b.py \\\n",
                "  --out evidence/colab\n",
                "```\n",
                "\n",
                "The URL changes each time the notebook restarts. Update the secret.\n",
                "\n",
                "**Keep this tab open** — closing it kills the Colab runtime and the server."
            ],
        },
        # ─── Keep-alive cell ───
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# Optional: keep-alive to prevent Colab timeout\n",
                "# Run this in a separate cell to periodically ping the runtime\n",
                "import time\n",
                "from IPython.display import clear_output\n",
                "\n",
                "while True:\n",
                "    print(f'Server alive: {time.strftime(\"%H:%M:%S UTC\", time.gmtime())}')\n",
                "    time.sleep(300)  # ping every 5 minutes\n",
                "    clear_output(wait=True)"
            ],
        },
    ]

    notebook = {
        "nbformat": 4,
        "nbformat_minor": 0,
        "metadata": {
            "colab": {
                "name": "HDAR Host B Server.ipynb",
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
    print(f"Colab server notebook written: {out_path} ({out_path.stat().st_size} bytes)")
    print(f"Upload to: https://colab.research.google.com")
    print(f"Run all cells, then copy the Gradio public URL.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
