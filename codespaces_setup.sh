#!/usr/bin/env bash
# HDAR Host B — GitHub Codespaces setup and runner
#
# Usage in Codespaces terminal:
#   curl -sL <url-to-run_host_b.py> -o run_host_b.py
#   bash codespaces_setup.sh
#
# Or if you have the file locally, just:
#   python3 run_host_b.py --out ./host_b_output --host-label codespaces-$(hostname)

set -euo pipefail

echo "============================================================"
echo "HDAR Host B — GitHub Codespaces Runner"
echo "============================================================"
echo "Platform: $(python3 -c 'import platform; print(platform.platform())')"
echo "Python:   $(python3 --version)"
echo "Hostname: $(hostname)"
echo "============================================================"

# Install cryptography
echo ""
echo "[1/3] Installing cryptography..."
pip install cryptography -q

# Run Host B
echo ""
echo "[2/3] Running Host B..."
if [ ! -f "run_host_b.py" ]; then
    echo "ERROR: run_host_b.py not found. Place it in the current directory."
    exit 1
fi

python3 run_host_b.py \
    --out ./host_b_output \
    --host-label "codespaces-$(hostname)" \
    --operator "$(whoami)@codespaces"

echo ""
echo "[3/3] Done. Artifacts in ./host_b_output/"
echo ""
echo "To verify on Host A, copy these back:"
echo "  scp ./host_b_output/host_b_report.json <host-a>:/tmp/hdar_host_a/colab/"
echo "  scp -r ./host_b_output/capsule_epoch_2 <host-a>:/tmp/hdar_host_a/colab/"
echo ""
echo "Or download from Codespaces: File > Download..."
