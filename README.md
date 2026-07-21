# HDAR Cross-Platform Proof

Host-Detached Archival Runtime — cryptographic proof that an agent workspace can be sealed on one platform, transported, restored on a different platform, and continued with verifiable lineage.

## Status

- **18/20 verifier checks pass** (local same-machine test)
- **2 failures**: Platform separation checks (expected — both hosts are macOS)
- **Cryptographic chain**: Ed25519 owner signatures, SHA-256 content addressing, receipt hashes — all verified
- **Pipeline determinism**: 5-stage analysis pipeline produces identical output hash across runs
- **Lineage**: E2.parent_manifest_hash == E1.manifest_hash — verified

## What Works

| Check | Status |
|---|---|
| E1 manifest hash valid | PASS |
| E1 Ed25519 owner signature valid | PASS |
| E1 receipt hash valid | PASS |
| E2 manifest hash valid | PASS |
| E2 receipt hash valid | PASS |
| Cryptographic lineage E1→E2 | PASS |
| Epoch advancement 1→2 | PASS |
| Owner public key consistent | PASS |
| E1/E2 receipt workspace hashes | PASS |
| E2 workspace differs from E1 | PASS |
| E2 workspace grew | PASS |
| Shared workspace files preserved | PASS |
| Host B nonce/timestamps/hostname | PASS |
| Pipeline output hash in report | PASS |
| E2 content blocks all valid | PASS |
| Platform separation (Host A ≠ Host B) | **FAIL** (same machine) |
| Host B report confirms separation | **FAIL** (same machine) |

## How to Complete the Proof

### Option 1: Google Colab (easiest)
1. Run `python3 host_a_seal.py --out /tmp/hdar_host_a`
2. Generate notebook: `python3 generate_colab_notebook.py --runner /tmp/hdar_host_a/run_host_b.py --out hdar_host_b_colab.ipynb`
3. Upload `hdar_host_b_colab.ipynb` to https://colab.research.google.com
4. Run all cells — Colab runs Linux, providing real platform separation
5. Download `host_b_report.json` and `capsule_epoch_2.tar.gz`
6. Verify: `python3 verify_all.py --host-a-dir /tmp/hdar_host_a --host-b-report <downloaded_report> --e2-capsule <extracted_capsule>`

### Option 2: GitHub Codespaces
1. Run `python3 host_a_seal.py --out /tmp/hdar_host_a`
2. Copy `run_host_b.py` and `codespaces_setup.sh` to a Codespaces instance
3. Run `bash codespaces_setup.sh`
4. Download artifacts and verify on Host A

### Option 3: E2B Sandbox
1. `pip install e2b` and set `E2B_API_KEY`
2. Run `python3 host_a_seal.py --out /tmp/hdar_host_a`
3. Run `python3 e2b_runner.py --runner /tmp/hdar_host_a/run_host_b.py --out ./e2b_output`
4. Verify: `python3 verify_all.py --host-a-dir /tmp/hdar_host_a --host-b-report ./e2b_output/host_b_report.json --e2-capsule ./e2b_output/capsule_epoch_2`

## Files

- `host_a_seal.py` — Seals Epoch 1 capsule with Ed25519 owner signature (runs on Host A)
- `run_host_b.py` — Self-contained Host B runner with embedded capsule (template — gets filled by host_a_seal.py)
- `verify_all.py` — Independent verifier (runs on Host A or any third machine)
- `e2b_runner.py` — E2B sandbox runner for remote Linux execution
- `generate_colab_notebook.py` — Generates Google Colab notebook
- `codespaces_setup.sh` — GitHub Codespaces setup script

## Dependencies

- Python 3.8+
- `cryptography` package (`pip install cryptography`)
- For E2B: `e2b` package and `E2B_API_KEY`
