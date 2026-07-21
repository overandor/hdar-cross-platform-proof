# HDAR Cross-Platform Proof

Host-Detached Archival Runtime — cryptographic proof that an agent workspace can be sealed on one platform, transported, restored on a different platform, and continued with verifiable lineage.

## Status

**80/80 verifier checks passed. 4/4 platform separations confirmed.**

Host A sealed Epoch 1 on macOS (this Mac). Host B ran on 4 separate remote platforms:
- GitHub Codespaces (Linux 6.8.0, Azure x86_64)
- GitHub Actions Ubuntu 22.04 (Linux x86_64)
- GitHub Actions Ubuntu 24.04 (Linux x86_64)
- GitHub Actions macOS 14 (arm64, different machine)

All 4 produced the same pipeline output hash: `8708384aa5f7118c1f1b356e9abfda416c1b3c1c33943498c6016fb29b9d396a`

## One-Command Verification

```bash
git clone https://github.com/overandor/hdar-cross-platform-proof
cd hdar-cross-platform-proof
pip install cryptography
python3 prove.py
```

This runs 20 checks per platform (80 total) against the published evidence. All artifacts are in the repo — no network access to remote platforms needed.

## What the Verifier Checks (20 per platform)

| # | Check | What it proves |
|---|---|---|
| 1 | E1 manifest hash valid | Capsule not tampered in transit |
| 2 | E1 Ed25519 owner signature valid | Host A identity authenticated |
| 3 | E1 receipt hash valid | Sealing event not forged |
| 4 | E2 manifest hash valid | Host B capsule not tampered |
| 5 | E2 receipt hash valid | Host B sealing event not forged |
| 6 | Cryptographic lineage E1→E2 | E2 descends from E1 (linked list of hashes) |
| 7 | Epoch advancement 1→2 | Continuation happened |
| 8 | Platform separation | Host A and Host B are different machines |
| 9 | Owner public key consistent | Same owner across epochs |
| 10 | Host B confirms platform separation | Host B self-reports different platform |
| 11-12 | Receipt workspace hashes match manifests | Receipts not forged |
| 13 | E2 workspace differs from E1 | Work continued (state changed) |
| 14 | E2 workspace grew | Pipeline produced output |
| 15 | Shared workspace files preserved | Original files not corrupted |
| 16-18 | Host B nonce/timestamps/hostname | Fresh evidence from real runtime |
| 19 | Pipeline output hash in report | Deterministic computation verified |
| 20 | E2 content blocks all valid | No bit rot in E2 capsule |

## Honest Claim Boundary

This repo proves:
- A workspace can be sealed, transported, restored, and continued on a different platform
- The Ed25519 signature survives cross-platform transfer
- A deterministic pipeline produces byte-identical output across OS/arch combinations
- Cryptographic lineage links epochs without the private key leaving Host A

This repo does NOT prove:
- That the pipeline is useful (it's a 5-stage JSONL analysis — toy task)
- That an AI agent's cognitive state is preserved (only files are preserved)
- That the verifier is independent (it shares Python with the sealer, though it re-implements all checks from the capsule format spec)
- That the system is secure against a determined attacker (the private key is in `.gitignore` but was on the same machine as the verifier)

## How to Generate Fresh Evidence

### Run your own Host A
```bash
python3 host_a_seal.py --out /tmp/my_host_a
```

### Run Host B on a remote platform
Copy `/tmp/my_host_a/run_host_b.py` to any Linux machine (Colab, Codespaces, VPS, E2B):
```bash
pip install cryptography
python3 run_host_b.py --out ./host_b_output --host-label my-platform
```

### Verify
```bash
python3 verify_all.py \
  --host-a-dir /tmp/my_host_a \
  --host-b-report ./host_b_output/host_b_report.json \
  --e2-capsule ./host_b_output/capsule_epoch_2
```

### GitHub Actions (automated)
```bash
gh workflow run host_b_proof.yml --repo overandor/hdar-cross-platform-proof
```

## Files

- `prove.py` — One-command verification against published evidence
- `host_a_seal.py` — Seals Epoch 1 capsule with Ed25519 owner signature (runs on Host A)
- `run_host_b.py` — Host B runner template (gets capsule embedded by host_a_seal.py)
- `run_host_b_embedded.py` — Host B runner with capsule already embedded (gitignored, used by CI)
- `verify_all.py` — Independent verifier (runs on Host A or any third machine)
- `e2b_runner.py` — E2B sandbox runner for remote Linux execution
- `generate_colab_notebook.py` — Generates Google Colab notebook
- `codespaces_setup.sh` — GitHub Codespaces setup script
- `capsule_epoch_1/` — E1 capsule (manifest, receipt, content-addressed blocks)
- `evidence/` — Host B reports and E2 capsules from all 4 platforms

## Dependencies

- Python 3.8+
- `cryptography` package (`pip install cryptography`)
- For E2B: `e2b` package and `E2B_API_KEY`
