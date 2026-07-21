# HDAR Cross-Platform Proof

Host-Detached Archival Runtime — cryptographic proof that an agent workspace can be sealed on one platform, transported, restored on a different platform, and continued with verifiable lineage.

## Status

**80/80 verifier checks passed. 4/4 platform separations confirmed.**

Host A sealed Epoch 1 on macOS (this Mac). Host B ran on 4 recorded Host B runtime configurations, including one Codespaces environment and three separately provisioned GitHub Actions jobs:
- GitHub Codespaces (Linux 6.8.0, Azure x86_64)
- GitHub Actions Ubuntu 22.04 (Linux x86_64)
- GitHub Actions Ubuntu 24.04 (Linux x86_64)
- GitHub Actions macOS 14 (arm64, separately provisioned runner)

Each published Host B execution occurred outside Host A; the three GitHub Actions jobs ran on separately provisioned hosted VMs, and the Codespaces execution ran in a development container hosted on a VM.

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
| 16-18 | Host B nonce/timestamps/hostname | Consistent with runtime generation; support replay detection when bound to independently authenticated execution provenance |
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
- That Host B origin is cryptographically authenticated (platform strings, nonces, and timestamps are Host-B-reported fields inside the report, not external proof of the report's origin; see `TRUST_BOUNDARY.md`)
- That the Host B executions occurred on four independent cloud providers (the published evidence establishes Codespaces plus GitHub-hosted Actions infrastructure, not four independent providers)

## How to Generate Fresh Evidence

### Single-provider run (seals a fresh E1)
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

## Canonical Release Bundle (multi-provider proof)

The audit's central remaining milestone: freeze one canonical E1 and dispatch the **identical** bundle to multiple providers. Different E1 hashes mean different experiments. The release bundle freezes:

- `protocol_version`, `source_commit`, `owner_public_key`
- `runner_sha256`, `verifier_sha256`, `builder_sha256`, `orchestrator_sha256`
- `e1_manifest_hash`, `e1_workspace_root_hash`, `transport_capsule_sha256`
- `dependency_lock_sha256`, `cryptography_version`, wheel SHA-256s
- `worker_version`, `ruleset_version`

### Build a canonical release once
```bash
python3 release.py build --out /tmp/hdar_release
```

### Inspect the frozen identity
```bash
python3 release.py inspect /tmp/hdar_release/release_bundle.tar.gz
```

### Verify the bundle is internally consistent (11 checks)
```bash
python3 release.py verify /tmp/hdar_release/release_bundle.tar.gz
```

### Dispatch the identical bundle to multiple providers
```bash
python3 run_proof.py --reuse-release /tmp/hdar_release/release_bundle.tar.gz --provider e2b
python3 run_proof.py --reuse-release /tmp/hdar_release/release_bundle.tar.gz --provider codespaces
python3 run_proof.py --reuse-release /tmp/hdar_release/release_bundle.tar.gz --provider colab
python3 run_proof.py --reuse-release /tmp/hdar_release/release_bundle.tar.gz --provider chatgpt-linux
```

Every run begins from the same E1 manifest, owner key, runner hash, and verifier hash. Different Host B keys, E2 hashes, timestamps, and provider identities are expected. **Different E1 hashes mean it is a different experiment.**

### GitHub Actions (automated, single E1 per run)
```bash
gh workflow run host_b_proof.yml --repo overandor/hdar-cross-platform-proof
```

### GitHub Actions (reproduction matrix — same E1 across 4 providers)
```bash
gh workflow run reproduction_matrix.yml --repo overandor/hdar-cross-platform-proof
```

This workflow builds one canonical release bundle, dispatches the **identical** E1 to Ubuntu 22.04, Ubuntu 24.04, macOS 13, and macOS 14, then runs `reproduction_matrix.py` to confirm all providers ran the same E1 with the same pipeline output hash. This is the audit's central milestone: "make five unrelated computers prove the exact same E1."

## Files

- `prove.py` — One-command verification against published evidence
- `host_a_seal.py` — Seals Epoch 1 capsule with Ed25519 owner signature (runs on Host A)
- `run_host_b.py` — Host B runner template (gets capsule embedded by host_a_seal.py)
- `run_host_b_embedded.py` — Host B runner with capsule already embedded (gitignored, used by CI)
- `verify_all.py` — Independent verifier (runs on Host A or any third machine)
- `release.py` — Canonical release bundle builder (freezes one E1 for multi-provider dispatch)
- `run_proof.py` — End-to-end orchestrator (supports `--reuse-release` for multi-provider proof)
- `e2b_runner.py` — E2B sandbox runner for remote Linux execution
- `generate_colab_notebook.py` — Generates Google Colab notebook
- `codespaces_setup.sh` — GitHub Codespaces setup script
- `capsule_epoch_1/` — E1 capsule (manifest, receipt, content-addressed blocks)
- `evidence/` — Host B reports and E2 capsules from all 4 platforms
- `TRUST_BOUNDARY.md` — Documents the open Host B identity gap and the attestation roadmap

## Dependencies

- Python 3.8+
- `cryptography` package (`pip install cryptography`)
- For E2B: `e2b` package and `E2B_API_KEY`
