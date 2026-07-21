# HDAR3 Notebook Audit

## Artifact identity

- File: `hdar3.ipynb`
- Size: 247,566 bytes
- SHA-256: `9e86308769b3c9cea59539754e7bf3fdad6aa516084f7f8ee445ebb34cebf78c`
- Cells: 95 total — 55 code, 40 markdown
- Code cells with stored outputs: 51
- Code cells with explicit execution counters: 27
- Stored error outputs: 3
- Cells with outputs but no execution counter: 24

## Executive conclusion

The notebook is useful as a development-history and experimentation record, but it is not a clean proof packet and should not be presented to an investor, auditor, or security reviewer as canonical evidence. It combines five different evidence classes without reliably distinguishing them:

1. simulated JSON transitions;
2. placeholder verifiers;
3. real-looking E2B sandbox executions;
4. a cloned `hdar-host-b-proof` repository with executed tests;
5. later synthetic signing demonstrations using publicly embedded deterministic keys.

The current GitHub `hdar-canonical` repository is the superior diligence surface. This notebook explains how the work evolved, but it reintroduces key leakage, circular validation, stale-output provenance, and false multi-provider claims that the canonical repository partly corrected.

## What is genuinely valuable

### 1. Real repository execution is recorded

The notebook clones `overandor/hdar-host-b-proof`, runs `seed_milestone_demo.py`, and stores output showing 27 checks passed. That is meaningful evidence of an executable MirrorLease + EvidencePipe + host-continuity demonstration.

It then runs the repository test suite and stores a `16 passed` result. The same 16 tests are copied into an isolated Colab directory and pass again after packaging and re-extraction.

These outputs support the narrower claim that the referenced code and tests executed successfully in one Colab environment.

### 2. E2B remote execution likely occurred

Several cells retrieve `E2B_API_KEY` through Colab secrets, create E2B sandboxes, upload JSON artifacts, execute Python workers, retrieve results, and kill the sandboxes. The outputs are consistent with real API calls rather than pure prose.

This supports a limited claim: JSON input was transferred to an E2B sandbox, transformed, returned, and hash-linked to its predecessor.

### 3. The notebook exposes the actual development path

It records progression from placeholder shell scripts to repository execution, test isolation, capsule packaging, E2B execution, and signing experiments. For internal R&D provenance, this has value.

## Critical evidence defects

### 1. The notebook contains a complete private SSH key

Cell 15 embeds a full OpenSSH private key and writes it to `/root/.ssh/id_ed25519_colab`. Cell 83 duplicates the same key as raw base64. The key must be treated as compromised. The audit intentionally does not reproduce it.

The same notebook also invokes SSH with `StrictHostKeyChecking=no`, weakening server-identity verification.

Required response:

- revoke/delete the corresponding public key wherever authorized;
- generate a new keypair;
- remove the private material from every notebook, archive, Git commit, shared link, and cached copy;
- do not use the exposed key for any future proof.

### 2. Stored outputs are not reliably bound to current cell source

Twenty-four code cells contain outputs but no execution counter. More seriously, cells 45 and 49 currently contain only an HTML "old simulated code removed" comment while retaining outputs from code that is no longer present.

This proves that the notebook was edited after execution without clearing outputs. Therefore, stored outputs cannot automatically be treated as reproductions of the source currently visible above them.

Execution order is also nonlinear. For example, cell 92 executed before cells 54–55 even though it appears later and displays the earlier placeholder verifier behavior.

### 3. The initial "11/11 verifier" is explicitly simulated

Cell 20 creates `hdar_artifacts.json` from hard-coded event strings and loops eleven times printing successful checks. Its own comment says the cryptographic verification logic "would go here."

The resulting "independent recomputability proven" message is not evidence.

### 4. The base chain is manually fabricated

`hdar_artifacts.json` is not derived from a signed capsule. It is manually written in cell 20 and recreated again in cell 84 with:

- two event labels;
- a plain continuation key;
- three strings naming supposed checks.

Subsequent E2B lineage proofs establish only that later JSON contains the SHA-256 of this manually created JSON. They do not establish continuity from the canonical HDAR Epoch 1 capsule.

### 5. Hash serialization changes mid-notebook

Early E2B code hashes `json.dumps(data)` without canonical key ordering. Later code switches to `sort_keys=True`. Stored outputs therefore show different parent hashes for ostensibly the same artifact.

The notebook eventually creates a consistent sorted-key chain, but the earlier and later evidence are different runs and must not be merged.

### 6. The 16/16 test result follows a source patch to the expected hash

Before running the final test suite, cell 61 uses `sed` to replace `TASK_EXPECTED_OUTPUT_HASH` with a value taken from prior test results. The resulting 16/16 pass demonstrates consistency with the patched expectation, not independent confirmation that the expected value was specified before execution.

That may be a legitimate bug fix, but the evidence packet must preserve:

- the failing test;
- the independently derived expected value;
- the source diff;
- the passing test;
- a reviewer explanation of why the new value is correct.

Without that chain, the test can look circular.

### 7. The "outsider audit" is not independent

The notebook copies implementation and tests into another directory in the same Colab runtime, zips them, extracts them, and reruns pytest with the same interpreter and dependencies.

This proves packaging portability inside one environment. It does not prove:

- independent operator review;
- another machine;
- another provider;
- hostile verification;
- independence of test and implementation authorship.

The generated ZIP also contains `.pytest_cache`, `__pycache__`, `.pyc` files, duplicate runner locations, and generated directories, so it is not a clean canonical capsule.

### 8. The "multi-platform verifier" does not run on multiple platforms

Cells 51–55 and 92 pass strings such as `Windows-AMD64-remote`, `RaspberryPi-ARMv7-edge`, and `Android-aarch64-mobile` into one Bash script running in Colab Linux.

The script:

- hashes one local file;
- warns that the public key is missing;
- treats every non-macOS label as "cross-platform compatibility verified";
- always prints success.

No Windows, Raspberry Pi, Android, or macOS execution occurs. Those outputs are labels, not platform evidence.

### 9. The claimed three-provider chain is actually same-provider E2B chaining

The automated chain creates two E2B sandboxes using the same template and API account. The second is labeled `Next_Sandbox_Stage`, but it remains E2B.

That is two ephemeral environments, not three independent providers. The notebook never obtains the expected `node_b_epoch2_evidence.json` from GitHub Codespaces; cell 78 explicitly reports it missing.

Cell 80 then substitutes `e2b_successor_evidence.json` and hard-codes provider lineage as macOS → Codespaces → E2B. Its auditor marks status `VERIFIED` merely when the input contains a `parent_hash` field and sets `integrity_check` to `PASS` unconditionally.

This does not verify a Codespaces transition or a three-provider lineage.

### 10. Signing verifies possession of a public notebook secret, not identity

Cells 85 and 87 derive an Ed25519 private key from a fixed placeholder string embedded in the notebook. I independently reproduced the stored public key and exact signature from that public string.

Anyone with the notebook can produce the same signature. The signature proves deterministic possession of published material; it does not authenticate a unique agent, owner, E2B worker, or provider.

Cell 83 additionally embeds the complete SSH private key and derives another Ed25519 key from it. That is even more severe because the supposedly secure signer secret is distributed with the proof.

The artifact also carries its own public key without an external trust anchor. A self-contained `(payload, signature, public key)` tuple proves internal signature validity, not that the signer was authorized.

### 11. Signed and unsigned chains are disconnected

The signed artifact is `epoch3_signed_evidence.json`. The later "final multi-epoch verification" in cell 88 verifies `e2b_successor_evidence.json` against the different unsigned file `epoch3_final_evidence.json`.

Thus the final parent-hash chain does not incorporate the signed artifact, and the signing demonstration does not authenticate the final chain report.

### 12. Claimed manifest linkage is absent

`verify_epoch3_integrity(evidence_path, manifest_path)` accepts the canonical manifest path but never reads or uses it. It verifies only the artifact's self-supplied public key and signature.

Therefore, the signed E2B artifact is not cryptographically bound to `/content/hdar_canonical_v2/protocol_manifest.json` or to the current GitHub canonical protocol.

### 13. Protocol identity is fragmented

The notebook uses multiple incompatible labels:

- `1.0.0`;
- `1.1.0-alpha`;
- `2024.06.01` rules;
- "canonical v2";
- the older `hdar-host-b-proof` implementation;
- the separately maintained `hdar-canonical` v1.0 repository.

These should not be presented as one protocol version without an explicit migration map and schema compatibility rules.

## Claim-by-claim verdict

| Claim | Verdict | Supported boundary |
|---|---|---|
| Repository code executed in Colab | Supported | Stored output shows clone, demo execution, and pytest runs |
| 16 tests passed | Supported with caveat | Passed after expected-hash source patch |
| Package reruns after extraction | Supported | Same Colab runtime and dependency environment |
| E2B sandbox transformed JSON | Plausibly supported | Stored API-style outputs; not independently attested |
| Hash-linked JSON chain exists | Supported | For the manually fabricated JSON artifacts in the later sorted-key run |
| Canonical HDAR capsule continued | Not supported by this notebook chain | Base artifact is synthetic `hdar_artifacts.json` |
| Three independent providers | Not supported | Codespaces evidence is missing; two stages are E2B |
| Windows / Android / Raspberry Pi compatibility | Not supported | Only labels passed to one local Bash script |
| Cryptographic agent identity | Not supported | Signing secret is public and deterministic |
| Independent auditor verified chain | Not supported | Same operator/runtime; Node C auditor checks field presence only |
| Hardware independence | Not established | Colab packaging and E2B JSON execution are narrower evidence |
| Investor-ready proof packet | No | Secret leakage, stale outputs, mixed simulations, disconnected chains |

## Relationship to `hdar-canonical`

The current canonical repository should remain the primary engineering surface because it has one protocol library, one verifier, scoped tests, clearer claim boundaries, and no notebook execution ambiguity.

The notebook should be retained only as:

- an internal R&D chronology;
- a source of experiments worth porting into real tests;
- evidence that remote E2B work was attempted;
- a record of rejected placeholder approaches.

It should not be linked from the investor README until sanitized and explicitly labeled historical/noncanonical.

## Required remediation sequence

1. Revoke the exposed SSH key immediately and rotate every reused credential.
2. Remove private key material from the notebook and all repository/archive history.
3. Clear every output and rerun from a fresh runtime in strict top-to-bottom order.
4. Replace synthetic `hdar_artifacts.json` with a canonical signed E1 capsule.
5. Never transmit the owner private key to Host B.
6. Use owner-signed delegation plus a distinct Host B signing key.
7. Bind the signed transition to the canonical manifest, task contract, environment digest, and exact parent capsule hash.
8. Verify actual content blocks and restored workspace bytes, not only event JSON.
9. Run the canonical v1.0 implementation on a real second provider and obtain an independently signed Host B attestation.
10. Run Verifier C under a third operator or CI identity with no signing keys.
11. Publish CI logs, artifact digests, and a transparency-log entry.
12. Delete the fake platform loop and replace it with an explicit platform matrix executed by CI or real hardware.

## Valuation effect

This notebook adds R&D provenance and demonstrates substantial persistence, but it does not increase the protocol's defensible valuation on its own. Its security and evidence defects reduce diligence confidence until sanitized.

The valuation remains driven by the canonical repository and a future clean proof:

- current technical asset: approximately `$100,000–$250,000`;
- investable after corrected trust separation, canonical cross-provider reproduction, and CI: approximately `$200,000` on a `$5 million` post-money SAFE cap;
- higher pricing requires a paying design partner and repeated independent transitions.
