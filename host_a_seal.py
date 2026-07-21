#!/usr/bin/env python3
"""HDAR Host A — Seals Epoch 1 capsule with Ed25519 owner signature.

This runs on the LOCAL machine (macOS). It:
1. Generates an Ed25519 owner keypair (private key stays here)
2. Creates a demo workspace with a 5-stage pipeline
3. Seals it as a content-addressed capsule
4. Signs the manifest with the owner private key
5. Creates a transport tar.gz
6. Writes host_a_report.json and owner_public_key.txt
7. Generates a self-contained run_host_b.py with the capsule embedded

Usage:
    python3 host_a_seal.py --out /tmp/hdar_host_a
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import shutil
import sys
import tarfile
import time
from pathlib import Path

CHUNK_SIZE = 1024 * 1024
SCHEMA = "hdar.transport-capsule/v0.1"
RECEIPT_SCHEMA = "hdar.receipt/v0.1"
AGENT_ID = "hdar-cross-platform-agent"
PROTOCOL_VERSION = "hdar-canonical/v1.0"

# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("WARNING: cryptography package not available. Install: pip install cryptography", file=sys.stderr)
    sys.exit(1)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def generate_keypair() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def sign_message(priv: bytes, msg: bytes) -> bytes:
    key = Ed25519PrivateKey.from_private_bytes(priv)
    return key.sign(msg)


# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------

INPUT_RECORDS = """\
{"id": "rec-0000", "category": "alpha", "value": 97.12, "timestamp": 1700000000}
{"id": "rec-0001", "category": "beta", "value": 193.08, "timestamp": 1700000060}
{"id": "rec-0002", "category": "gamma", "value": 48.89, "timestamp": 1700000120}
{"id": "rec-0003", "category": "delta", "value": 342.12, "timestamp": 1700000180}
{"id": "rec-0004", "category": "alpha", "value": 97.45, "timestamp": 1700000240}
{"id": "rec-0005", "category": "beta", "value": 140.11, "timestamp": 1700000300}
{"id": "rec-0006", "category": "gamma", "value": 53.32, "timestamp": 1700000360}
{"id": "rec-0007", "category": "delta", "value": 283.96, "timestamp": 1700000420}
{"id": "rec-0008", "category": "alpha", "value": 95.66, "timestamp": 1700000480}
{"id": "rec-0009", "category": "beta", "value": 204.64, "timestamp": 1700000540}
{"id": "rec-0010", "category": "gamma", "value": 52.32, "timestamp": 1700000600}
{"id": "rec-0011", "category": "delta", "value": 369.81, "timestamp": 1700000660}
{"id": "rec-0012", "category": "alpha", "value": 113.13, "timestamp": 1700000720}
{"id": "rec-0013", "category": "beta", "value": 204.42, "timestamp": 1700000780}
{"id": "rec-0014", "category": "gamma", "value": 42.62, "timestamp": 1700000840}
{"id": "rec-0015", "category": "delta", "value": 239.12, "timestamp": 1700000900}
{"id": "rec-0016", "category": "alpha", "value": 104.93, "timestamp": 1700000960}
{"id": "rec-0017", "category": "beta", "value": 252.44, "timestamp": 1700001020}
{"id": "rec-0018", "category": "gamma", "value": 50.42, "timestamp": 1700001080}
{"id": "rec-0019", "category": "delta", "value": 293.62, "timestamp": 1700001140}
{"id": "rec-0020", "category": "alpha", "value": 110.64, "timestamp": 1700001200}
{"id": "rec-0021", "category": "beta", "value": 141.86, "timestamp": 1700001260}
{"id": "rec-0022", "category": "gamma", "value": 46.88, "timestamp": 1700001320}
{"id": "rec-0023", "category": "delta", "value": 329.42, "timestamp": 1700001380}
{"id": "rec-0024", "category": "alpha", "value": 117.47, "timestamp": 1700001440}
{"id": "rec-0025", "category": "beta", "value": 190.37, "timestamp": 1700001500}
{"id": "rec-0026", "category": "gamma", "value": 53.77, "timestamp": 1700001560}
{"id": "rec-0027", "category": "delta", "value": 314.89, "timestamp": 1700001620}
{"id": "rec-0028", "category": "alpha", "value": 115.65, "timestamp": 1700001680}
{"id": "rec-0029", "category": "beta", "value": 155.47, "timestamp": 1700001740}
{"id": "rec-0030", "category": "gamma", "value": 55.68, "timestamp": 1700001800}
{"id": "rec-0031", "category": "delta", "value": 209.13, "timestamp": 1700001860}
{"id": "rec-0032", "category": "alpha", "value": 47.6, "timestamp": 1700001920}
{"id": "rec-0033", "category": "beta", "value": 175.72, "timestamp": 1700001980}
{"id": "rec-0034", "category": "gamma", "value": 40.84, "timestamp": 1700002040}
{"id": "rec-0035", "category": "delta", "value": 352.56, "timestamp": 1700002100}
{"id": "rec-0036", "category": "alpha", "value": 113.29, "timestamp": 1700002160}
{"id": "rec-0037", "category": "beta", "value": 151.24, "timestamp": 1700002220}
{"id": "rec-0038", "category": "gamma", "value": 58.47, "timestamp": 1700002280}
{"id": "rec-0039", "category": "delta", "value": 239.87, "timestamp": 1700002340}
{"id": "rec-0040", "category": "alpha", "value": 98.28, "timestamp": 1700002400}
{"id": "rec-0041", "category": "beta", "value": 188.24, "timestamp": 1700002460}
{"id": "rec-0042", "category": "gamma", "value": 51.14, "timestamp": 1700002520}
{"id": "rec-0043", "category": "delta", "value": 349.12, "timestamp": 1700002580}
{"id": "rec-0044", "category": "alpha", "value": 112.77, "timestamp": 1700002640}
{"id": "rec-0045", "category": "beta", "value": 214.0, "timestamp": 1700002700}
{"id": "rec-0046", "category": "gamma", "value": 56.5, "timestamp": 1700002760}
{"id": "rec-0047", "category": "delta", "value": 328.71, "timestamp": 1700002820}
{"id": "rec-0048", "category": "alpha", "value": 87.46, "timestamp": 1700002880}
{"id": "rec-0049", "category": "beta", "value": 171.31, "timestamp": 1700002940}
{"id": "rec-bad-01", "category": "alpha"}
{"id": "rec-bad-02", "category": "beta", "value": -5}
"""

WORKER_PY = '''#!/usr/bin/env python3
"""Multi-stage analysis pipeline — Host B continuation task."""
import json, sys, hashlib
from pathlib import Path
from collections import defaultdict

def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def sha256_bytes(data) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()

def stage_parse(workspace):
    input_path = workspace / "data" / "input_records.jsonl"
    records = [json.loads(l) for l in input_path.read_text().strip().split("\\n") if l.strip()]
    result = {"stage": "parse", "records_loaded": len(records), "first_id": records[0]["id"], "last_id": records[-1]["id"]}
    result["parent_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
    return result

def stage_filter(workspace, records, parent_hash):
    valid, rejected = [], []
    for r in records:
        if not r.get("id") or not r.get("category") or "value" not in r:
            rejected.append({"id": r.get("id", "unknown"), "reason": "missing_fields"})
        elif not isinstance(r["value"], (int, float)) or r["value"] < 0:
            rejected.append({"id": r["id"], "reason": "invalid_value"})
        else:
            valid.append(r)
    return {"stage": "filter", "parent_hash": parent_hash, "input_count": len(records), "valid_count": len(valid), "rejected_count": len(rejected), "rejected": rejected}

def stage_aggregate(workspace, records, parent_hash):
    by_cat = defaultdict(list)
    for r in records:
        by_cat[r["category"]].append(r["value"])
    stats = {}
    for cat, vals in sorted(by_cat.items()):
        stats[cat] = {"count": len(vals), "sum": round(sum(vals), 4), "mean": round(sum(vals)/len(vals), 4), "min": min(vals), "max": max(vals), "median": sorted(vals)[len(vals)//2]}
    return {"stage": "aggregate", "parent_hash": parent_hash, "categories": list(sorted(by_cat.keys())), "stats": stats}

def stage_classify(workspace, records, stats, parent_hash):
    tiers = {"critical": [], "high": [], "medium": [], "low": []}
    for r in records:
        cm = stats[r["category"]]["mean"]
        ratio = r["value"] / cm if cm > 0 else 0
        if ratio >= 2.0: tiers["critical"].append(r["id"])
        elif ratio >= 1.5: tiers["high"].append(r["id"])
        elif ratio >= 0.5: tiers["medium"].append(r["id"])
        else: tiers["low"].append(r["id"])
    return {"stage": "classify", "parent_hash": parent_hash, "tier_counts": {k: len(v) for k, v in tiers.items()}, "tier_members": tiers}

def stage_report(ws, pr, fr, ar, cr, parent_hash):
    return {"stage": "report", "parent_hash": parent_hash, "pipeline": "multi_stage_analysis_pipeline",
            "summary": {"total_input": pr["records_loaded"], "valid_records": fr["valid_count"], "rejected": fr["rejected_count"], "categories": ar["categories"], "tier_distribution": cr["tier_counts"]},
            "category_stats": ar["stats"], "tier_members": cr["tier_members"], "metadata": {"stages_completed": 5, "version": "1.1"}}

def main():
    workspace = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    out = workspace / "output"
    out.mkdir(parents=True, exist_ok=True)
    pr = stage_parse(workspace)
    parse_hash = sha256_bytes(canonical_json(pr).encode())
    pr["stage_hash"] = parse_hash
    (out / "stage_parse.json").write_text(json.dumps(pr, indent=2, sort_keys=True) + "\\n")
    print(f"Stage 1 (parse): {pr['records_loaded']} records loaded")
    input_path = workspace / "data" / "input_records.jsonl"
    records = [json.loads(l) for l in input_path.read_text().strip().split("\\n") if l.strip()]
    fr = stage_filter(workspace, records, parse_hash)
    filter_hash = sha256_bytes(canonical_json(fr))
    fr["stage_hash"] = filter_hash
    (out / "stage_filter.json").write_text(json.dumps(fr, indent=2, sort_keys=True) + "\\n")
    print(f"Stage 2 (filter): {fr['valid_count']} valid, {fr['rejected_count']} rejected")
    valid = [r for r in records if r.get("id") and r.get("category") and isinstance(r.get("value"), (int, float)) and r["value"] >= 0]
    ar = stage_aggregate(workspace, valid, filter_hash)
    agg_hash = sha256_bytes(canonical_json(ar))
    ar["stage_hash"] = agg_hash
    (out / "stage_aggregate.json").write_text(json.dumps(ar, indent=2, sort_keys=True) + "\\n")
    print(f"Stage 3 (aggregate): {len(ar['categories'])} categories")
    cr = stage_classify(workspace, valid, ar["stats"], agg_hash)
    classify_hash = sha256_bytes(canonical_json(cr))
    cr["stage_hash"] = classify_hash
    (out / "stage_classify.json").write_text(json.dumps(cr, indent=2, sort_keys=True) + "\\n")
    print(f"Stage 4 (classify): {cr['tier_counts']}")
    report = stage_report(workspace, pr, fr, ar, cr, classify_hash)
    rh = sha256_bytes(canonical_json(report))
    report["stage_hash"] = rh
    (out / "final_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\\n")
    (out / "stage_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\\n")
    print(f"Stage 5 (report): final_report.json written, hash={rh}")

if __name__ == "__main__":
    main()
'''


def hash_workspace(workspace: Path) -> dict:
    files = []
    total_size = 0
    for path in sorted(workspace.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel_path = path.relative_to(workspace).as_posix()
        st = path.stat()
        entry = {"rel_path": rel_path, "sha256": sha256_file(path), "size": st.st_size, "mode": st.st_mode & 0o777}
        files.append(entry)
        total_size += entry["size"]
    root_material = "\n".join(f"{f['rel_path']}|{f['sha256']}|{f['size']}|{f['mode']}" for f in files).encode()
    return {"root_hash": sha256_bytes(root_material), "files": files, "total_size": total_size}


def create_workspace(workspace: Path) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "src").mkdir(exist_ok=True)
    (workspace / "data").mkdir(exist_ok=True)
    (workspace / "agent_state.json").write_text(json.dumps({
        "agent_id": AGENT_ID,
        "epoch": 1,
        "host_a_label": "host-a-local-mac",
        "status": "sealed_on_host_a",
        "task": "multi_stage_analysis_pipeline",
        "task_completed": False,
        "task_stages": ["parse", "filter", "aggregate", "classify", "report"],
        "next_action": "Host B must restore workspace, execute pipeline, and seal epoch 2.",
    }, indent=2, sort_keys=True) + "\n")
    (workspace / "progress.log").write_text(
        json.dumps({"event": "created_on_host_a", "host": "host-a", "timestamp": time.time(), "epoch": 1}, sort_keys=True) + "\n"
    )
    (workspace / "todo.md").write_text(
        "# HDAR Task List\n\n## Epoch 1 (Host A)\n- [x] Create workspace\n- [x] Seal capsule\n\n## Epoch 2 (Host B)\n- [ ] Execute pipeline\n- [ ] Seal successor\n"
    )
    (workspace / "src" / "worker.py").write_text(WORKER_PY)
    (workspace / "data" / "input_records.jsonl").write_text(INPUT_RECORDS)


def seal_capsule(workspace: Path, capsule_dir: Path, owner_priv: bytes, owner_pub: bytes) -> dict:
    capsule_dir.mkdir(parents=True, exist_ok=True)
    blocks_dir = capsule_dir / "blocks"
    blocks_dir.mkdir(parents=True, exist_ok=True)

    workspace_manifest = hash_workspace(workspace)
    for entry in workspace_manifest["files"]:
        src = workspace / entry["rel_path"]
        digest = entry["sha256"]
        dest = blocks_dir / digest[:2] / digest
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)

    manifest = {
        "schema": SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "agent_id": AGENT_ID,
        "epoch": 1,
        "parent_manifest_hash": None,
        "created_at": time.time(),
        "source_host_label": "host-a-local-mac",
        "source_host_platform": platform.platform(),
        "objective": "Cross-platform HDAR continuation proof",
        "continuation_point": "Host A sealed epoch 1; Host B must restore, execute pipeline, seal epoch 2.",
        "workspace_manifest": workspace_manifest,
        "owner_public_key": owner_pub.hex(),
        "owner_signature_algorithm": "ed25519",
    }

    # Sign the manifest content (excluding manifest_hash and owner_signature)
    signing_content = {k: v for k, v in manifest.items() if k not in ("manifest_hash", "owner_signature")}
    manifest["manifest_hash"] = sha256_bytes(canonical_json(signing_content))
    manifest["owner_signature"] = sign_message(owner_priv, manifest["manifest_hash"].encode()).hex()

    (capsule_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))

    receipt = {
        "schema": RECEIPT_SCHEMA,
        "event": "capsule_sealed",
        "agent_id": AGENT_ID,
        "epoch": 1,
        "source_host_label": "host-a-local-mac",
        "source_host_platform": platform.platform(),
        "manifest_hash": manifest["manifest_hash"],
        "workspace_root_hash": workspace_manifest["root_hash"],
        "timestamp": time.time(),
    }
    receipt["receipt_hash"] = sha256_bytes(canonical_json({k: v for k, v in receipt.items() if k != "receipt_hash"}))
    (capsule_dir / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True))

    return manifest


def main() -> int:
    ap = argparse.ArgumentParser(description="HDAR Host A — Seal Epoch 1 capsule")
    ap.add_argument("--out", required=True, help="Output directory")
    args = ap.parse_args()

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate owner keypair
    owner_priv, owner_pub = generate_keypair()
    (out_dir / "owner_private_key.txt").write_text(owner_priv.hex() + "\n")
    (out_dir / "owner_public_key.txt").write_text(owner_pub.hex() + "\n")
    (out_dir / "owner_private_key.txt").chmod(0o600)
    print(f"Owner keypair generated. Public key: {owner_pub.hex()}")

    # 2. Create workspace
    workspace = out_dir / "_workspace"
    if workspace.exists():
        shutil.rmtree(workspace)
    create_workspace(workspace)
    print(f"Workspace created: {len(list(workspace.rglob('*')))} files")

    # 3. Seal capsule
    capsule_dir = out_dir / "capsule_epoch_1"
    if capsule_dir.exists():
        shutil.rmtree(capsule_dir)
    manifest = seal_capsule(workspace, capsule_dir, owner_priv, owner_pub)
    print(f"Capsule sealed. Manifest hash: {manifest['manifest_hash']}")

    # 4. Create transport tar.gz
    tar_path = out_dir / "transport_capsule_epoch_1.tar.gz"
    if tar_path.exists():
        tar_path.unlink()
    with tarfile.open(tar_path, "w:gz") as tf:
        for root, dirs, files in os.walk(capsule_dir):
            dirs.sort()
            files.sort()
            for fname in files:
                fpath = Path(root) / fname
                arcname = fpath.relative_to(capsule_dir.parent).as_posix()
                info = tarfile.TarInfo(name=arcname)
                info.size = fpath.stat().st_size
                info.mtime = 0
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                with fpath.open("rb") as f:
                    tf.addfile(info, f)
    tar_bytes = tar_path.read_bytes()
    tar_sha256 = sha256_bytes(tar_bytes)
    print(f"Transport tar.gz: {len(tar_bytes)} bytes, sha256={tar_sha256}")

    # 5. Write host_a_report.json
    report = {
        "schema": "hdar.host-a-report/v1.0",
        "protocol_version": PROTOCOL_VERSION,
        "host_a_platform": platform.platform(),
        "host_a_python": sys.version,
        "host_a_timestamp": time.time(),
        "host_a_runtime_destroyed": True,
        "owner_public_key": owner_pub.hex(),
        "owner_signature_algorithm": "ed25519",
        "capsule_epoch_1": {
            "manifest_hash": manifest["manifest_hash"],
            "workspace_root_hash": manifest["workspace_manifest"]["root_hash"],
            "file_count": len(manifest["workspace_manifest"]["files"]),
            "total_size": manifest["workspace_manifest"]["total_size"],
            "epoch": 1,
        },
        "transport_capsule": {
            "path": "transport_capsule_epoch_1.tar.gz",
            "bytes": len(tar_bytes),
            "sha256": tar_sha256,
        },
        "claim": "Host A sealed Epoch 1 with Ed25519 owner signature. Private key never leaves Host A.",
    }
    (out_dir / "host_a_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Host A report written: {out_dir / 'host_a_report.json'}")

    # 6. Clean up workspace (runtime destroyed)
    shutil.rmtree(workspace)
    print(f"Workspace destroyed (runtime destroyed=true)")

    # 7. Generate self-contained run_host_b.py
    tar_b64 = base64.b64encode(tar_bytes).decode()
    runner_path = Path(__file__).parent / "run_host_b.py"
    runner_template = runner_path.read_text() if runner_path.exists() else ""
    # The runner template has EMBEDDED_CAPSULE_B64 and EMBEDDED_CAPSULE_SHA256 placeholders
    if "EMBEDDED_CAPSULE_B64" in runner_template:
        runner_text = runner_template
        runner_text = runner_text.replace('EMBEDDED_CAPSULE_B64 = ""', f'EMBEDDED_CAPSULE_B64 = "{tar_b64}"')
        runner_text = runner_text.replace('EMBEDDED_CAPSULE_SHA256 = ""', f'EMBEDDED_CAPSULE_SHA256 = "{tar_sha256}"')
        runner_text = runner_text.replace('EMBEDDED_OWNER_PUB = ""', f'EMBEDDED_OWNER_PUB = "{owner_pub.hex()}"')
        runner_text = runner_text.replace('EMBEDDED_HOST_A_PLATFORM = ""', f'EMBEDDED_HOST_A_PLATFORM = "{platform.platform()}"')
        embedded_path = out_dir / "run_host_b.py"
        embedded_path.write_text(runner_text)
        embedded_path.chmod(0o755)
        print(f"Self-contained runner written: {embedded_path} ({len(runner_text)} bytes)")
    else:
        print("WARNING: run_host_b.py template not found or missing placeholders. Copy manually.")

    print()
    print("=" * 60)
    print("Host A complete. Artifacts in:", out_dir)
    print("=" * 60)
    print(f"  owner_public_key.txt   — share this with Host B and Verifier")
    print(f"  transport_capsule_epoch_1.tar.gz — the sealed capsule")
    print(f"  host_a_report.json     — Host A build report")
    print(f"  run_host_b.py          — self-contained Host B runner (embeds capsule)")
    print(f"  owner_private_key.txt  — KEEP PRIVATE. Needed for verifier.")
    print()
    print("Next: Copy run_host_b.py to Colab / Codespaces / E2B and run it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
