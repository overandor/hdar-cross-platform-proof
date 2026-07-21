#!/usr/bin/env python3
"""HDAR Host B — Self-contained cross-platform runner.

This script embeds the Epoch 1 capsule as base64. It runs on ANY platform
(Colab, Codespaces, E2B, local Linux, etc.) and performs:

1. Extract the embedded capsule
2. Verify the Ed25519 owner signature (using embedded public key)
3. Restore the workspace exactly
4. Execute the 5-stage deterministic pipeline
5. Seal Epoch 2 successor capsule
6. Write host_b_report.json with platform-specific evidence

Usage:
    python3 run_host_b.py --out ./host_b_output --host-label my-platform

No dependencies beyond Python 3.8+ and the `cryptography` package.
    pip install cryptography

The capsule, owner public key, and Host A platform are embedded by host_a_seal.py.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import shutil
import socket
import sys
import tarfile
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ============================================================================
# EMBEDDED ARTIFACTS — filled in by host_a_seal.py
# ============================================================================
EMBEDDED_CAPSULE_B64 = "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"
EMBEDDED_CAPSULE_SHA256 = "6070ff00b071aa32fc48a4c520b4baf8b93a9baad10e8935d158ada01f8abf1c"
EMBEDDED_OWNER_PUB = "3fa03ea8102c4c322e91f2ec8a05555abb0bbf37566d8936948d50462748166b"
EMBEDDED_HOST_A_PLATFORM = "macOS-26.5.2-arm64-arm-64bit-Mach-O"
# ============================================================================

CHUNK_SIZE = 1024 * 1024
SCHEMA = "hdar.transport-capsule/v0.1"
RECEIPT_SCHEMA = "hdar.receipt/v0.1"
AGENT_ID = "hdar-cross-platform-agent"
PROTOCOL_VERSION = "hdar-canonical/v1.0"

# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("FATAL: cryptography package required. Install: pip install cryptography", file=sys.stderr)
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


def verify_signature(pub_bytes: bytes, message: bytes, signature: bytes) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(signature, message)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Workspace hashing and capsule operations
# ---------------------------------------------------------------------------

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


def verify_capsule(capsule_dir: Path, owner_pub_hex: str) -> dict:
    manifest = json.loads((capsule_dir / "manifest.json").read_text())
    problems = []

    # Verify manifest hash
    signing_content = {k: v for k, v in manifest.items() if k not in ("manifest_hash", "owner_signature")}
    expected_hash = sha256_bytes(canonical_json(signing_content))
    if expected_hash != manifest.get("manifest_hash"):
        problems.append("manifest hash mismatch")

    # Verify content blocks
    missing = 0
    corrupt = 0
    for entry in manifest["workspace_manifest"]["files"]:
        digest = entry["sha256"]
        blob = capsule_dir / "blocks" / digest[:2] / digest
        if not blob.exists():
            missing += 1
        elif sha256_file(blob) != digest:
            corrupt += 1
    if missing:
        problems.append(f"{missing} content blocks missing")
    if corrupt:
        problems.append(f"{corrupt} content blocks corrupt")

    # Verify Ed25519 owner signature
    sig_valid = False
    if "owner_signature" in manifest and "owner_public_key" in manifest:
        if manifest["owner_public_key"] != owner_pub_hex:
            problems.append("owner public key mismatch")
        else:
            sig_valid = verify_signature(
                bytes.fromhex(owner_pub_hex),
                manifest["manifest_hash"].encode(),
                bytes.fromhex(manifest["owner_signature"]),
            )
            if not sig_valid:
                problems.append("owner Ed25519 signature INVALID")
    else:
        problems.append("no owner signature in manifest")

    # Verify receipt
    receipt = json.loads((capsule_dir / "receipt.json").read_text())
    receipt_expected = sha256_bytes(canonical_json({k: v for k, v in receipt.items() if k != "receipt_hash"}))
    if receipt_expected != receipt.get("receipt_hash"):
        problems.append("receipt hash mismatch")

    return {
        "ok": not problems,
        "problems": problems,
        "manifest_hash": manifest["manifest_hash"],
        "workspace_root_hash": manifest["workspace_manifest"]["root_hash"],
        "epoch": manifest["epoch"],
        "owner_signed": "owner_signature" in manifest,
        "signature_valid": sig_valid,
        "parent_manifest_hash": manifest.get("parent_manifest_hash"),
        "file_count": len(manifest["workspace_manifest"]["files"]),
        "total_size": manifest["workspace_manifest"]["total_size"],
    }


def restore_workspace(capsule_dir: Path, dest: Path) -> dict:
    manifest = json.loads((capsule_dir / "manifest.json").read_text())
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for entry in manifest["workspace_manifest"]["files"]:
        blob = capsule_dir / "blocks" / entry["sha256"][:2] / entry["sha256"]
        out = dest / entry["rel_path"]
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(blob, out)
        os.chmod(out, entry["mode"])
    restored = hash_workspace(dest)
    return {
        "restored_root_hash": restored["root_hash"],
        "expected_root_hash": manifest["workspace_manifest"]["root_hash"],
        "exact": restored["root_hash"] == manifest["workspace_manifest"]["root_hash"],
        "file_count": len(restored["files"]),
    }


def safe_extract_tar(tf: tarfile.TarFile, dest: Path) -> None:
    dest_resolved = dest.resolve()
    for member in tf.getmembers():
        if member.name.startswith("/"):
            raise ValueError(f"tar member has absolute path: {member.name}")
        if ".." in Path(member.name).parts:
            raise ValueError(f"tar member has path traversal: {member.name}")
        if member.issym() or member.islnk():
            raise ValueError(f"tar member is symlink/hardlink: {member.name}")
        if not (member.isfile() or member.isdir()):
            raise ValueError(f"tar member is not regular file or dir: {member.name}")
        member_path = (dest / member.name).resolve()
        if not str(member_path).startswith(str(dest_resolved) + os.sep) and member_path != dest_resolved:
            raise ValueError(f"tar member escapes destination: {member.name}")
    if sys.version_info >= (3, 12):
        tf.extractall(dest, filter="data")
    else:
        tf.extractall(dest)


def seal_epoch_2(workspace: Path, capsule_dir: Path, epoch: int, parent_manifest_hash: str, host_label: str) -> dict:
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
        "epoch": epoch,
        "parent_manifest_hash": parent_manifest_hash,
        "created_at": time.time(),
        "source_host_label": host_label,
        "source_host_platform": platform.platform(),
        "objective": "Cross-platform HDAR continuation proof — Epoch 2 sealed by Host B",
        "continuation_point": f"Host B ({host_label}) restored E1, executed pipeline, sealed E2.",
        "workspace_manifest": workspace_manifest,
    }
    signing_content = {k: v for k, v in manifest.items() if k not in ("manifest_hash",)}
    manifest["manifest_hash"] = sha256_bytes(canonical_json(signing_content))

    (capsule_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))

    receipt = {
        "schema": RECEIPT_SCHEMA,
        "event": "capsule_sealed_after_host_b_continuation",
        "agent_id": AGENT_ID,
        "epoch": epoch,
        "source_host_label": host_label,
        "source_host_platform": platform.platform(),
        "manifest_hash": manifest["manifest_hash"],
        "workspace_root_hash": workspace_manifest["root_hash"],
        "timestamp": time.time(),
    }
    receipt["receipt_hash"] = sha256_bytes(canonical_json({k: v for k, v in receipt.items() if k != "receipt_hash"}))
    (capsule_dir / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True))

    return manifest


def execute_pipeline(workspace: Path) -> dict:
    worker_path = workspace / "src" / "worker.py"
    if not worker_path.exists():
        return {"ok": False, "reason": "src/worker.py not found"}
    import subprocess
    result = subprocess.run(
        [sys.executable, str(worker_path), str(workspace)],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        return {"ok": False, "reason": f"worker.py exited {result.returncode}: {result.stderr}"}
    output_path = workspace / "output" / "final_report.json"
    if not output_path.exists():
        return {"ok": False, "reason": "worker.py did not produce output/final_report.json"}
    output = json.loads(output_path.read_text())
    output_hash = sha256_bytes(canonical_json(output))

    stage_chain = []
    for sname in ["parse", "filter", "aggregate", "classify", "report"]:
        sfile = workspace / "output" / f"stage_{sname}.json"
        if sfile.exists():
            sdata = json.loads(sfile.read_text())
            stage_chain.append({"stage": sname, "hash": sdata.get("stage_hash", ""), "parent_hash": sdata.get("parent_hash")})

    return {
        "ok": True,
        "pipeline": "multi_stage_analysis_pipeline",
        "stages_completed": output.get("metadata", {}).get("stages_completed", 0),
        "output_hash": output_hash,
        "stage_chain": stage_chain,
        "stdout": result.stdout,
    }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    ap = argparse.ArgumentParser(description="HDAR Host B — Cross-platform runner")
    ap.add_argument("--out", default="./host_b_output", help="Output directory")
    ap.add_argument("--host-label", default="", help="Label for this host (auto-detected if empty)")
    ap.add_argument("--operator", default="", help="Operator identity (optional)")
    args = ap.parse_args()

    if not EMBEDDED_CAPSULE_B64:
        print("FATAL: This script has no embedded capsule. Run host_a_seal.py first to generate it.", file=sys.stderr)
        return 1

    runner_start = time.time()
    runner_start_utc = utc_now_iso()
    machine_nonce = str(uuid.uuid4())
    machine_hostname = socket.gethostname()
    host_label = args.host_label or f"{machine_hostname}-{platform.system().lower()}"

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print(f"HDAR Host B — Cross-platform continuation proof")
    print(f"Host label: {host_label}")
    print(f"Platform: {platform.platform()}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Hostname: {machine_hostname}")
    print(f"Nonce: {machine_nonce}")
    print(f"Started: {runner_start_utc}")
    print("=" * 60)

    # 1. Decode and verify embedded capsule
    print("\n[1/6] Decoding embedded capsule...")
    capsule_bytes = base64.b64decode(EMBEDDED_CAPSULE_B64.encode())
    capsule_hash = sha256_bytes(capsule_bytes)
    print(f"  Capsule SHA-256: {capsule_hash}")
    if capsule_hash != EMBEDDED_CAPSULE_SHA256:
        print(f"  FATAL: Capsule hash mismatch! Expected {EMBEDDED_CAPSULE_SHA256}", file=sys.stderr)
        return 1
    print(f"  Hash verified: matches embedded checksum")

    # 2. Extract capsule
    print("\n[2/6] Extracting capsule...")
    tar_path = out_dir / "transport_capsule_epoch_1.tar.gz"
    tar_path.write_bytes(capsule_bytes)
    with tarfile.open(tar_path, "r:gz") as tf:
        safe_extract_tar(tf, out_dir)
    print(f"  Extracted to: {out_dir}")

    # Find capsule directory
    capsule_epoch_1 = None
    for candidate in ("capsule_epoch_1", "capsule"):
        cdir = out_dir / candidate
        if (cdir / "manifest.json").exists():
            capsule_epoch_1 = cdir
            break
    if capsule_epoch_1 is None:
        for d in out_dir.iterdir():
            if d.is_dir() and (d / "manifest.json").exists():
                capsule_epoch_1 = d
                break
    if capsule_epoch_1 is None:
        print("FATAL: Could not find capsule directory with manifest.json", file=sys.stderr)
        return 1
    print(f"  Capsule directory: {capsule_epoch_1.name}")

    # 3. Verify capsule (signature, hashes, blocks)
    print("\n[3/6] Verifying Epoch 1 capsule...")
    verification = verify_capsule(capsule_epoch_1, EMBEDDED_OWNER_PUB)
    if not verification["ok"]:
        print(f"  FATAL: Capsule verification failed: {verification['problems']}", file=sys.stderr)
        return 1
    print(f"  Manifest hash: {verification['manifest_hash']}")
    print(f"  Workspace root hash: {verification['workspace_root_hash']}")
    print(f"  Owner signature valid: {verification['signature_valid']}")
    print(f"  Files: {verification['file_count']}, Size: {verification['total_size']}B")
    print(f"  Host A platform: {EMBEDDED_HOST_A_PLATFORM}")
    print(f"  Platform separation: {'YES' if platform.platform() != EMBEDDED_HOST_A_PLATFORM else 'NO (same platform)'}")

    # 4. Restore workspace
    print("\n[4/6] Restoring workspace...")
    restored_workspace = out_dir / "restored_workspace"
    restore_report = restore_workspace(capsule_epoch_1, restored_workspace)
    if not restore_report["exact"]:
        print("FATAL: Workspace restoration was not exact!", file=sys.stderr)
        return 1
    print(f"  Restoration exact: True")
    print(f"  Files restored: {restore_report['file_count']}")

    # 5. Execute pipeline
    print("\n[5/6] Executing 5-stage pipeline...")
    task_result = execute_pipeline(restored_workspace)
    if not task_result["ok"]:
        print(f"FATAL: Pipeline execution failed: {task_result.get('reason')}", file=sys.stderr)
        return 1
    print(f"  Pipeline output hash: {task_result['output_hash']}")
    print(f"  Stages completed: {task_result['stages_completed']}")
    for stage in task_result["stage_chain"]:
        print(f"    {stage['stage']}: {stage['hash'][:16]}...")

    # 6. Seal Epoch 2
    print("\n[6/6] Sealing Epoch 2 successor capsule...")
    capsule_epoch_2 = out_dir / "capsule_epoch_2"
    if capsule_epoch_2.exists():
        shutil.rmtree(capsule_epoch_2)
    e2_manifest = seal_epoch_2(
        restored_workspace,
        capsule_epoch_2,
        epoch=2,
        parent_manifest_hash=verification["manifest_hash"],
        host_label=host_label,
    )
    print(f"  E2 manifest hash: {e2_manifest['manifest_hash']}")
    print(f"  E2 parent hash: {e2_manifest['parent_manifest_hash']}")
    print(f"  E2 workspace root: {e2_manifest['workspace_manifest']['root_hash']}")

    # Create E2 transport tar
    e2_tar = out_dir / "transport_capsule_epoch_2.tar.gz"
    with tarfile.open(e2_tar, "w:gz") as tf:
        for root, dirs, files in os.walk(capsule_epoch_2):
            dirs.sort()
            files.sort()
            for fname in files:
                fpath = Path(root) / fname
                arcname = fpath.relative_to(capsule_epoch_2.parent).as_posix()
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
    e2_tar_bytes = e2_tar.read_bytes()
    e2_tar_sha256 = sha256_bytes(e2_tar_bytes)

    runner_end = time.time()
    runner_end_utc = utc_now_iso()

    # Write host_b_report.json
    report = {
        "schema": "hdar.host-b-report/v1.0",
        "protocol_version": PROTOCOL_VERSION,
        "host_b_identity": {
            "host_label": host_label,
            "machine_hostname": machine_hostname,
            "platform": platform.platform(),
            "python_version": sys.version,
            "machine_nonce": machine_nonce,
            "operator": args.operator,
            "runner_start_utc": runner_start_utc,
            "runner_end_utc": runner_end_utc,
            "runner_duration_seconds": round(runner_end - runner_start, 3),
        },
        "host_b_platform": platform.platform(),
        "host_a_platform": EMBEDDED_HOST_A_PLATFORM,
        "platforms_differ": platform.platform() != EMBEDDED_HOST_A_PLATFORM,
        "capsule_e1_verification": verification,
        "workspace_restoration": restore_report,
        "pipeline_result": task_result,
        "capsule_e2": {
            "manifest_hash": e2_manifest["manifest_hash"],
            "parent_manifest_hash": e2_manifest["parent_manifest_hash"],
            "workspace_root_hash": e2_manifest["workspace_manifest"]["root_hash"],
            "file_count": len(e2_manifest["workspace_manifest"]["files"]),
            "total_size": e2_manifest["workspace_manifest"]["total_size"],
            "epoch": 2,
        },
        "transport_capsule_e2": {
            "bytes": len(e2_tar_bytes),
            "sha256": e2_tar_sha256,
        },
        "owner_public_key": EMBEDDED_OWNER_PUB,
        "claim": f"Host B ({host_label}) independently restored E1, verified owner signature, executed pipeline, sealed E2.",
        "claim_boundary": "This report is generated by Host B. It proves the capsule was restorable and the pipeline is deterministic on this platform. Cross-platform proof requires the verifier to confirm platforms_differ=true.",
    }
    report_path = out_dir / "host_b_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    print("\n" + "=" * 60)
    print(f"Host B complete. Report: {report_path}")
    print("=" * 60)
    print(f"  Platform: {platform.platform()}")
    print(f"  Platform separation: {report['platforms_differ']}")
    print(f"  Pipeline output hash: {task_result['output_hash']}")
    print(f"  E2 manifest hash: {e2_manifest['manifest_hash']}")
    print(f"  Duration: {round(runner_end - runner_start, 3)}s")
    print()
    print("To verify: copy host_b_report.json + capsule_epoch_2/ back to Host A")
    print("           then run: python3 verify_all.py --host-a-dir <host_a_dir> --host-b-report <report.json> --e2-capsule <capsule_epoch_2>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
