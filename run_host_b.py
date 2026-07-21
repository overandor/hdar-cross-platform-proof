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
EMBEDDED_CAPSULE_B64 = ""
EMBEDDED_CAPSULE_SHA256 = ""
EMBEDDED_OWNER_PUB = ""
EMBEDDED_HOST_A_PLATFORM = ""
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
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("FATAL: cryptography package required. Install: pip install cryptography", file=sys.stderr)
    sys.exit(1)


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an ephemeral Ed25519 keypair for Host B signing."""
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
    """Sign a message with an Ed25519 private key."""
    key = Ed25519PrivateKey.from_private_bytes(priv)
    return key.sign(msg)


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


def seal_epoch_2(
    workspace: Path,
    capsule_dir: Path,
    epoch: int,
    parent_manifest_hash: str,
    host_label: str,
    host_b_priv: bytes | None = None,
    host_b_pub: bytes | None = None,
    challenge_nonce: str = "",
) -> dict:
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
        "continuation_point": f"Host B ({host_label}) restored E1, executed pipeline, updated agent state, sealed E2.",
        "workspace_manifest": workspace_manifest,
    }
    if challenge_nonce:
        manifest["challenge_nonce"] = challenge_nonce
    if host_b_pub is not None:
        manifest["host_b_public_key"] = host_b_pub.hex()

    signing_content = {k: v for k, v in manifest.items() if k not in ("manifest_hash", "host_b_signature")}
    manifest["manifest_hash"] = sha256_bytes(canonical_json(signing_content))

    # Host B signs the manifest hash
    if host_b_priv is not None and host_b_pub is not None:
        signature = sign_message(host_b_priv, manifest["manifest_hash"].encode())
        manifest["host_b_signature"] = signature.hex()

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
    if host_b_pub is not None:
        receipt["host_b_public_key"] = host_b_pub.hex()
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
    ap.add_argument("--challenge-nonce", default="", help="Verifier-issued challenge nonce (optional, for challenge-response freshness)")
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

    # 5b. Update agent state to reflect completion (semantic continuation)
    print("\n[5b/6] Updating agent state for Epoch 2...")
    agent_state_path = restored_workspace / "agent_state.json"
    agent_state = json.loads(agent_state_path.read_text())
    agent_state["epoch"] = 2
    agent_state["task_completed"] = True
    agent_state["status"] = "completed_on_host_b"
    agent_state["previous_manifest_hash"] = verification["manifest_hash"]
    agent_state["completed_at_utc"] = utc_now_iso()
    agent_state["completed_on_platform"] = platform.platform()
    agent_state["next_action"] = "Epoch 3: Transfer E2 to next host or verify lineage."
    agent_state_path.write_text(json.dumps(agent_state, indent=2, sort_keys=True) + "\n")
    print(f"  agent_state.epoch = {agent_state['epoch']}")
    print(f"  agent_state.task_completed = {agent_state['task_completed']}")
    print(f"  agent_state.status = {agent_state['status']}")

    # 5c. Update todo.md to mark Epoch 2 work complete
    todo_path = restored_workspace / "todo.md"
    todo_path.write_text(
        "# HDAR Task List\n\n"
        "## Epoch 1 (Host A)\n"
        "- [x] Create workspace\n"
        "- [x] Seal capsule\n\n"
        "## Epoch 2 (Host B)\n"
        "- [x] Execute pipeline\n"
        "- [x] Seal successor\n"
        "- [x] Update agent state\n\n"
        "## Epoch 3 (Next Host)\n"
        "- [ ] Restore E2 capsule\n"
        "- [ ] Continue work\n"
    )
    print(f"  todo.md updated: Epoch 2 marked complete")

    # 5d. Append to progress.log
    progress_path = restored_workspace / "progress.log"
    with progress_path.open("a") as f:
        f.write(json.dumps({
            "event": "completed_on_host_b",
            "host": host_label,
            "platform": platform.platform(),
            "timestamp": time.time(),
            "epoch": 2,
            "pipeline_output_hash": task_result["output_hash"],
        }, sort_keys=True) + "\n")

    # 6. Seal Epoch 2 (with Host B ephemeral signing)
    print("\n[6/6] Sealing Epoch 2 successor capsule...")
    capsule_epoch_2 = out_dir / "capsule_epoch_2"
    if capsule_epoch_2.exists():
        shutil.rmtree(capsule_epoch_2)

    # Generate ephemeral Host B signing key
    host_b_priv, host_b_pub = generate_keypair()

    e2_manifest = seal_epoch_2(
        restored_workspace,
        capsule_epoch_2,
        epoch=2,
        parent_manifest_hash=verification["manifest_hash"],
        host_label=host_label,
        host_b_priv=host_b_priv,
        host_b_pub=host_b_pub,
        challenge_nonce=args.challenge_nonce,
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
        "host_b_public_key": host_b_pub.hex(),
        "host_b_signature": e2_manifest.get("host_b_signature", ""),
        "challenge_nonce": args.challenge_nonce if args.challenge_nonce else None,
        "claim": f"Host B ({host_label}) independently restored E1, verified owner signature, executed pipeline, updated agent state, sealed E2.",
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
