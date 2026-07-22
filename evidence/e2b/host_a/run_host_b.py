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
EMBEDDED_CAPSULE_SHA256 = "c6de0b6aa4bf6733d800a2c3e7a4a5625ebee042522d763d5b4c34a9b987ab31"
EMBEDDED_OWNER_PUB = "d76415e64342c89b43b3ef6f9503fc85338d104a42d571a95d38f70e57e70a7e"
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

    # Verify receipt (try both old and new hash methods for backward compat)
    receipt = json.loads((capsule_dir / "receipt.json").read_text())
    receipt_expected_new = sha256_bytes(canonical_json(
        {k: v for k, v in receipt.items() if k != "receipt_hash" and k != "manifest_hash"}
    ))
    receipt_expected_old = sha256_bytes(canonical_json(
        {k: v for k, v in receipt.items() if k != "receipt_hash"}
    ))
    if receipt_expected_new != receipt.get("receipt_hash") and receipt_expected_old != receipt.get("receipt_hash"):
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

    # Generate Host B environment manifest and bind its hash into E2
    # (audit defect 7: environment manifest was not evidence-bound)
    import subprocess as _sp
    def _pip_freeze() -> list[str]:
        try:
            r = _sp.run([sys.executable, "-m", "pip", "freeze"], capture_output=True, text=True, timeout=10)
            return r.stdout.strip().split("\n") if r.returncode == 0 else []
        except Exception:
            return []
    host_b_env_manifest = {
        "python_version": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "machine": platform.machine(),
        "os_uname": list(platform.uname()),
        "hostname": platform.node(),
        "installed_packages": _pip_freeze(),
    }
    host_b_env_manifest_hash = sha256_bytes(canonical_json(host_b_env_manifest))

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
        "host_b_environment_manifest_hash": host_b_env_manifest_hash,
    }
    if challenge_nonce:
        manifest["challenge_nonce"] = challenge_nonce
    if host_b_pub is not None:
        manifest["host_b_public_key"] = host_b_pub.hex()

    # Bind the receipt hash into the manifest (audit defect 6: receipts were
    # self-hashed only, not anchored into the signed manifest).
    # Receipt hash is computed over a stable subset (excluding manifest_hash
    # and receipt_hash) to avoid circular dependency. See host_a_seal.py for
    # the full explanation.
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "event": "capsule_sealed_after_host_b_continuation",
        "agent_id": AGENT_ID,
        "epoch": epoch,
        "source_host_label": host_label,
        "source_host_platform": platform.platform(),
        "manifest_hash": "",  # filled after manifest hash is known
        "workspace_root_hash": workspace_manifest["root_hash"],
        "timestamp": time.time(),
    }
    if host_b_pub is not None:
        receipt["host_b_public_key"] = host_b_pub.hex()
    receipt["receipt_hash"] = sha256_bytes(canonical_json(
        {k: v for k, v in receipt.items() if k != "receipt_hash" and k != "manifest_hash"}
    ))

    # Bind receipt_hash into manifest, compute manifest hash
    manifest["receipt_hash"] = receipt["receipt_hash"]
    signing_content = {k: v for k, v in manifest.items() if k not in ("manifest_hash", "host_b_signature")}
    manifest["manifest_hash"] = sha256_bytes(canonical_json(signing_content))

    # Fill in manifest_hash in receipt (informational linkage)
    receipt["manifest_hash"] = manifest["manifest_hash"]

    # Host B signs the manifest hash
    if host_b_priv is not None and host_b_pub is not None:
        signature = sign_message(host_b_priv, manifest["manifest_hash"].encode())
        manifest["host_b_signature"] = signature.hex()

    (capsule_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    (capsule_dir / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True))
    # Write Host B environment manifest alongside the E2 capsule
    (capsule_dir / "environment_manifest.json").write_text(
        json.dumps(host_b_env_manifest, indent=2, sort_keys=True) + "\n"
    )

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
