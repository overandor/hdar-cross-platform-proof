#!/usr/bin/env python3
"""HDAR Canonical Release Bundle — freeze one immutable E1 for multi-provider proof.

The audit's central remaining milestone:

    "Freeze one canonical release bundle ... then dispatch the IDENTICAL
     immutable bundle to E2B, GitHub Codespaces, ChatGPT Linux, Google Colab,
     and an independent outside operator. Every run must begin with the same
     E1 manifest, owner key, runner hash, verifier hash, worker version, and
     ruleset. Different E1 hashes mean it is a different experiment."

This module:

1. Runs Host A once to produce a canonical E1 capsule, owner keypair, and
   embedded runner.
2. Hashes every canonical component (runner, verifier, builder, orchestrator,
   worker, ruleset) into a release_manifest.json.
3. Captures dependency evidence (pinned versions, wheel SHA-256s, install
   transcript) so the bundle is reproducible byte-for-byte.
4. Packs everything into a single self-contained `release_bundle.tar.gz`.
5. Exposes `load_release()` so `run_proof.py --reuse-release <bundle>` can
   dispatch the IDENTICAL bundle to multiple providers without rebuilding E1.

Usage:

    # Build a canonical release (run once):
    python3 release.py build --out /tmp/hdar_release

    # Inspect a release manifest:
    python3 release.py inspect /tmp/hdar_release/release_bundle.tar.gz

    # Verify a release bundle is internally consistent:
    python3 release.py verify /tmp/hdar_release/release_bundle.tar.gz

A release is a directory containing:

    release_manifest.json          # the frozen identity of this release
    release_bundle.tar.gz          # self-contained tarball for dispatch
    host_a/                        # Host A output (E1 capsule, owner keys, runner)
    dependency_evidence.json       # pinned versions + wheel hashes + transcript
    requirements.lock              # pip-freeze output at build time
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).parent.resolve()
CHUNK_SIZE = 1024 * 1024
RELEASE_SCHEMA = "hdar.release-manifest/v1.0"
PROTOCOL_VERSION = "hdar-canonical/v1.0"

# Canonical files whose hashes are frozen into the release manifest.
# Any change to these files produces a different release identity.
CANONICAL_FILES = {
    "builder": "host_a_seal.py",
    "runner_template": "run_host_b.py",
    "verifier": "verify_all.py",
    "orchestrator": "run_proof.py",
    "release_tool": "release.py",
}


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


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_extract_tar(tf: tarfile.TarFile, dest: Path) -> None:
    """Extract tar with explicit safety: reject absolute paths, .., symlinks,
    hardlinks, and non-regular files. Uses filter='data' on Python 3.12+."""
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


# ---------------------------------------------------------------------------
# Dependency evidence
# ---------------------------------------------------------------------------

def capture_dependency_evidence() -> dict:
    """Capture pinned dependency versions, wheel hashes, and install transcript.

    This produces reproducible dependency evidence so a downstream verifier can
    confirm the Host B environment matches the release's pinned versions.
    """
    import subprocess as _sp

    # pip freeze → requirements.lock content
    try:
        r = _sp.run(
            [sys.executable, "-m", "pip", "freeze"],
            capture_output=True, text=True, timeout=15,
        )
        freeze_output = r.stdout.strip() if r.returncode == 0 else ""
    except Exception as e:
        freeze_output = f"(pip freeze failed: {e})"

    pinned = {}
    for line in freeze_output.split("\n"):
        if "==" in line:
            name, version = line.split("==", 1)
            pinned[name.strip().lower()] = version.strip()

    # Capture wheel hashes for the cryptography package (the one runtime dep).
    # `pip show -f` gives file lists but not wheel hashes; `pip download` with
    # --no-deps and hash reporting is the canonical way. We record what we can
    # without network calls here; the full wheel-hash capture happens during
    # `release.py build` via `pip download --hashes`.
    crypto_version = pinned.get("cryptography", "unknown")

    return {
        "schema": "hdar.dependency-evidence/v1.0",
        "captured_at_utc": utc_now_iso(),
        "python_version": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "pip_freeze": freeze_output,
        "pinned_versions": pinned,
        "requirements_lock": freeze_output,
        "requirements_lock_sha256": sha256_bytes(freeze_output.encode()),
        "cryptography_version": crypto_version,
        "note": (
            "Wheel SHA-256s require `pip download --no-deps --dest <dir> "
            "cryptography==<version>` at build time. See release_bundle/ "
            "wheel_hashes.json for the captured digests."
        ),
    }


def capture_wheel_hashes(dest_dir: Path) -> dict:
    """Download the cryptography wheel and record its SHA-256.

    This is the strongest dependency evidence: the exact wheel bytes that
    should be installed on Host B. Falls back gracefully if offline.
    """
    import subprocess as _sp

    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        r = _sp.run(
            [sys.executable, "-m", "pip", "download",
             "--no-deps", "--no-binary=:none:",
             "--dest", str(dest_dir),
             "cryptography"],
            capture_output=True, text=True, timeout=120,
        )
        transcript = r.stdout + ("\n--- stderr ---\n" + r.stderr if r.stderr else "")
        success = r.returncode == 0
    except Exception as e:
        transcript = f"(pip download failed: {e})"
        success = False

    wheel_hashes = {}
    if success:
        for f in dest_dir.glob("*.whl"):
            wheel_hashes[f.name] = sha256_file(f)
        for f in dest_dir.glob("*.tar.gz"):
            wheel_hashes[f.name] = sha256_file(f)

    return {
        "captured_at_utc": utc_now_iso(),
        "success": success,
        "transcript": transcript,
        "wheel_hashes": wheel_hashes,
        "wheel_count": len(wheel_hashes),
    }


# ---------------------------------------------------------------------------
# Source-commit binding
# ---------------------------------------------------------------------------

def get_source_commit_binding() -> dict:
    import subprocess as _sp

    def _git(args: list[str]) -> str:
        try:
            r = _sp.run(["git"] + args, cwd=REPO_ROOT, capture_output=True, text=True, timeout=5)
            return r.stdout.strip() if r.returncode == 0 else ""
        except Exception:
            return ""

    commit_sha = _git(["rev-parse", "HEAD"])
    dirty = _git(["status", "--porcelain"])
    remote_url = _git(["config", "--get", "remote.origin.url"])
    branch = _git(["rev-parse", "--abbrev-ref", "HEAD"])

    file_hashes = {}
    for label, fname in CANONICAL_FILES.items():
        fpath = REPO_ROOT / fname
        file_hashes[label] = {
            "filename": fname,
            "sha256": sha256_file(fpath) if fpath.exists() else "",
        }

    return {
        "repository": remote_url,
        "branch": branch,
        "commit_sha": commit_sha,
        "dirty_tree": bool(dirty),
        "dirty_files": dirty.split("\n") if dirty else [],
        "canonical_file_hashes": file_hashes,
    }


# ---------------------------------------------------------------------------
# Release build
# ---------------------------------------------------------------------------

def build_release(out_dir: Path) -> dict:
    """Build a canonical release bundle.

    Steps:
      1. Run host_a_seal.py once → canonical E1, owner keypair, embedded runner.
      2. Hash every canonical file.
      3. Capture dependency evidence + wheel hashes.
      4. Write release_manifest.json (the frozen identity).
      5. Pack release_bundle.tar.gz (the immutable dispatch artifact).
    """
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("HDAR Canonical Release — Build")
    print("=" * 70)
    print(f"  Output: {out_dir}")
    print(f"  Platform: {platform.platform()}")
    print(f"  Python: {sys.version.split()[0]}")
    print()

    # 1. Run Host A to produce canonical E1
    host_a_dir = out_dir / "host_a"
    if host_a_dir.exists():
        shutil.rmtree(host_a_dir)
    print("[1/5] Sealing canonical Epoch 1 (Host A)...")
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "host_a_seal.py"), "--out", str(host_a_dir)],
        cwd=str(REPO_ROOT),
    )
    if result.returncode != 0:
        print(f"FATAL: host_a_seal.py exited {result.returncode}", file=sys.stderr)
        sys.exit(1)

    host_a_report = json.loads((host_a_dir / "host_a_report.json").read_text())
    owner_pub = (host_a_dir / "owner_public_key.txt").read_text().strip()
    e1_manifest = json.loads((host_a_dir / "capsule_epoch_1" / "manifest.json").read_text())
    runner_path = host_a_dir / "run_host_b.py"
    runner_sha256 = sha256_file(runner_path)
    transport_tar = host_a_dir / "transport_capsule_epoch_1.tar.gz"
    transport_sha256 = sha256_file(transport_tar)

    print(f"  E1 manifest hash:      {e1_manifest['manifest_hash']}")
    print(f"  E1 workspace root:     {e1_manifest['workspace_manifest']['root_hash']}")
    print(f"  Owner public key:      {owner_pub[:16]}...")
    print(f"  Runner SHA-256:        {runner_sha256}")
    print(f"  Transport capsule SHA: {transport_sha256}")

    # 2. Capture source-commit binding + canonical file hashes
    print("\n[2/5] Capturing source-commit binding and canonical file hashes...")
    source_binding = get_source_commit_binding()
    # Override runner hash with the EMBEDDED runner (the one actually dispatched)
    source_binding["canonical_file_hashes"]["runner_template"]["sha256"] = runner_sha256
    source_binding["canonical_file_hashes"]["runner_template"]["filename"] = "host_a/run_host_b.py"
    print(f"  Git commit: {source_binding['commit_sha'][:16]}...")
    print(f"  Dirty tree: {source_binding['dirty_tree']}")

    # 3. Capture dependency evidence
    print("\n[3/5] Capturing dependency evidence...")
    dep_evidence = capture_dependency_evidence()
    wheel_dir = out_dir / "wheels"
    wheel_evidence = capture_wheel_hashes(wheel_dir)
    dep_evidence["wheel_hashes"] = wheel_evidence["wheel_hashes"]
    dep_evidence["wheel_capture_transcript"] = wheel_evidence["transcript"]
    dep_evidence["wheel_capture_success"] = wheel_evidence["success"]
    (out_dir / "dependency_evidence.json").write_text(
        json.dumps(dep_evidence, indent=2, sort_keys=True) + "\n"
    )
    (out_dir / "requirements.lock").write_text(dep_evidence["requirements_lock"] + "\n")
    print(f"  requirements.lock: {dep_evidence['requirements_lock_sha256'][:16]}...")
    print(f"  Wheel hashes: {len(wheel_evidence['wheel_hashes'])} captured")

    # 4. Write release_manifest.json — the frozen identity
    print("\n[4/5] Writing release_manifest.json...")
    release_manifest = {
        "schema": RELEASE_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "release_id": "",  # filled in after hash
        "built_at_utc": utc_now_iso(),
        "built_at_epoch": time.time(),
        "built_on_platform": platform.platform(),
        "built_on_python": sys.version,
        "source_commit_binding": source_binding,
        "owner_public_key": owner_pub,
        "owner_signature_algorithm": "ed25519",
        "e1_manifest_hash": e1_manifest["manifest_hash"],
        "e1_workspace_root_hash": e1_manifest["workspace_manifest"]["root_hash"],
        "e1_file_count": len(e1_manifest["workspace_manifest"]["files"]),
        "e1_total_size": e1_manifest["workspace_manifest"]["total_size"],
        "transport_capsule_sha256": transport_sha256,
        "transport_capsule_bytes": transport_tar.stat().st_size,
        "runner_sha256": runner_sha256,
        "runner_bytes": runner_path.stat().st_size,
        "verifier_sha256": source_binding["canonical_file_hashes"]["verifier"]["sha256"],
        "builder_sha256": source_binding["canonical_file_hashes"]["builder"]["sha256"],
        "orchestrator_sha256": source_binding["canonical_file_hashes"]["orchestrator"]["sha256"],
        "release_tool_sha256": source_binding["canonical_file_hashes"]["release_tool"]["sha256"],
        "worker_version": "multi_stage_analysis_pipeline/v1.1",
        "ruleset_version": "hdar-verifier-rules/v1.0",
        "dependency_lock_sha256": dep_evidence["requirements_lock_sha256"],
        "cryptography_version": dep_evidence["cryptography_version"],
        "wheel_hashes": wheel_evidence["wheel_hashes"],
        "claim": (
            "This release manifest freezes one canonical HDAR Epoch 1 capsule, "
            "owner keypair, embedded runner, verifier, and dependency lock. "
            "Multiple Host B providers can dispatch this identical bundle to "
            "prove they continued the SAME E1, not a rebuilt one."
        ),
        "claim_boundary": (
            "This manifest authenticates the release identity and Host A's E1 "
            "seal. It does NOT authenticate any Host B execution environment. "
            "Host B provenance requires GitHub artifact attestations or "
            "equivalent provider-backed attestation (see TRUST_BOUNDARY.md)."
        ),
    }
    # Compute release_id = SHA-256 of the manifest (excluding release_id itself)
    signing_content = {k: v for k, v in release_manifest.items() if k != "release_id"}
    release_manifest["release_id"] = sha256_bytes(canonical_json(signing_content))
    manifest_path = out_dir / "release_manifest.json"
    manifest_path.write_text(json.dumps(release_manifest, indent=2, sort_keys=True) + "\n")
    print(f"  Release ID: {release_manifest['release_id']}")

    # 5. Pack release_bundle.tar.gz — the immutable dispatch artifact
    print("\n[5/5] Packing release_bundle.tar.gz...")
    bundle_path = out_dir / "release_bundle.tar.gz"
    if bundle_path.exists():
        bundle_path.unlink()
    with tarfile.open(bundle_path, "w:gz") as tf:
        # release_manifest.json
        _add_file_to_tar(tf, manifest_path, "release_manifest.json")
        # host_a/ contents (E1 capsule, owner PUBLIC key, runner, transport tar, report)
        for fpath in sorted(host_a_dir.rglob("*")):
            if fpath.is_file() and "owner_private_key.txt" not in fpath.name:
                arcname = fpath.relative_to(out_dir).as_posix()
                _add_file_to_tar(tf, fpath, arcname)
        # dependency evidence
        _add_file_to_tar(tf, out_dir / "dependency_evidence.json", "dependency_evidence.json")
        _add_file_to_tar(tf, out_dir / "requirements.lock", "requirements.lock")
        # wheels (if captured)
        if wheel_dir.exists():
            for fpath in sorted(wheel_dir.glob("*")):
                if fpath.is_file():
                    _add_file_to_tar(tf, fpath, f"wheels/{fpath.name}")
    bundle_sha256 = sha256_file(bundle_path)
    bundle_bytes = bundle_path.stat().st_size
    print(f"  Bundle: {bundle_path.name} ({bundle_bytes} bytes)")
    print(f"  Bundle SHA-256: {bundle_sha256}")

    # Append bundle hash to manifest
    release_manifest["release_bundle_sha256"] = bundle_sha256
    release_manifest["release_bundle_bytes"] = bundle_bytes
    # Recompute release_id with bundle hash included
    signing_content = {k: v for k, v in release_manifest.items() if k != "release_id"}
    release_manifest["release_id"] = sha256_bytes(canonical_json(signing_content))
    manifest_path.write_text(json.dumps(release_manifest, indent=2, sort_keys=True) + "\n")

    print()
    print("=" * 70)
    print("RELEASE COMPLETE")
    print("=" * 70)
    print(f"  Release ID:           {release_manifest['release_id']}")
    print(f"  E1 manifest hash:     {release_manifest['e1_manifest_hash'][:16]}...")
    print(f"  Owner public key:     {release_manifest['owner_public_key'][:16]}...")
    print(f"  Runner SHA-256:       {release_manifest['runner_sha256'][:16]}...")
    print(f"  Verifier SHA-256:     {release_manifest['verifier_sha256'][:16]}...")
    print(f"  Transport capsule SHA:{release_manifest['transport_capsule_sha256'][:16]}...")
    print(f"  Dependency lock SHA:  {release_manifest['dependency_lock_sha256'][:16]}...")
    print(f"  Bundle SHA-256:       {bundle_sha256[:16]}...")
    print()
    print(f"  Dispatch to providers:")
    print(f"    python3 run_proof.py --reuse-release {bundle_path} --provider e2b")
    print(f"    python3 run_proof.py --reuse-release {bundle_path} --provider codespaces")
    print(f"    python3 run_proof.py --reuse-release {bundle_path} --provider colab")
    print()
    print(f"  Verify a bundle:")
    print(f"    python3 release.py verify {bundle_path}")
    return release_manifest


def _add_file_to_tar(tf: tarfile.TarFile, fpath: Path, arcname: str) -> None:
    """Add a file to a tar archive with deterministic metadata."""
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


# ---------------------------------------------------------------------------
# Release verify
# ---------------------------------------------------------------------------

def verify_release(bundle_path: Path) -> int:
    """Verify a release bundle is internally consistent.

    Checks:
      1. release_manifest.json present and parseable
      2. release_id matches recomputed hash
      3. E1 manifest hash matches the bundled capsule_epoch_1/manifest.json
      4. Owner public key in manifest matches bundled owner_public_key.txt
      5. Runner SHA-256 matches bundled host_a/run_host_b.py
      6. Transport capsule SHA-256 matches bundled tar.gz
      7. Dependency lock SHA-256 matches bundled requirements.lock
      8. E1 Ed25519 owner signature valid
      9. E1 manifest hash internally consistent
     10. E1 receipt hash valid
     11. E1 content blocks all present and valid
    """
    bundle_path = bundle_path.resolve()
    if not bundle_path.exists():
        print(f"FATAL: bundle not found: {bundle_path}", file=sys.stderr)
        return 1

    print("=" * 70)
    print("HDAR Canonical Release — Verify")
    print("=" * 70)
    print(f"  Bundle: {bundle_path}")
    print(f"  Bundle SHA-256: {sha256_file(bundle_path)}")
    print()

    # Extract to temp dir
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        with tarfile.open(bundle_path, "r:gz") as tf:
            safe_extract_tar(tf, tmp)

        manifest_path = tmp / "release_manifest.json"
        if not manifest_path.exists():
            print("FAIL: release_manifest.json not found in bundle", file=sys.stderr)
            return 1
        manifest = json.loads(manifest_path.read_text())

        checks = []
        def check(name: str, passed: bool, detail: str = ""):
            status = "PASS" if passed else "FAIL"
            line = f"  [{status}] {name}"
            if detail:
                line += f" — {detail}"
            print(line)
            checks.append({"check": name, "passed": passed, "detail": detail})

        # 1. release_manifest parseable — already done by loading it
        check("release_manifest.json parseable", True)

        # 2. release_id matches recomputed hash
        signing_content = {k: v for k, v in manifest.items() if k != "release_id"}
        recomputed_id = sha256_bytes(canonical_json(signing_content))
        check("release_id matches recomputed hash",
              recomputed_id == manifest["release_id"],
              f"expected={recomputed_id[:16]}... actual={manifest['release_id'][:16]}...")

        # 3. E1 manifest hash
        e1_manifest_path = tmp / "host_a" / "capsule_epoch_1" / "manifest.json"
        e1_manifest = json.loads(e1_manifest_path.read_text())
        check("E1 manifest hash matches release manifest",
              e1_manifest["manifest_hash"] == manifest["e1_manifest_hash"],
              f"e1={e1_manifest['manifest_hash'][:16]}... release={manifest['e1_manifest_hash'][:16]}...")

        # 4. Owner public key
        owner_pub_path = tmp / "host_a" / "owner_public_key.txt"
        owner_pub = owner_pub_path.read_text().strip()
        check("Owner public key matches release manifest",
              owner_pub == manifest["owner_public_key"],
              f"file={owner_pub[:16]}... manifest={manifest['owner_public_key'][:16]}...")

        # 5. Runner SHA-256
        runner_path = tmp / "host_a" / "run_host_b.py"
        runner_hash = sha256_file(runner_path)
        check("Runner SHA-256 matches release manifest",
              runner_hash == manifest["runner_sha256"],
              f"file={runner_hash[:16]}... manifest={manifest['runner_sha256'][:16]}...")

        # 6. Transport capsule SHA-256
        transport_path = tmp / "host_a" / "transport_capsule_epoch_1.tar.gz"
        transport_hash = sha256_file(transport_path)
        check("Transport capsule SHA-256 matches release manifest",
              transport_hash == manifest["transport_capsule_sha256"],
              f"file={transport_hash[:16]}... manifest={manifest['transport_capsule_sha256'][:16]}...")

        # 7. Dependency lock SHA-256
        lock_path = tmp / "requirements.lock"
        lock_content = lock_path.read_text().strip()
        lock_hash = sha256_bytes(lock_content.encode())
        check("Dependency lock SHA-256 matches release manifest",
              lock_hash == manifest["dependency_lock_sha256"],
              f"file={lock_hash[:16]}... manifest={manifest['dependency_lock_sha256'][:16]}...")

        # 8. E1 Ed25519 owner signature valid
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(owner_pub))
            sig_valid = True
            try:
                pub.verify(
                    bytes.fromhex(e1_manifest["owner_signature"]),
                    e1_manifest["manifest_hash"].encode(),
                )
            except Exception:
                sig_valid = False
            check("E1 Ed25519 owner signature valid", sig_valid)
        except ImportError:
            check("E1 Ed25519 owner signature valid", False, "cryptography not installed")

        # 9. E1 manifest hash internally consistent
        e1_signing = {k: v for k, v in e1_manifest.items() if k not in ("manifest_hash", "owner_signature")}
        e1_expected = sha256_bytes(canonical_json(e1_signing))
        check("E1 manifest hash internally consistent",
              e1_expected == e1_manifest["manifest_hash"])

        # 10. E1 receipt hash valid
        #     New evidence: receipt hash computed over subset excluding manifest_hash
        #     and receipt_hash (to avoid circular dependency with manifest binding).
        #     Old evidence: receipt hash computed over all fields except receipt_hash.
        #     Try both methods for backward compatibility (matches verify_all.py).
        e1_receipt = json.loads((tmp / "host_a" / "capsule_epoch_1" / "receipt.json").read_text())
        e1_r_expected_new = sha256_bytes(canonical_json(
            {k: v for k, v in e1_receipt.items() if k != "receipt_hash" and k != "manifest_hash"}
        ))
        e1_r_expected_old = sha256_bytes(canonical_json(
            {k: v for k, v in e1_receipt.items() if k != "receipt_hash"}
        ))
        check("E1 receipt hash valid",
              e1_r_expected_new == e1_receipt["receipt_hash"] or
              e1_r_expected_old == e1_receipt["receipt_hash"])

        # 11. E1 content blocks all present and valid
        blocks_dir = tmp / "host_a" / "capsule_epoch_1" / "blocks"
        missing = 0
        corrupt = 0
        for entry in e1_manifest["workspace_manifest"]["files"]:
            digest = entry["sha256"]
            blob = blocks_dir / digest[:2] / digest
            if not blob.exists():
                missing += 1
            elif sha256_file(blob) != digest:
                corrupt += 1
        check("E1 content blocks all valid",
              missing == 0 and corrupt == 0,
              f"missing={missing} corrupt={corrupt}" if missing or corrupt else "all blocks verified")

        # Summary
        passed = sum(1 for c in checks if c["passed"])
        failed = sum(1 for c in checks if not c["passed"])
        print()
        print(f"  Result: {passed}/{len(checks)} passed, {failed} failed")
        print(f"  Release ID: {manifest['release_id']}")
        print(f"  E1 manifest: {manifest['e1_manifest_hash'][:16]}...")
        print(f"  Verdict: {'RELEASE VALID' if failed == 0 else 'RELEASE INVALID'}")
        return 0 if failed == 0 else 1


# ---------------------------------------------------------------------------
# Release inspect
# ---------------------------------------------------------------------------

def inspect_release(bundle_path: Path) -> int:
    """Print the release manifest from a bundle."""
    bundle_path = bundle_path.resolve()
    if not bundle_path.exists():
        print(f"FATAL: bundle not found: {bundle_path}", file=sys.stderr)
        return 1

    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        with tarfile.open(bundle_path, "r:gz") as tf:
            safe_extract_tar(tf, tmp)
        manifest = json.loads((tmp / "release_manifest.json").read_text())

        print("=" * 70)
        print("HDAR Canonical Release — Inspect")
        print("=" * 70)
        print(f"  Release ID:            {manifest['release_id']}")
        print(f"  Protocol version:      {manifest['protocol_version']}")
        print(f"  Built at (UTC):        {manifest['built_at_utc']}")
        print(f"  Built on platform:     {manifest['built_on_platform']}")
        print()
        print("  Frozen identity:")
        print(f"    E1 manifest hash:     {manifest['e1_manifest_hash']}")
        print(f"    E1 workspace root:    {manifest['e1_workspace_root_hash']}")
        print(f"    Owner public key:     {manifest['owner_public_key']}")
        print(f"    Runner SHA-256:       {manifest['runner_sha256']}")
        print(f"    Verifier SHA-256:     {manifest['verifier_sha256']}")
        print(f"    Builder SHA-256:      {manifest['builder_sha256']}")
        print(f"    Orchestrator SHA-256: {manifest['orchestrator_sha256']}")
        print(f"    Transport capsule:    {manifest['transport_capsule_sha256']}")
        print(f"    Dependency lock SHA:  {manifest['dependency_lock_sha256']}")
        print(f"    Worker version:       {manifest['worker_version']}")
        print(f"    Ruleset version:      {manifest['ruleset_version']}")
        print()
        print("  Source commit binding:")
        sb = manifest["source_commit_binding"]
        print(f"    Repository:  {sb['repository']}")
        print(f"    Commit:      {sb['commit_sha']}")
        print(f"    Branch:      {sb['branch']}")
        print(f"    Dirty tree:  {sb['dirty_tree']}")
        print()
        print("  Dependencies:")
        print(f"    cryptography: {manifest['cryptography_version']}")
        print(f"    Wheel hashes: {len(manifest.get('wheel_hashes', {}))} captured")
        print()
        print("  Claim:")
        print(f"    {manifest['claim']}")
        print()
        print("  Claim boundary:")
        print(f"    {manifest['claim_boundary']}")
        return 0


# ---------------------------------------------------------------------------
# Release load (for run_proof.py --reuse-release)
# ---------------------------------------------------------------------------

def load_release(bundle_path: Path, extract_to: Path) -> dict:
    """Load a release bundle into a directory and return the manifest + paths.

    This is used by run_proof.py --reuse-release to dispatch the IDENTICAL
    bundle to a provider without rebuilding E1.
    """
    bundle_path = bundle_path.resolve()
    extract_to = extract_to.resolve()
    extract_to.mkdir(parents=True, exist_ok=True)

    with tarfile.open(bundle_path, "r:gz") as tf:
        safe_extract_tar(tf, extract_to)

    manifest = json.loads((extract_to / "release_manifest.json").read_text())
    host_a_dir = extract_to / "host_a"
    runner_path = host_a_dir / "run_host_b.py"
    owner_pub = (host_a_dir / "owner_public_key.txt").read_text().strip()
    e1_manifest = json.loads((host_a_dir / "capsule_epoch_1" / "manifest.json").read_text())

    # Verify bundle integrity against manifest
    runner_hash = sha256_file(runner_path)
    if runner_hash != manifest["runner_sha256"]:
        raise ValueError(
            f"Runner SHA-256 mismatch: file={runner_hash} manifest={manifest['runner_sha256']}"
        )
    transport_path = host_a_dir / "transport_capsule_epoch_1.tar.gz"
    transport_hash = sha256_file(transport_path)
    if transport_hash != manifest["transport_capsule_sha256"]:
        raise ValueError(
            f"Transport capsule SHA-256 mismatch: file={transport_hash} manifest={manifest['transport_capsule_sha256']}"
        )
    if e1_manifest["manifest_hash"] != manifest["e1_manifest_hash"]:
        raise ValueError(
            f"E1 manifest hash mismatch: file={e1_manifest['manifest_hash']} manifest={manifest['e1_manifest_hash']}"
        )

    return {
        "manifest": manifest,
        "host_a_dir": host_a_dir,
        "runner_path": runner_path,
        "owner_pub": owner_pub,
        "e1_manifest": e1_manifest,
        "runner_hash": runner_hash,
        "transport_path": transport_path,
        "release_id": manifest["release_id"],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="HDAR Canonical Release Bundle")
    sub = ap.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="Build a canonical release bundle")
    p_build.add_argument("--out", required=True, help="Output directory")

    p_verify = sub.add_parser("verify", help="Verify a release bundle")
    p_verify.add_argument("bundle", help="Path to release_bundle.tar.gz")

    p_inspect = sub.add_parser("inspect", help="Inspect a release manifest")
    p_inspect.add_argument("bundle", help="Path to release_bundle.tar.gz")

    args = ap.parse_args()

    if args.command == "build":
        build_release(Path(args.out))
        return 0
    elif args.command == "verify":
        return verify_release(Path(args.bundle))
    elif args.command == "inspect":
        return inspect_release(Path(args.bundle))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
