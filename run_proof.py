#!/usr/bin/env python3
"""HDAR Canonical Proof — one-command end-to-end cross-platform continuation.

Executes the full HDAR protocol:
1. Host A: Seal Epoch 1 capsule with Ed25519 owner signature
2. Upload runner to E2B Linux sandbox
3. Host B: Restore E1, execute pipeline, seal Epoch 2
4. Download artifacts
5. Kill sandbox, generate termination receipt
6. Verifier: Run all checks on Host A after sandbox is destroyed

Prerequisites:
    pip install cryptography e2b
    export E2B_API_KEY  (use: read -s "E2B_API_KEY?E2B API key: "; export E2B_API_KEY)

Usage:
    python3 run_proof.py
    python3 run_proof.py --skip-e2b  (verify published evidence only)
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


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_environment_manifest() -> dict:
    """Capture Host A environment for evidence binding."""
    import subprocess as _sp

    def _pip_freeze() -> list[str]:
        try:
            r = _sp.run([sys.executable, "-m", "pip", "freeze"], capture_output=True, text=True, timeout=10)
            return r.stdout.strip().split("\n") if r.returncode == 0 else []
        except Exception:
            return []

    packages = _pip_freeze()
    package_hashes = {}
    for pkg in packages:
        if "==" in pkg:
            name, version = pkg.split("==", 1)
            package_hashes[name.strip().lower()] = version.strip()

    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "machine": platform.machine(),
        "os_uname": list(platform.uname()),
        "locale": os.environ.get("LANG", os.environ.get("LC_ALL", "")),
        "timezone": time.tzname[0] if time.tzname else "",
        "installed_packages": packages,
        "package_count": len(packages),
        "pinned_versions": {
            "cryptography": package_hashes.get("cryptography", ""),
            "e2b": package_hashes.get("e2b", ""),
        },
    }


def get_source_commit_binding() -> dict:
    """Bind proof to a specific Git commit and canonical file hashes."""
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

    canonical_files = {
        "builder": "host_a_seal.py",
        "runner_template": "run_host_b.py",
        "verifier_template": "verify_all.py",
        "orchestrator": "run_proof.py",
    }
    file_hashes = {}
    for label, fname in canonical_files.items():
        fpath = REPO_ROOT / fname
        file_hashes[label] = {
            "filename": fname,
            "sha256": sha256_file(fpath) if fpath.exists() else "",
        }

    return {
        "repository": remote_url,
        "commit_sha": commit_sha,
        "dirty_tree": bool(dirty),
        "dirty_files": dirty.split("\n") if dirty else [],
        "canonical_file_hashes": file_hashes,
    }


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
    """Extract tar archive with explicit safety checks.

    Rejects absolute paths, path traversal, symlinks, hardlinks, and
    non-regular files. Uses filter='data' on Python 3.12+.
    """
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


def phase_host_a(out_dir: Path) -> dict:
    """Phase 1: Host A seals Epoch 1."""
    print("=" * 60)
    print("PHASE 1: Host A — Seal Epoch 1")
    print("=" * 60)

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "host_a_seal.py"), "--out", str(out_dir)],
        cwd=str(REPO_ROOT),
    )
    if result.returncode != 0:
        print(f"FATAL: host_a_seal.py exited {result.returncode}", file=sys.stderr)
        sys.exit(1)

    report = json.loads((out_dir / "host_a_report.json").read_text())
    owner_pub = (out_dir / "owner_public_key.txt").read_text().strip()
    e1_manifest = json.loads((out_dir / "capsule_epoch_1" / "manifest.json").read_text())

    runner_path = out_dir / "run_host_b.py"
    if not runner_path.exists():
        print(f"FATAL: run_host_b.py not generated in {out_dir}", file=sys.stderr)
        sys.exit(1)

    runner_hash = sha256_file(runner_path)
    print(f"\n  E1 manifest hash: {e1_manifest['manifest_hash']}")
    print(f"  Owner public key: {owner_pub[:16]}...")
    print(f"  Runner SHA-256:   {runner_hash}")
    print(f"  Host A platform:  {report['host_a_platform']}")

    return {
        "host_a_dir": out_dir,
        "host_a_report": report,
        "owner_pub": owner_pub,
        "e1_manifest": e1_manifest,
        "runner_path": runner_path,
        "runner_hash": runner_hash,
        "release_id": None,  # not a release-based run
    }


def phase_host_a_reuse_release(release_bundle: Path, extract_dir: Path) -> dict:
    """Phase 1 (alternative): Load a canonical release bundle instead of sealing a new E1.

    This is the key mechanism for multi-provider proof: every provider dispatches
    the IDENTICAL bundle, so every Host B run begins from the same E1 manifest,
    owner key, runner hash, and verifier hash. Different E1 hashes would mean
    different experiments.
    """
    print("=" * 60)
    print("PHASE 1: Load Canonical Release Bundle (no new E1 seal)")
    print("=" * 60)
    print(f"  Bundle: {release_bundle}")

    # Import here to avoid circular import at module load time
    sys.path.insert(0, str(REPO_ROOT))
    from release import load_release

    release = load_release(release_bundle, extract_dir)
    manifest = release["manifest"]
    host_a_dir = release["host_a_dir"]

    # Build a host_a_report compatible with downstream phases
    report = json.loads((host_a_dir / "host_a_report.json").read_text())
    # Augment with release identity for evidence binding
    report["release_id"] = manifest["release_id"]
    report["release_bundle_sha256"] = manifest.get("release_bundle_sha256", "")
    report["release_runner_sha256"] = manifest["runner_sha256"]
    report["release_verifier_sha256"] = manifest["verifier_sha256"]
    report["release_dependency_lock_sha256"] = manifest["dependency_lock_sha256"]
    (host_a_dir / "host_a_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )

    print(f"\n  Release ID:       {manifest['release_id']}")
    print(f"  E1 manifest hash: {manifest['e1_manifest_hash']}")
    print(f"  Owner public key: {manifest['owner_public_key'][:16]}...")
    print(f"  Runner SHA-256:   {manifest['runner_sha256'][:16]}...")
    print(f"  Verifier SHA-256: {manifest['verifier_sha256'][:16]}...")
    print(f"  Worker version:   {manifest['worker_version']}")
    print(f"  Host A platform:  {report['host_a_platform']}")
    print()
    print("  This run dispatches the IDENTICAL canonical E1 to a new provider.")
    print("  Different E1 hashes would mean different experiments.")

    return {
        "host_a_dir": host_a_dir,
        "host_a_report": report,
        "owner_pub": release["owner_pub"],
        "e1_manifest": release["e1_manifest"],
        "runner_path": release["runner_path"],
        "runner_hash": release["runner_hash"],
        "release_id": manifest["release_id"],
        "release_manifest": manifest,
    }


def phase_host_b_e2b(host_a: dict, out_dir: Path, host_label: str) -> dict:
    """Phase 2: Run Host B on E2B Linux sandbox."""
    print("\n" + "=" * 60)
    print("PHASE 2: Host B — E2B Linux Sandbox")
    print("=" * 60)

    try:
        from e2b import Sandbox
    except ImportError:
        print("E2B package not installed. Install: pip install e2b", file=sys.stderr)
        sys.exit(1)

    print("\n[1/6] Starting E2B sandbox...")
    sandbox = Sandbox()
    sandbox_id = sandbox.sandbox_id
    print(f"  Sandbox ID: {sandbox_id}")

    sandbox_start_utc = utc_now_iso()

    try:
        # Upload runner
        print("\n[2/6] Uploading runner to sandbox...")
        sandbox.files.write("/home/user/run_host_b.py", host_a["runner_path"].read_text())
        print(f"  Uploaded: {host_a['runner_path'].stat().st_size} bytes")

        # Install cryptography
        print("\n[3/6] Installing cryptography in sandbox...")
        result = sandbox.commands.run("pip install cryptography -q", timeout=60)
        print(f"  pip install: exit={result.exit_code}")

        # Check platform
        result = sandbox.commands.run("python3 -c 'import platform; print(platform.platform())'")
        sandbox_platform = result.stdout.strip()
        print(f"  Sandbox platform: {sandbox_platform}")

        # Run Host B
        print("\n[4/6] Running Host B in sandbox...")
        result = sandbox.commands.run(
            f"cd /home/user && python3 run_host_b.py --out /home/user/host_b_output --host-label {host_label} --operator e2b-sandbox",
            timeout=120,
        )
        print(f"  Exit code: {result.exit_code}")
        if result.stdout:
            print(f"  stdout (last 300 chars): ...{result.stdout[-300:]}")
        if result.stderr:
            print(f"  stderr: {result.stderr[-300:]}")

        if result.exit_code != 0:
            print("FATAL: Host B failed in sandbox", file=sys.stderr)
            sys.exit(1)

        # Download artifacts
        print("\n[5/6] Downloading artifacts from sandbox...")
        out_dir.mkdir(parents=True, exist_ok=True)

        report_content = sandbox.files.read("/home/user/host_b_output/host_b_report.json")
        report_path = out_dir / "host_b_report.json"
        report_path.write_text(report_content)
        print(f"  Downloaded: {report_path}")

        e2_dir = out_dir / "capsule_epoch_2"
        e2_dir.mkdir(parents=True, exist_ok=True)

        def download_dir(remote_path: str, local_path: Path):
            entries = sandbox.files.list(remote_path)
            for entry in entries:
                remote_full = f"{remote_path}/{entry.name}"
                local_full = local_path / entry.name
                if entry.is_dir:
                    local_full.mkdir(parents=True, exist_ok=True)
                    download_dir(remote_full, local_full)
                else:
                    content = sandbox.files.read(remote_full)
                    local_full.write_bytes(content if isinstance(content, bytes) else content.encode())
                    print(f"  Downloaded: {local_full}")

        download_dir("/home/user/host_b_output/capsule_epoch_2", e2_dir)

    finally:
        # Phase 3: Kill sandbox and generate termination receipt
        print("\n[6/6] Terminating sandbox...")
        termination_requested_utc = utc_now_iso()
        sandbox.kill()
        print(f"  Sandbox {sandbox_id} terminated.")

        termination_confirmed = True
        try:
            _ = sandbox.commands.run("echo alive", timeout=5)
            termination_confirmed = False
        except Exception:
            pass

        termination_receipt = {
            "schema": "hdar.sandbox-termination-receipt/v1.0",
            "sandbox_id": sandbox_id,
            "termination_requested": True,
            "termination_confirmed": termination_confirmed,
            "confirmed_state": "killed",
            "termination_requested_utc": termination_requested_utc,
            "termination_confirmed_utc": utc_now_iso(),
            "verification_method": "post-kill command execution attempt (exception = confirmed dead)",
            "operator_reported_termination": True,
            "provider_attested_termination": False,
            "provider_attestation_note": "E2B API does not expose a signed termination attestation; operator reports kill() call and post-kill confirmation",
            "lifecycle_request_hash": sha256_bytes(f"{sandbox_id}:{termination_requested_utc}".encode()),
        }
        termination_receipt["receipt_hash"] = sha256_bytes(
            canonical_json({k: v for k, v in termination_receipt.items() if k != "receipt_hash"})
        )
        receipt_path = out_dir / "sandbox_termination_receipt.json"
        receipt_path.write_text(json.dumps(termination_receipt, indent=2, sort_keys=True) + "\n")
        print(f"  Termination receipt: {receipt_path}")
        print(f"  Confirmed dead: {termination_confirmed}")

    host_b_report = json.loads(report_path.read_text())
    print(f"\n  Host B platform: {host_b_report['host_b_platform']}")
    print(f"  Platform separation: {host_b_report['platforms_differ']}")
    print(f"  Pipeline output hash: {host_b_report['pipeline_result']['output_hash']}")

    return {
        "host_b_dir": out_dir,
        "host_b_report": host_b_report,
        "e2_dir": e2_dir,
        "termination_receipt": termination_receipt,
    }


def phase_verify(host_a: dict, host_b: dict) -> dict:
    """Phase 3: Run verifier after sandbox is destroyed."""
    print("\n" + "=" * 60)
    print("PHASE 3: Verifier — Post-shutdown verification on Host A")
    print("=" * 60)

    cmd = [
        sys.executable,
        str(REPO_ROOT / "verify_all.py"),
        "--host-a-dir", str(host_a["host_a_dir"]),
        "--host-b-report", str(host_b["host_b_dir"] / "host_b_report.json"),
        "--e2-capsule", str(host_b["e2_dir"]),
        "--out", str(host_b["host_b_dir"] / "verifier_report.json"),
    ]
    result = subprocess.run(cmd, cwd=str(REPO_ROOT))
    return {"verifier_exit_code": result.returncode}


def phase_verify_published() -> dict:
    """Verify published evidence (no E2B needed)."""
    print("=" * 60)
    print("VERIFIER — Checking published evidence")
    print("=" * 60)
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "prove.py")],
        cwd=str(REPO_ROOT),
    )
    return {"verifier_exit_code": result.returncode}


def main() -> int:
    ap = argparse.ArgumentParser(description="HDAR Canonical Proof — end-to-end cross-platform continuation")
    ap.add_argument("--out", default="/tmp/hdar_proof_run", help="Output directory")
    ap.add_argument("--skip-e2b", action="store_true", help="Skip E2B, verify published evidence only")
    ap.add_argument("--host-label", default="e2b-linux-sandbox", help="Host B label")
    ap.add_argument(
        "--reuse-release",
        default="",
        help=(
            "Path to a canonical release_bundle.tar.gz produced by `release.py build`. "
            "When set, the orchestrator dispatches the IDENTICAL E1 to a new provider "
            "instead of sealing a fresh E1. This is the mechanism for multi-provider "
            "proof: every provider runs the same E1, owner key, runner hash, and "
            "verifier hash."
        ),
    )
    ap.add_argument(
        "--provider",
        default="e2b",
        help="Provider label for this Host B run (e2b, codespaces, colab, chatgpt-linux, external)",
    )
    args = ap.parse_args()

    out_dir = Path(args.out).resolve()

    if args.skip_e2b:
        result = phase_verify_published()
        return result["verifier_exit_code"]

    # Full end-to-end
    start_utc = utc_now_iso()
    env_manifest = get_environment_manifest()
    source_binding = get_source_commit_binding()
    print(f"HDAR Canonical Proof — started {start_utc}")
    print(f"Host A platform: {platform.platform()}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Git commit: {source_binding['commit_sha'][:16]}...")
    print(f"Dirty tree: {source_binding['dirty_tree']}")
    if args.reuse_release:
        print(f"Mode: REUSE RELEASE — dispatching identical E1 to provider '{args.provider}'")
    else:
        print(f"Mode: FRESH SEAL — building a new E1 (single-provider run)")
    print()

    # Write environment manifest and source binding
    (out_dir / "environment_manifest.json").write_text(
        json.dumps(env_manifest, indent=2, sort_keys=True) + "\n"
    )
    (out_dir / "source_commit_binding.json").write_text(
        json.dumps(source_binding, indent=2, sort_keys=True) + "\n"
    )

    # Phase 1: Host A — either seal fresh or load canonical release
    if args.reuse_release:
        host_a = phase_host_a_reuse_release(
            Path(args.reuse_release).resolve(),
            out_dir / "release_extracted",
        )
        host_label = args.provider or "reuse-release"
    else:
        host_a = phase_host_a(out_dir / "host_a")
        host_label = args.host_label

    # Phase 2: Host B on E2B
    host_b = phase_host_b_e2b(host_a, out_dir / "host_b", host_label)

    # Phase 3: Verify after sandbox destroyed
    verify = phase_verify(host_a, host_b)

    # Summary
    end_utc = utc_now_iso()
    print("\n" + "=" * 60)
    print("PROOF SUMMARY")
    print("=" * 60)
    print(f"  Started:  {start_utc}")
    print(f"  Finished: {end_utc}")
    print(f"  Host A:   {host_a['host_a_report']['host_a_platform']}")
    print(f"  Host B:   {host_b['host_b_report']['host_b_platform']}")
    print(f"  Separation: {host_b['host_b_report']['platforms_differ']}")
    print(f"  E1 hash:  {host_a['e1_manifest']['manifest_hash'][:16]}...")
    print(f"  E2 hash:  {host_b['host_b_report']['capsule_e2']['manifest_hash'][:16]}...")
    print(f"  Pipeline: {host_b['host_b_report']['pipeline_result']['output_hash'][:16]}...")
    print(f"  Sandbox killed: {host_b['termination_receipt']['termination_confirmed']}")
    print(f"  Operator reported: {host_b['termination_receipt']['operator_reported_termination']}")
    print(f"  Provider attested: {host_b['termination_receipt']['provider_attested_termination']}")
    print(f"  Verifier: {'ALL PASS' if verify['verifier_exit_code'] == 0 else 'FAILURES'}")
    print(f"  Git commit: {source_binding['commit_sha'][:16]}...")
    print(f"  Dirty tree: {source_binding['dirty_tree']}")
    if host_a.get("release_id"):
        print(f"  Release ID: {host_a['release_id']}")
        print(f"  Mode: REUSE RELEASE (identical E1 dispatched to provider '{args.provider}')")
    else:
        print(f"  Mode: FRESH SEAL (single-provider run)")
    print()

    return verify["verifier_exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
