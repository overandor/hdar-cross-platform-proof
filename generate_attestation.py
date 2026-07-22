#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate CI attestation manifest for evidence directory")
    parser.add_argument("--evidence-dir", required=True, help="Directory containing evidence files")
    parser.add_argument("--out", required=True, help="Output attestation JSON path")
    parser.add_argument("--provider", default="", help="Provider name (e.g. e2b.dev, google-colab)")
    parser.add_argument("--browser", default="", help="Browser automation tool (e.g. burchi-wkwebview)")
    args = parser.parse_args()

    evidence_dir = Path(args.evidence_dir).resolve()
    if not evidence_dir.exists():
        print(f"FATAL: evidence directory not found: {evidence_dir}", file=sys.stderr)
        return 1

    attestation = {
        "schema": "hdar.ci-attestation/v1.0",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "github_run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "github_run_number": os.environ.get("GITHUB_RUN_NUMBER", ""),
        "github_sha": os.environ.get("GITHUB_SHA", ""),
        "github_ref": os.environ.get("GITHUB_REF", ""),
        "github_actor": os.environ.get("GITHUB_ACTOR", ""),
        "github_workflow": os.environ.get("GITHUB_WORKFLOW", ""),
        "github_job": os.environ.get("GITHUB_JOB", ""),
        "runner_os": platform.platform(),
        "runner_hostname": platform.node(),
        "provider": args.provider,
        "browser_automation": args.browser,
        "evidence_files": [],
    }

    for p in sorted(evidence_dir.rglob("*")):
        if p.is_file():
            data = p.read_bytes()
            rel = p.relative_to(evidence_dir).as_posix()
            attestation["evidence_files"].append({
                "relative_path": rel,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            })

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(attestation, indent=2) + "\n")
    print(f"Attestation: {len(attestation['evidence_files'])} files fingerprinted -> {out_path}")
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main())
