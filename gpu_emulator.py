#!/usr/bin/env python3
"""GPU Emulator — Extract GPU-like compute from CPU resources.

Provides a software GPU layer that:
1. Detects real GPU hardware (NVIDIA CUDA, Apple Metal, etc.)
2. If no GPU found, creates a virtual GPU device backed by CPU cores
3. Generates a CUDA-compatible device manifest for HDAR evidence
4. Exposes a parallel compute API that uses multiprocessing to emulate
   GPU-style SIMD parallelism on CPU

Integrates with run_host_b.py environment manifest to add GPU evidence
to the HDAR cross-platform proof.

Usage:
    from gpu_emulator import GPUEmulator
    gpu = GPUEmulator()
    info = gpu.detect()          # returns device manifest
    gpu.parallel_map(fn, data)   # GPU-style parallel execution on CPU
"""
from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import os
import platform
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

EMULATOR_VERSION = "gpu-emulator/1.0.0"
EMULATOR_SCHEMA = "hdar.gpu-emulator/v1.0"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _try_cmd(cmd: list[str]) -> str | None:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return None


def _detect_nvidia() -> dict | None:
    nvidia_smi = shutil.which("nvidia-smi")
    if not nvidia_smi:
        return None
    out = _try_cmd([nvidia_smi, "--query-gpu=name,uuid,memory.total,driver_version,compute_cap", "--format=csv,noheader"])
    if not out:
        return None
    parts = [p.strip() for p in out.split(",")]
    return {
        "vendor": "NVIDIA",
        "name": parts[0] if len(parts) > 0 else "Unknown",
        "uuid": parts[1] if len(parts) > 1 else "",
        "memory_total_mb": parts[2] if len(parts) > 2 else "",
        "driver_version": parts[3] if len(parts) > 3 else "",
        "compute_capability": parts[4] if len(parts) > 4 else "",
        "detection_method": "nvidia-smi",
    }


def _detect_apple_metal() -> dict | None:
    if platform.system() != "Darwin":
        return None
    out = _try_cmd(["system_profiler", "SPDisplaysDataType", "-json"])
    if not out:
        return None
    try:
        data = json.loads(out)
        gpus = data.get("SPDisplaysDataType", [])
        if gpus:
            gpu = gpus[0]
            return {
                "vendor": "Apple",
                "name": gpu.get("sppci_model", "Apple GPU"),
                "uuid": "",
                "memory_total_mb": gpu.get("sppci_vram", "").replace(" ", "") if isinstance(gpu.get("sppci_vram"), str) else "",
                "driver_version": "",
                "compute_capability": "Metal",
                "detection_method": "system_profiler",
            }
    except Exception:
        pass
    return None


def _detect_amd() -> dict | None:
    if platform.system() == "Linux":
        out = _try_cmd(["lspci", "-nn"])
        if out and "AMD" in out.upper() and "VGA" in out.upper():
            for line in out.splitlines():
                if "VGA" in line and "AMD" in line.upper():
                    return {
                        "vendor": "AMD",
                        "name": line.split(":")[-1].strip(),
                        "uuid": "",
                        "memory_total_mb": "",
                        "driver_version": "",
                        "compute_capability": "ROCm",
                        "detection_method": "lspci",
                    }
    return None


# ─── CPU-backed virtual GPU ─────────────────────────────────────────────────

def _cpu_gpu_device() -> dict:
    cpu_count = os.cpu_count() or 1
    mem_bytes = 0
    try:
        import resource
        mem_bytes = resource.RLIMIT_AS
    except Exception:
        pass

    # Try to get total system RAM as "VRAM"
    total_ram_mb = 0
    if platform.system() == "Darwin":
        mem_out = _try_cmd(["sysctl", "-n", "hw.memsize"])
        if mem_out:
            total_ram_mb = int(mem_out) // (1024 * 1024)
    elif platform.system() == "Linux":
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        total_ram_mb = int(line.split()[1]) // 1024
                        break
        except Exception:
            pass

    # Allocate a virtual VRAM slice (25% of system RAM, max 8GB)
    vram_mb = min(total_ram_mb // 4, 8192) if total_ram_mb else 4096

    device_id = str(uuid.uuid4())
    device_name = f"VirtualGPU-CPUx{cpu_count}"

    return {
        "vendor": "CPU-Emulated",
        "name": device_name,
        "uuid": device_id,
        "memory_total_mb": f"{vram_mb} MiB",
        "driver_version": EMULATOR_VERSION,
        "compute_capability": f"CPU-SIMD-{cpu_count}c",
        "detection_method": "software-emulation",
        "emulated": True,
        "cpu_cores": cpu_count,
        "system_ram_mb": total_ram_mb,
        "allocated_vram_mb": vram_mb,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "machine": platform.machine(),
    }


# ─── Parallel compute emulation ─────────────────────────────────────────────

def _worker_chunk(args: tuple) -> list:
    fn, chunk = args
    return [fn(item) for item in chunk]


def _square_add(x: int) -> int:
    return x * x + 1


class GPUEmulator:
    """Software GPU backed by CPU multiprocessing.

    Detects real GPU hardware first. If none found, creates a virtual
    GPU device and provides GPU-style parallel compute via CPU cores.
    """

    def __init__(self, force_emulation: bool = False):
        self.force_emulation = force_emulation
        self.device: dict | None = None
        self.is_emulated: bool = False
        self.detect()

    def detect(self) -> dict:
        """Detect GPU hardware or create virtual GPU from CPU."""
        if not self.force_emulation:
            for detector in (_detect_nvidia, _detect_apple_metal, _detect_amd):
                result = detector()
                if result:
                    result["emulated"] = False
                    result["detected_at_utc"] = _utc_now_iso()
                    self.device = result
                    self.is_emulated = False
                    return result

        # No real GPU — create virtual GPU from CPU
        device = _cpu_gpu_device()
        device["detected_at_utc"] = _utc_now_iso()
        device["emulator_version"] = EMULATOR_VERSION
        self.device = device
        self.is_emulated = True
        return device

    def parallel_map(self, fn: Callable, data: list, chunk_size: int | None = None) -> list:
        """GPU-style parallel map using CPU multiprocessing.

        Emulates GPU SIMD parallelism by distributing work across CPU cores.
        """
        if not data:
            return []

        cpu_count = os.cpu_count() or 1
        if chunk_size is None:
            chunk_size = max(1, len(data) // (cpu_count * 4))

        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

        if len(chunks) == 1 or cpu_count == 1:
            return [fn(item) for item in data]

        with mp.Pool(cpu_count) as pool:
            results = pool.map(_worker_chunk, [(fn, chunk) for chunk in chunks])

        # Flatten
        return [item for sublist in results for item in sublist]

    def parallel_starmap(self, fn: Callable, data: list[tuple], chunk_size: int | None = None) -> list:
        """GPU-style parallel starmap — unpacks tuples as args."""
        if not data:
            return []
        cpu_count = os.cpu_count() or 1
        if chunk_size is None:
            chunk_size = max(1, len(data) // (cpu_count * 4))
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

        def _star_worker(chunk):
            return [fn(*item) for item in chunk]

        if len(chunks) == 1 or cpu_count == 1:
            return [fn(*item) for item in data]

        with mp.Pool(cpu_count) as pool:
            results = pool.map(_star_worker, chunks)
        return [item for sublist in results for item in sublist]

    def benchmark(self, n: int = 1_000_000) -> dict:
        """Run a synthetic compute benchmark to measure emulated GPU throughput."""
        data = list(range(n))
        start = time.time()
        result = self.parallel_map(_square_add, data)
        elapsed = time.time() - start

        ops_per_sec = n / elapsed if elapsed > 0 else 0
        gflops = ops_per_sec / 1e9

        return {
            "benchmark": "vector_square_add",
            "elements": n,
            "elapsed_seconds": round(elapsed, 4),
            "ops_per_second": int(ops_per_sec),
            "gflops": round(gflops, 4),
            "cpu_cores": os.cpu_count(),
            "emulated": self.is_emulated,
            "device": self.device["name"] if self.device else "unknown",
            "timestamp_utc": _utc_now_iso(),
        }

    def manifest(self) -> dict:
        """Generate HDAR-compatible GPU evidence manifest."""
        if not self.device:
            self.detect()

        device_json = json.dumps(self.device, sort_keys=True, separators=(",", ":"))
        device_hash = _sha256(device_json)

        return {
            "schema": EMULATOR_SCHEMA,
            "emulator_version": EMULATOR_VERSION,
            "detected_at_utc": _utc_now_iso(),
            "is_emulated": self.is_emulated,
            "device": self.device,
            "device_hash": device_hash,
            "platform": platform.platform(),
            "python_version": sys.version,
            "hostname": platform.node(),
        }

    def nvidia_smi_emulated(self) -> str:
        """Generate fake nvidia-smi output for compatibility testing."""
        if not self.device:
            self.detect()
        d = self.device
        lines = [
            f"+-----------------------------------------------------------------------------+",
            f"| NVIDIA-SMI 550.00.00    Driver Version: {d.get('driver_version', EMULATOR_VERSION)}   CUDA Version: 12.4  |",
            f"|-------------------------------+----------------------+----------------------+",
            f"| GPU  Name        Persistence-M| Bus-Id        Disp.A | Volatile Uncorr. ECC|",
            f"| Fan  Temp  Perf  Pwr:Usage/Cap|         Memory-Usage | GPU-Util  Compute M.|",
            f"|                               |                      |               MIG M.|",
            f"|===============================+======================+======================|",
            f"|   0  {d.get('name', 'VirtualGPU'):<16}  N/A  00000000:00:00.0 Off  N/A               |",
            f"| N/A   N/A    P0    N/A /  N/A | {d.get('memory_total_mb', '4096 MiB'):>20} |      0%   Default  |",
            f"|                               |                      |                  N/A |",
            f"+-------------------------------+----------------------+----------------------+",
            f"",
            f"+-----------------------------------------------------------------------------+",
            f"| Processes:                                                                  |",
            f"|  GPU   GI   CI        PID   Type   Process name                  GPU Memory |",
            f"|        ID   ID                                                   Usage      |",
            f"|=============================================================================|",
            f"|  No running processes found                                                 |",
            f"+-----------------------------------------------------------------------------+",
        ]
        return "\n".join(lines)

    def summary(self) -> str:
        """Human-readable GPU summary."""
        if not self.device:
            self.detect()
        d = self.device
        tag = "EMULATED" if self.is_emulated else "HARDWARE"
        lines = [
            f"GPU Device [{tag}]",
            f"  Name:       {d.get('name', 'unknown')}",
            f"  Vendor:     {d.get('vendor', 'unknown')}",
            f"  Memory:     {d.get('memory_total_mb', 'unknown')}",
            f"  Compute:    {d.get('compute_capability', 'unknown')}",
            f"  Method:     {d.get('detection_method', 'unknown')}",
        ]
        if self.is_emulated:
            lines.append(f"  CPU Cores:  {d.get('cpu_cores', 'unknown')}")
            lines.append(f"  Sys RAM:    {d.get('system_ram_mb', 'unknown')} MB")
            lines.append(f"  VRAM Alloc: {d.get('allocated_vram_mb', 'unknown')} MB")
        return "\n".join(lines)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="GPU Emulator — extract GPU from CPU")
    ap.add_argument("--force-emulation", action="store_true", help="Force CPU emulation even if GPU present")
    ap.add_argument("--benchmark", type=int, default=0, help="Run benchmark with N elements")
    ap.add_argument("--manifest", action="store_true", help="Output HDAR GPU manifest JSON")
    ap.add_argument("--nvidia-smi", action="store_true", help="Output emulated nvidia-smi text")
    args = ap.parse_args()

    gpu = GPUEmulator(force_emulation=args.force_emulation)

    print(gpu.summary())
    print()

    if args.benchmark > 0:
        print(f"\nBenchmarking with {args.benchmark} elements...")
        bench = gpu.benchmark(args.benchmark)
        print(f"  Result: {json.dumps(bench, indent=2)}")

    if args.manifest:
        m = gpu.manifest()
        print(f"\nGPU Manifest:")
        print(json.dumps(m, indent=2, sort_keys=True))

    if args.nvidia_smi:
        print(f"\nEmulated nvidia-smi output:")
        print(gpu.nvidia_smi_emulated())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
