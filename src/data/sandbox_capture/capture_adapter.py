"""
Feature L3.2 - bounded, read-only Sandbox/lab packet-capture adapter.

Mechanism: shells out to `tcpdump` (a mature, widely-audited capture tool)
with `-w <path>` so tcpdump itself writes packets straight to disk as they
arrive - this process's own memory NEVER holds the packet stream, which is
how "do not buffer an entire capture in memory" is satisfied structurally,
not just by convention.

This module NEVER:
  - sends, injects, or modifies a packet (no scapy .send()/.sendp(), no
    tcpdump -w replaced with anything that writes to the wire)
  - changes firewall rules, routes, IP addresses, or interface state (no
    `ip addr add/del`, `ip link set`, `iptables`, `nft`, `route`, `sysctl`
    invocation anywhere in this file)
  - makes an outbound network connection itself (tcpdump is a local
    subprocess reading a local NIC; this Python code opens no socket)
  - retries with escalated privileges (no `sudo` invocation anywhere)
  - proceeds past a failed interface/permission check "just to see" - a
    failed precondition is a hard stop, always
"""

import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .capture_config import CaptureConfig
from .interface_inspect import InterfaceInfo, inspect_interface
from .permission_check import PermissionStatus, check_tcpdump_permission


@dataclass(frozen=True)
class ProgressSnapshot:
    elapsed_s: float
    file_size_bytes: int


@dataclass(frozen=True)
class CaptureResult:
    accepted: bool  # False means capture was rejected before ever starting tcpdump
    config: CaptureConfig
    interface_info: InterfaceInfo
    permission_status: PermissionStatus
    start_time_utc: str | None
    end_time_utc: str | None
    output_path: str
    file_size_bytes: int
    progress: tuple  # tuple[ProgressSnapshot, ...]
    tcpdump_returncode: int | None
    tcpdump_stderr: str
    errors: tuple  # tuple[str, ...]
    provenance: str = "OBSERVED_LAB_TRAFFIC (raw capture, no computation applied) - see docs/sandbox_input_contract/SANDBOX_INPUT_CONTRACT.md DataProvenance"


def run_bounded_capture(config: CaptureConfig, poll_interval_s: float = 0.5) -> CaptureResult:
    """
    Orchestrates a bounded, read-only tcpdump capture on config.interface.

    Preconditions checked, in order, BEFORE any subprocess is launched:
      1. Interface must exist and be administratively/link up.
      2. Capture permission must be plausible (root euid or CAP_NET_RAW).
    Either failing means accepted=False and NO tcpdump process is ever
    started - this is the "fail clearly if permissions/interface are
    unavailable" requirement, satisfied by construction.
    """
    errors = []

    iface_info = inspect_interface(config.interface)
    if not iface_info.exists:
        errors.append(f"Interface '{config.interface}' does not exist: {iface_info.note}")
    elif iface_info.link_state not in ("up",):
        errors.append(f"Interface '{config.interface}' is not link-up (link_state={iface_info.link_state!r}).")

    perm_status = check_tcpdump_permission()
    if not perm_status.capture_likely_permitted:
        errors.append(f"Capture permission unavailable: {perm_status.reason}")

    if errors:
        return CaptureResult(
            accepted=False, config=config, interface_info=iface_info, permission_status=perm_status,
            start_time_utc=None, end_time_utc=None, output_path=str(config.output_path),
            file_size_bytes=0, progress=(), tcpdump_returncode=None, tcpdump_stderr="",
            errors=tuple(errors),
        )

    # ---- preconditions satisfied: launch the bounded, read-only capture ----
    cmd = ["tcpdump", "-i", config.interface, "-w", str(config.output_path), "-U"]  # -U: flush to disk per packet
    if config.max_packets is not None:
        cmd += ["-c", str(config.max_packets)]

    start = time.time()
    start_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start))
    proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True)

    progress = []
    try:
        while True:
            elapsed = time.time() - start
            size = Path(config.output_path).stat().st_size if Path(config.output_path).exists() else 0
            progress.append(ProgressSnapshot(elapsed_s=round(elapsed, 2), file_size_bytes=size))

            if proc.poll() is not None:
                break  # tcpdump exited on its own (e.g. hit -c packet count)
            if config.max_duration_s is not None and elapsed >= config.max_duration_s:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
            if config.max_file_size_bytes is not None and size >= config.max_file_size_bytes:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
            time.sleep(poll_interval_s)
    finally:
        stderr_output = ""
        try:
            _, stderr_output = proc.communicate(timeout=5)
        except Exception:
            pass

    end = time.time()
    end_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end))
    final_size = Path(config.output_path).stat().st_size if Path(config.output_path).exists() else 0

    return CaptureResult(
        accepted=True, config=config, interface_info=iface_info, permission_status=perm_status,
        start_time_utc=start_iso, end_time_utc=end_iso, output_path=str(config.output_path),
        file_size_bytes=final_size, progress=tuple(progress),
        tcpdump_returncode=proc.returncode, tcpdump_stderr=stderr_output or "", errors=(),
    )
