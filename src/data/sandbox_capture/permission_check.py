"""
Feature L3.2 - read-only capture-permission check.

Determines whether the current process/user plausibly has permission to
run a packet capture on a given interface, WITHOUT attempting an actual
capture and without changing any capability, ownership, or permission
bit. All checks are read-only.
"""

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class PermissionStatus:
    mechanism: str
    mechanism_found: bool
    mechanism_path: str | None
    running_as_root: bool | None
    capabilities: str | None  # raw `getcap` output, or None if not checked/available
    capture_likely_permitted: bool
    reason: str


def check_tcpdump_permission() -> PermissionStatus:
    """
    Read-only permission probe for the 'tcpdump' mechanism:
      1. Is tcpdump even installed (`shutil.which`)?
      2. Is the current process running as root (os.geteuid() == 0)?
      3. Does the tcpdump binary have CAP_NET_RAW/CAP_NET_ADMIN set (`getcap`,
         a read-only query)?
    Never attempts sudo, never sets a capability, never runs tcpdump itself.
    """
    path = shutil.which("tcpdump")
    if path is None:
        return PermissionStatus(
            mechanism="tcpdump", mechanism_found=False, mechanism_path=None,
            running_as_root=None, capabilities=None, capture_likely_permitted=False,
            reason="tcpdump is not installed/on PATH - cannot capture with this mechanism.",
        )

    running_as_root = None
    if platform.system() == "Linux" and hasattr(os, "geteuid"):
        running_as_root = os.geteuid() == 0

    capabilities = None
    if platform.system() == "Linux" and shutil.which("getcap"):
        try:
            proc = subprocess.run(["getcap", path], capture_output=True, text=True, timeout=5)
            capabilities = proc.stdout.strip() or "(no capabilities set)"
        except (OSError, subprocess.SubprocessError):
            capabilities = None

    has_raw_cap = bool(capabilities and "cap_net_raw" in capabilities.lower())
    capture_likely_permitted = bool(running_as_root) or has_raw_cap

    if running_as_root:
        reason = "Running as root (euid 0) - tcpdump capture permitted."
    elif has_raw_cap:
        reason = f"tcpdump binary has CAP_NET_RAW set ({capabilities}) - capture permitted without root."
    elif running_as_root is False:
        reason = (
            "Not running as root and tcpdump has no CAP_NET_RAW capability set - capture would require "
            "sudo (interactive password) or a capability change, neither of which this read-only check "
            "performs or recommends performing automatically."
        )
    else:
        reason = "Permission could not be determined on this platform (not Linux, or euid unavailable)."

    return PermissionStatus(
        mechanism="tcpdump", mechanism_found=True, mechanism_path=path,
        running_as_root=running_as_root, capabilities=capabilities,
        capture_likely_permitted=capture_likely_permitted, reason=reason,
    )
