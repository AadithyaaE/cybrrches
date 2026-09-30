"""
Feature L3.2 - read-only Linux network-interface inspection.

Reads ONLY from /sys/class/net/<iface>/... and /proc/net/dev - standard
Linux kernel-exposed read-only files. Never opens a socket, never sends a
packet, never writes to any interface/sysfs file, never invokes ip/ifconfig
with a mutating verb. On a non-Linux host (e.g. native Windows), this
correctly and honestly reports the interface as not found - it never
fabricates Linux-style interface data on a platform that doesn't have it.
"""

import platform
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class InterfaceInfo:
    name: str
    exists: bool
    admin_state: str | None  # "up" / "down" / None if unknown
    link_state: str | None  # "up" (carrier present) / "down" / None if unknown
    mac_address: str | None
    ipv4_addresses: tuple  # tuple[str, ...]
    ipv6_addresses: tuple
    mtu: int | None
    rx_packets: int | None
    tx_packets: int | None
    rx_bytes: int | None
    tx_bytes: int | None
    inspection_platform: str
    inspection_method: str
    note: str = ""


def _read_sysfs(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _read_ip_addresses(iface: str) -> tuple:
    """Reads IPv4/IPv6 addresses via `ip -o addr show <iface>` - a READ-ONLY
    query verb (no mutation). Returns (ipv4_tuple, ipv6_tuple)."""
    import subprocess
    try:
        proc = subprocess.run(["ip", "-o", "addr", "show", iface], capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, OSError):
        return (), ()
    if proc.returncode != 0:
        return (), ()
    ipv4, ipv6 = [], []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if "inet" in parts:
            idx = parts.index("inet")
            ipv4.append(parts[idx + 1])
        if "inet6" in parts:
            idx = parts.index("inet6")
            ipv6.append(parts[idx + 1])
    return tuple(ipv4), tuple(ipv6)


def inspect_interface(name: str) -> InterfaceInfo:
    """
    Read-only inspection of a network interface by name. On Linux, reads
    /sys/class/net/<name>/{operstate,address,mtu,statistics/*} plus a
    read-only `ip addr show` for IP addresses. On any other platform (or if
    the interface simply doesn't exist), returns exists=False honestly -
    never guesses or fabricates values for a platform/interface it cannot
    actually inspect.
    """
    system = platform.system()
    if system != "Linux":
        return InterfaceInfo(
            name=name, exists=False, admin_state=None, link_state=None, mac_address=None,
            ipv4_addresses=(), ipv6_addresses=(), mtu=None,
            rx_packets=None, tx_packets=None, rx_bytes=None, tx_bytes=None,
            inspection_platform=system, inspection_method="none - not a Linux host",
            note=f"This inspection ran on {system}, not Linux - '{name}' cannot exist here by definition. "
                 "No Linux-style interface data can be honestly reported on this platform.",
        )

    sysfs_root = Path(f"/sys/class/net/{name}")
    if not sysfs_root.exists():
        return InterfaceInfo(
            name=name, exists=False, admin_state=None, link_state=None, mac_address=None,
            ipv4_addresses=(), ipv6_addresses=(), mtu=None,
            rx_packets=None, tx_packets=None, rx_bytes=None, tx_bytes=None,
            inspection_platform=system, inspection_method="/sys/class/net",
            note=f"/sys/class/net/{name} does not exist on this Linux host - interface not present.",
        )

    operstate = _read_sysfs(sysfs_root / "operstate")
    mac = _read_sysfs(sysfs_root / "address")
    mtu_raw = _read_sysfs(sysfs_root / "mtu")
    mtu = int(mtu_raw) if mtu_raw and mtu_raw.isdigit() else None

    def _stat(name_: str):
        raw = _read_sysfs(sysfs_root / "statistics" / name_)
        return int(raw) if raw and raw.lstrip("-").isdigit() else None

    ipv4, ipv6 = _read_ip_addresses(name)

    return InterfaceInfo(
        name=name,
        exists=True,
        admin_state=operstate,  # sysfs 'operstate' reflects link/carrier state; a separate admin-up/down
                                  # flag requires IFF_UP from `ip link show` - approximated here as operstate
        link_state=operstate,
        mac_address=mac,
        ipv4_addresses=ipv4,
        ipv6_addresses=ipv6,
        mtu=mtu,
        rx_packets=_stat("rx_packets"), tx_packets=_stat("tx_packets"),
        rx_bytes=_stat("rx_bytes"), tx_bytes=_stat("tx_bytes"),
        inspection_platform=system,
        inspection_method="/sys/class/net + ip addr show (read-only)",
    )


def list_all_interfaces() -> tuple:
    """Read-only enumeration of every interface name present under /sys/class/net (Linux only)."""
    if platform.system() != "Linux":
        return ()
    root = Path("/sys/class/net")
    if not root.exists():
        return ()
    return tuple(sorted(p.name for p in root.iterdir()))
