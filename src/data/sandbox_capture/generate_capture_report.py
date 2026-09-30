"""
Feature L3.2 - generates results/sandbox_capture/ inspection + capture
report artifacts. Read-only w.r.t. everything else in the repo. Performs
NO live network capture unless run_bounded_capture()'s own preconditions
are genuinely satisfied (they are not, in the environment this was
authored/run in - see the generated report for exactly why).
"""

import dataclasses
import json
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from data.sandbox_capture.interface_inspect import inspect_interface, list_all_interfaces  # noqa: E402
from data.sandbox_capture.permission_check import check_tcpdump_permission  # noqa: E402
from data.sandbox_capture.capture_config import CaptureConfig  # noqa: E402
from data.sandbox_capture.capture_adapter import run_bounded_capture  # noqa: E402

OUT_DIR = ROOT / "results/sandbox_capture"
TARGET_INTERFACE = "ens3"


def _asdict(obj):
    return dataclasses.asdict(obj) if dataclasses.is_dataclass(obj) else obj


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "feature": "L3.2 - Sandbox/Lab Traffic Capture",
        "inspection_platform": platform.system(),
        "inspection_platform_detail": platform.platform(),
        "target_interface": TARGET_INTERFACE,
        "all_interfaces_found": list(list_all_interfaces()),
        "target_interface_inspection": _asdict(inspect_interface(TARGET_INTERFACE)),
        "capture_permission": _asdict(check_tcpdump_permission()),
    }

    # Attempt the bounded capture against the target interface. Preconditions are checked
    # BEFORE any subprocess is launched - if either fails, no tcpdump process ever starts
    # and no file is ever created (verified separately in tests/test_sandbox_capture.py).
    output_path = OUT_DIR / f"attempted_capture_{TARGET_INTERFACE}.pcap"
    if output_path.exists():
        output_path.unlink()
    cfg = CaptureConfig(interface=TARGET_INTERFACE, output_path=output_path, max_packets=50, max_duration_s=10)
    result = run_bounded_capture(cfg)

    result_dict = dataclasses.asdict(result)
    result_dict["config"]["output_path"] = str(result_dict["config"]["output_path"])
    report["capture_attempt"] = result_dict
    report["capture_performed"] = bool(result.accepted and result.tcpdump_returncode == 0)
    report["passes_l3_1_raw_pcap_file_gate"] = None  # no PCAP was ever produced - N/A, not False

    (OUT_DIR / "capture_report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    # ---- human-readable summary ----
    lines = []
    lines.append("=" * 70)
    lines.append("FEATURE L3.2 - SANDBOX/LAB TRAFFIC CAPTURE - INSPECTION REPORT")
    lines.append("=" * 70)
    lines.append(f"\nInspection platform: {platform.platform()}")
    lines.append(f"All interfaces found: {list(list_all_interfaces()) or '(none - not a Linux host, or none present)'}")
    lines.append(f"\nTarget interface '{TARGET_INTERFACE}':")
    ii = inspect_interface(TARGET_INTERFACE)
    lines.append(f"  exists: {ii.exists}")
    lines.append(f"  admin/link state: {ii.admin_state} / {ii.link_state}")
    lines.append(f"  MAC: {ii.mac_address}")
    lines.append(f"  IPv4: {ii.ipv4_addresses}")
    lines.append(f"  IPv6: {ii.ipv6_addresses}")
    lines.append(f"  MTU: {ii.mtu}")
    lines.append(f"  rx/tx packets: {ii.rx_packets}/{ii.tx_packets}  rx/tx bytes: {ii.rx_bytes}/{ii.tx_bytes}")
    lines.append(f"  note: {ii.note}")
    perm = check_tcpdump_permission()
    lines.append(f"\nCapture mechanism: {perm.mechanism} (found={perm.mechanism_found}, path={perm.mechanism_path})")
    lines.append(f"  running_as_root: {perm.running_as_root}")
    lines.append(f"  capabilities: {perm.capabilities}")
    lines.append(f"  capture_likely_permitted: {perm.capture_likely_permitted}")
    lines.append(f"  reason: {perm.reason}")
    lines.append(f"\nCapture attempt accepted: {result.accepted}")
    lines.append(f"Errors: {list(result.errors)}")
    lines.append(f"Capture performed: {report['capture_performed']}")
    lines.append(f"Passes L3.1 RAW_PCAP_FILE gate: {report['passes_l3_1_raw_pcap_file_gate']} (N/A - no PCAP was produced)")
    (OUT_DIR / "capture_report.txt").write_text("\n".join(lines), encoding="utf-8")

    print(f"Wrote {OUT_DIR / 'capture_report.json'} and capture_report.txt")
    print(f"accepted={result.accepted} errors={result.errors}")


if __name__ == "__main__":
    main()
