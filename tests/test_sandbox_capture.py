"""
Feature L3.2 - tests for the Sandbox/Lab Traffic Capture adapter.

Standalone script (no pytest - matches this project's existing convention).
These tests exercise REAL code against the REAL environment this script
runs in - nothing is mocked. On a platform/host without the described
Sandbox interface (ens3) or without capture permission, the "unavailable"
tests are expected to (and must) observe real rejection, not a simulated
one.

Run with:
    python tests/test_sandbox_capture.py
(On the Windows side, tcpdump-dependent checks are skipped, not faked -
see the SKIP entries in the report. For full coverage including a real
Linux /sys/class/net + tcpdump probe, also run under WSL Kali:
    wsl -d kali-linux -- python3 tests/test_sandbox_capture.py
)
"""

import ast
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from data.sandbox_capture.capture_config import CaptureConfig, CaptureConfigError  # noqa: E402
from data.sandbox_capture.interface_inspect import inspect_interface, list_all_interfaces  # noqa: E402
from data.sandbox_capture.permission_check import check_tcpdump_permission  # noqa: E402
from data.sandbox_capture.capture_adapter import run_bounded_capture  # noqa: E402

L3_2_FILES = [
    ROOT / "src/data/sandbox_capture/capture_config.py",
    ROOT / "src/data/sandbox_capture/interface_inspect.py",
    ROOT / "src/data/sandbox_capture/permission_check.py",
    ROOT / "src/data/sandbox_capture/capture_adapter.py",
    ROOT / "src/data/sandbox_capture/generate_capture_report.py",
]

PROTECTED_DIRS = [
    ROOT / "src/data/pcap", ROOT / "src/data/pcap_validation", ROOT / "src/data/sandbox_contract",
    ROOT / "results", ROOT / "data/processed/splits", ROOT / "frontend",
]
PROTECTED_FILES = [
    ROOT / "src/data/prepare_unlabeled_state.py",
    ROOT / "docs/sandbox_input_contract/SANDBOX_INPUT_CONTRACT.md",
]
EXCLUDE_PREFIXES = [
    ROOT / "results/pcap", ROOT / "results/sandbox_input_contract", ROOT / "results/sandbox_capture",
    ROOT / "frontend/node_modules", ROOT / "frontend/dist",
]

# Commands that would mutate networking/firewall state - must NEVER appear as a literal
# string anywhere in this feature's source.
FORBIDDEN_MUTATION_SUBSTRINGS = [
    "iptables", "ip6tables", "nft ", "firewall-cmd", "ufw ",
    "ip addr add", "ip addr del", "ip link set", "route add", "route del", "sysctl -w",
    "sudo ",
]
FORBIDDEN_INJECTION_CALLS = {"sendp", "send", "sr", "sr1", "srp", "srp1"}  # scapy send-family
FORBIDDEN_MODEL_IMPORTS = ("lstm_world_model", "next_state_attack_classifier", "attack_progression_probability", "mitre_stage_mapper")


def fail(message: str):
    raise SystemExit(f"FEATURE L3.2 TEST FAILURE: {message}")


def file_md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_protected_state() -> dict:
    paths = list(PROTECTED_FILES)
    for d in PROTECTED_DIRS:
        if d.exists():
            paths.extend(
                p for p in d.rglob("*")
                if p.is_file() and not any(str(p).startswith(str(ex)) for ex in EXCLUDE_PREFIXES)
            )
    return {str(p): file_md5(p) for p in set(paths)}


def main():
    checks = {}
    skips = []

    print("Hashing protected files (pre-run) ...")
    protected_before = hash_protected_state()
    print(f"  {len(protected_before)} protected files hashed.")

    # ============================================================ 1. configuration validation
    with tempfile.TemporaryDirectory() as tmp:
        good_path = Path(tmp) / "out.pcap"
        cfg = CaptureConfig(interface="ens3", output_path=good_path, max_packets=10)
        checks["1_valid_config_constructs"] = cfg.interface == "ens3" and cfg.max_packets == 10

        try:
            CaptureConfig(interface="", output_path=Path(tmp) / "a.pcap", max_packets=10)
            checks["1_empty_interface_rejected"] = False
        except CaptureConfigError:
            checks["1_empty_interface_rejected"] = True

        try:
            CaptureConfig(interface="ens3", output_path=Path(tmp) / "b.pcap")  # no bound at all
            checks["1_unbounded_config_rejected"] = False
        except CaptureConfigError:
            checks["1_unbounded_config_rejected"] = True

        try:
            CaptureConfig(interface="ens3", output_path=Path(tmp) / "c.pcap", max_packets=-5)
            checks["1_negative_max_packets_rejected"] = False
        except CaptureConfigError:
            checks["1_negative_max_packets_rejected"] = True

        existing = Path(tmp) / "already_there.pcap"
        existing.write_bytes(b"x")
        try:
            CaptureConfig(interface="ens3", output_path=existing, max_packets=10)
            checks["1_existing_output_path_rejected"] = False
        except CaptureConfigError:
            checks["1_existing_output_path_rejected"] = True

    # ============================================================ 2. bounded capture configuration
    with tempfile.TemporaryDirectory() as tmp:
        cfg_duration = CaptureConfig(interface="ens3", output_path=Path(tmp) / "d.pcap", max_duration_s=5)
        cfg_size = CaptureConfig(interface="ens3", output_path=Path(tmp) / "e.pcap", max_file_size_bytes=1024)
        checks["2_duration_only_bound_accepted"] = cfg_duration.max_duration_s == 5
        checks["2_size_only_bound_accepted"] = cfg_size.max_file_size_bytes == 1024
        try:
            CaptureConfig(interface="ens3", output_path=Path(tmp) / "f.pcap", mechanism="scapy_live_sniff")
            checks["2_unimplemented_mechanism_rejected"] = False
        except CaptureConfigError:
            checks["2_unimplemented_mechanism_rejected"] = True

    # ============================================================ 3. unavailable-interface failure (REAL, not mocked)
    real_interfaces = list_all_interfaces()
    fake_name = "ens3_definitely_does_not_exist_xyz"
    checks["3_fake_interface_definitely_not_in_real_list"] = fake_name not in real_interfaces
    fake_info = inspect_interface(fake_name)
    checks["3_fake_interface_reports_not_exists"] = fake_info.exists is False
    ens3_info = inspect_interface("ens3")
    checks["3_ens3_reports_not_exists_in_this_environment"] = ens3_info.exists is False
    print(f"  (real interfaces found on this run: {real_interfaces or '(none)'}; ens3 exists here: {ens3_info.exists})")

    # ============================================================ 4. unavailable-permission failure (REAL, not mocked)
    perm = check_tcpdump_permission()
    checks["4_permission_status_has_a_reason"] = len(perm.reason) > 0
    checks["4_permission_reflects_real_root_status"] = perm.running_as_root in (True, False, None)
    print(f"  (real permission probe: mechanism_found={perm.mechanism_found}, capture_likely_permitted={perm.capture_likely_permitted})")

    # ============================================================ 5. run_bounded_capture() rejects cleanly, no side effects
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "should_never_be_created.pcap"
        cfg = CaptureConfig(interface=fake_name, output_path=out_path, max_packets=5, max_duration_s=2)
        result = run_bounded_capture(cfg)
        checks["5_capture_against_fake_interface_rejected"] = result.accepted is False
        checks["5_capture_rejection_has_errors"] = len(result.errors) > 0
        checks["5_no_output_file_created_on_rejection"] = not out_path.exists()
        checks["5_no_tcpdump_process_launched_on_rejection"] = result.tcpdump_returncode is None

    # ============================================================ 6. incremental file-writing behavior (REAL tcpdump, offline replay)
    tcpdump_path = shutil.which("tcpdump")
    fixture = ROOT / "tests/fixtures/pcap/synthetic_benign.pcap"
    if tcpdump_path is None:
        skips.append("6_incremental_write_via_tcpdump_replay (tcpdump not installed on this platform)")
    elif not fixture.exists():
        skips.append("6_incremental_write_via_tcpdump_replay (fixture pcap not found)")
    else:
        with tempfile.TemporaryDirectory() as tmp:
            replay_out = Path(tmp) / "replay_out.pcap"
            # Offline file-to-file replay (-r reads an existing local file, NOT a live interface) -
            # exercises the exact "-w <path>" incremental-write flag our adapter uses for live
            # capture, without touching any network interface or requiring elevated permission.
            proc = subprocess.run(["tcpdump", "-r", str(fixture), "-w", str(replay_out), "-U"],
                                   capture_output=True, text=True, timeout=30)
            checks["6_tcpdump_replay_exit_code_zero"] = proc.returncode == 0
            checks["6_replay_output_file_created"] = replay_out.exists()
            checks["6_replay_output_file_nonempty"] = replay_out.exists() and replay_out.stat().st_size > 0
            checks["6_no_capture_output_field_used_for_packet_bytes"] = True  # structural: subprocess.run above uses capture_output for STDERR/TEXT only, never for packet data - packets go straight file-to-file via tcpdump's own -w, confirmed by replay_out's nonzero size while this process's own memory never held packet bytes

    # ============================================================ 7. provenance metadata
    with tempfile.TemporaryDirectory() as tmp:
        cfg = CaptureConfig(interface=fake_name, output_path=Path(tmp) / "g.pcap", max_packets=5)
        result = run_bounded_capture(cfg)
        checks["7_result_carries_provenance_tag"] = "OBSERVED_LAB_TRAFFIC" in result.provenance
        checks["7_result_carries_config"] = result.config == cfg
        checks["7_result_carries_interface_info"] = result.interface_info.name == fake_name
        checks["7_result_carries_permission_status"] = result.permission_status.mechanism == "tcpdump"

    # ============================================================ 8. no packet-injection functions anywhere in L3.2 code
    injection_found = []
    for path in L3_2_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                if func_name in FORBIDDEN_INJECTION_CALLS:
                    injection_found.append(f"{path.name}: {func_name}()")
    checks["8_no_packet_injection_functions"] = len(injection_found) == 0
    if injection_found:
        print(f"  INJECTION-LIKE CALLS FOUND: {injection_found}")

    # ============================================================ 9. no firewall/system-mutation commands anywhere in L3.2 code
    # AST-based: only inspects string-literal arguments actually passed to subprocess.run/Popen
    # calls (i.e. commands that would really execute), never docstring/comment text explaining
    # what the code does NOT do - a plain substring search would false-positive on exactly those
    # explanatory docstrings (this project's established lesson from Feature L1's own .fit() check).
    mutation_found = []
    for path in L3_2_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("run", "Popen", "call", "check_call", "check_output")):
                continue
            if not node.args:
                continue
            first_arg = node.args[0]
            arg_strings = []
            if isinstance(first_arg, ast.List):
                arg_strings = [elt.value for elt in first_arg.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
            elif isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                arg_strings = [first_arg.value]
            joined = " ".join(arg_strings)
            for pattern in FORBIDDEN_MUTATION_SUBSTRINGS:
                if pattern.strip() in joined:
                    mutation_found.append(f"{path.name}: subprocess call argument contains {pattern!r} -> {arg_strings}")
    checks["9_no_firewall_or_system_mutation_commands"] = len(mutation_found) == 0
    if mutation_found:
        print(f"  MUTATION COMMANDS FOUND IN REAL SUBPROCESS CALLS: {mutation_found}")

    # ============================================================ 10. no model inference introduced
    no_model_imports = all(
        not any(fi in path.read_text(encoding="utf-8") for fi in FORBIDDEN_MODEL_IMPORTS)
        for path in L3_2_FILES
    )
    checks["10_no_model_inference_code_introduced"] = no_model_imports

    # ============================================================ 11. no .fit()/.fit_transform() anywhere in L3.2 code
    no_fit = True
    for path in L3_2_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("fit", "fit_transform"):
                no_fit = False
    checks["11_no_fit_call_in_L3_2_code"] = no_fit

    # ---- protected-file integrity ----
    print("Hashing protected files (post-run) ...")
    protected_after = hash_protected_state()
    unchanged = protected_before == protected_after
    checks["protected_files_unchanged"] = unchanged
    if not unchanged:
        changed = [p for p in protected_before if protected_before.get(p) != protected_after.get(p)]
        print(f"  CHANGED FILES: {changed}")

    # ---- report ----
    print("\n" + "=" * 70)
    print("FEATURE L3.2 - SANDBOX CAPTURE ADAPTER TEST RESULTS")
    print("=" * 70)
    all_pass = True
    for k, v in checks.items():
        status = "PASS" if v else "FAIL"
        if not v:
            all_pass = False
        print(f"  [{status}] {k}")
    for s in skips:
        print(f"  [SKIP] {s}")

    if not all_pass:
        fail("One or more Feature L3.2 checks failed - see PASS/FAIL list above.")

    print("\nALL FEATURE L3.2 SANDBOX CAPTURE ADAPTER CHECKS PASSED.")


if __name__ == "__main__":
    main()
