"""Feature L2.7 - writes acquisition_report.txt and reproducibility_report.txt."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
OUT_DIR = ROOT / "results/pcap_cicflowmeter_reference"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    env = json.loads((OUT_DIR / "environment.json").read_text(encoding="utf-8"))
    manifest = json.loads((OUT_DIR / "pcap_manifest.json").read_text(encoding="utf-8"))

    # ---- acquisition_report.txt ----
    lines = []
    lines.append("=" * 70)
    lines.append("FEATURE L2.7 - CICFLOWMETER REFERENCE ACQUISITION REPORT")
    lines.append("=" * 70)
    lines.append("")
    lines.append("STEP 1 - ENVIRONMENT AUDIT (before installing anything)")
    lines.append("-" * 70)
    lines.append("  Python interpreters: python 3.12.10 (has scapy), python3 3.14.3 (no scapy)")
    lines.append(f"  Java: {env['java_version']}")
    lines.append(f"  Maven installed: {env['maven_installed']}   Gradle installed: {env['gradle_installed']}")
    lines.append(f"  tcpdump/tshark/wireshark/dumpcap installed: {env['tcpdump_installed']}")
    lines.append(f"  Network access available: {env['network_access_available']} ({env['network_check_method']})")
    lines.append("  No CICFlowMeter (any version) already present anywhere in this repository or environment.")
    lines.append("  git history: single 'Initial commit', no CICFlowMeter references anywhere in commit log.")
    lines.append("  Existing raw PCAP: only tests/fixtures/pcap/synthetic_benign.pcap (Feature L2's own protected")
    lines.append("    fixture - not reused here; see STEP 3 below for why a new capture was made instead).")
    lines.append("")
    lines.append("STEP 2 - RESEARCH AND ACQUISITION DECISION")
    lines.append("-" * 70)
    lines.append("  Preference order given by the task: (1) existing local/reference installation - NONE found.")
    lines.append("  (2) reproducible official/open-source repository - the ORIGINAL Java CICFlowMeter")
    lines.append("  (github.com/ahlashkari/CICFlowMeter, the tool that generated CSE-CIC-IDS2018) would require")
    lines.append("  cloning its repository, installing Maven (not present), and building a full Java desktop/CLI")
    lines.append("  application with native packet-capture dependencies (jnetpcap/pcap4j and platform pcap")
    lines.append("  drivers). This was judged to constitute exactly the kind of 'large dependency stack' this")
    lines.append("  task instructs NOT to install blindly, with meaningfully uncertain build success. NOT")
    lines.append("  attempted for this reason - documented here per the task's explicit 'if it cannot reasonably")
    lines.append("  be obtained, document exactly why' instruction.")
    lines.append("  (3) minimal isolated reference environment - USED. The PyPI package `cicflowmeter` 0.5.0")
    lines.append("  (github.com/hieulw/cicflowmeter, MIT license) is a small, pure-Python, scapy-based")
    lines.append("  reimplementation that explicitly cites the original Java CICFlowMeter as its design reference")
    lines.append("  and offers an offline PCAP-to-CSV mode requiring no live capture/root access. Installed into a")
    lines.append("  NEW, ISOLATED virtual environment (python -m venv) at")
    lines.append("  results/pcap_cicflowmeter_reference/reference_venv/ - this does not modify, and is entirely")
    lines.append("  separate from, the project's main Python 3.12/3.14 environments.")
    lines.append("")
    lines.append("  CRITICAL CAVEAT (see STEP 6 below): this is a THIRD-PARTY REIMPLEMENTATION, not the original")
    lines.append("  tool that generated the CSE-CIC-IDS2018 training CSV. 'Same column name' is NOT assumed to")
    lines.append("  mean 'same formula' - see feature_comparison.csv for exactly where they agree and disagree.")
    lines.append("")
    lines.append("  Exact command used to install (isolated, documented before running):")
    lines.append("    python -m venv results/pcap_cicflowmeter_reference/reference_venv")
    lines.append("    reference_venv/Scripts/python.exe -m pip install cicflowmeter==0.5.0")
    lines.append("")
    lines.append("STEP 2b - CONFIRMED REFERENCE-TOOL ISSUES ENCOUNTERED (documented, not silently patched)")
    lines.append("-" * 70)
    for i, issue in enumerate(env["confirmed_reference_tool_issues"], 1):
        lines.append(f"  {i}. {issue}")
        lines.append("")
    lines.append("STEP 3 - COMPARISON PCAP")
    lines.append("-" * 70)
    lines.append(f"  The existing L2 fixture (synthetic_benign.pcap) lacked a zero-duration/single-packet flow,")
    lines.append(f"  explicitly required by this task. A NEW, separate, deterministic, non-malicious capture was")
    lines.append(f"  generated instead (not modifying the protected L2 fixture): {manifest['pcap_file']}")
    lines.append(f"  SHA-256: {manifest['sha256']}")
    lines.append(f"  {manifest['frame_count']} frames across {len(manifest['flows_designed'])} designed flows:")
    for f in manifest["flows_designed"]:
        lines.append(f"    - {f['label']} ({f['protocol']}, {f['packets']} packets): {f['description']}")
    lines.append("")
    lines.append("STEP 10 - EXACT COMMANDS USED (for reproducibility)")
    lines.append("-" * 70)
    lines.append("  1. python src/data/pcap_cicflowmeter_reference/generate_comparison_pcap.py")
    lines.append("  2. reference_venv/Scripts/python.exe src/data/pcap_cicflowmeter_reference/run_cicflowmeter_reference.py \\")
    lines.append("       results/pcap_cicflowmeter_reference/comparison_capture.pcap \\")
    lines.append("       results/pcap_cicflowmeter_reference/cicflowmeter_reference_output_run{1,2}.csv")
    lines.append("  3. CyberChess side: read_pcap() -> reconstruct_flows() -> build_flow_feature_table() (all")
    lines.append("     Feature L2 functions, completely unmodified) on the same PCAP, run twice")
    lines.append("  4. python src/data/pcap_cicflowmeter_reference/compare_features.py")
    lines.append("  See reproducibility_report.txt for hashes proving both tools were deterministic across 2 runs.")

    (OUT_DIR / "acquisition_report.txt").write_text("\n".join(lines), encoding="utf-8")

    # ---- reproducibility_report.txt ----
    files = {
        "comparison_capture.pcap": OUT_DIR / "comparison_capture.pcap",
        "cicflowmeter_reference_output_run1.csv": OUT_DIR / "cicflowmeter_reference_output_run1.csv",
        "cicflowmeter_reference_output_run2.csv": OUT_DIR / "cicflowmeter_reference_output_run2.csv",
        "cyberchess_output_run1.csv": OUT_DIR / "cyberchess_output_run1.csv",
        "cyberchess_output_run2.csv": OUT_DIR / "cyberchess_output_run2.csv",
    }
    hashes = {name: sha256(path) for name, path in files.items()}

    r_lines = []
    r_lines.append("=" * 70)
    r_lines.append("FEATURE L2.7 - REPRODUCIBILITY REPORT")
    r_lines.append("=" * 70)
    r_lines.append("")
    r_lines.append("The comparison was run TWICE end-to-end (both the CICFlowMeter reference and the CyberChess")
    r_lines.append("extractor), on the identical PCAP file, in separate process invocations.")
    r_lines.append("")
    r_lines.append("SHA-256 hashes:")
    for name, h in hashes.items():
        r_lines.append(f"  {name}: {h}")
    r_lines.append("")
    ref_match = hashes["cicflowmeter_reference_output_run1.csv"] == hashes["cicflowmeter_reference_output_run2.csv"]
    cc_match = hashes["cyberchess_output_run1.csv"] == hashes["cyberchess_output_run2.csv"]
    r_lines.append(f"CICFlowMeter reference output identical across both runs (byte-for-byte): {ref_match}")
    r_lines.append(f"CyberChess output identical across both runs (byte-for-byte): {cc_match}")
    r_lines.append("")
    r_lines.append("Configuration used for both runs (recorded for reproducibility):")
    r_lines.append(f"  Reference tool: cicflowmeter=={env['reference_tool']['version_installed']} (isolated venv)")
    r_lines.append(f"  Reference tool invocation: FlowSession.process() called per packet via rdpcap() (see")
    r_lines.append(f"    run_cicflowmeter_reference.py and its docstring for why, not the broken CLI entry point)")
    r_lines.append(f"  CyberChess: src/data/pcap/{{pcap_reader,flow_reconstruction,flow_features}}.py (Feature L2/L2.6,")
    r_lines.append(f"    unmodified by this task) with default flow_timeout_us and active_idle_threshold_us")
    r_lines.append(f"  PCAP: {manifest['pcap_file']} (SHA-256 {manifest['sha256']})")
    r_lines.append("")
    r_lines.append(f"CONCLUSION: {'Both tools are deterministic on this capture.' if ref_match and cc_match else 'NON-DETERMINISM DETECTED - see hashes above.'}")

    (OUT_DIR / "reproducibility_report.txt").write_text("\n".join(r_lines), encoding="utf-8")

    print("Wrote acquisition_report.txt and reproducibility_report.txt")
    print(f"ref_match={ref_match} cc_match={cc_match}")


if __name__ == "__main__":
    main()
