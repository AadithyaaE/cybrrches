import json
import platform
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
OUT_DIR = ROOT / "results/pcap_cicflowmeter_reference"

env = {
    "os": platform.platform(),
    "python_interpreters_available": {
        "python (3.12.10)": r"C:\Users\Eswaran D\AppData\Local\Programs\Python\Python312\python.exe - has scapy; used for all L2/L2.5/L2.6/L2.7 CyberChess-side work",
        "python3 (3.14.3)": "no scapy; not used for PCAP work this session",
    },
    "java_version": "OpenJDK/Java(TM) SE 26.0.2 2026-07-21 (`java -version` confirmed present)",
    "maven_installed": False,
    "gradle_installed": False,
    "tcpdump_installed": False,
    "tshark_wireshark_dumpcap_installed": False,
    "network_access_available": True,
    "network_check_method": "curl -I https://pypi.org -> HTTP 200 OK",
    "reference_tool": {
        "name": "cicflowmeter",
        "source": "PyPI (https://pypi.org/project/cicflowmeter/)",
        "upstream_repository": "https://github.com/hieulw/cicflowmeter",
        "version_installed": "0.5.0",
        "author": "Hieu Le <hieulw99@gmail.com>",
        "license": "MIT",
        "is_original_java_cicflowmeter": False,
        "note": (
            "Third-party Python reimplementation explicitly modeled on the original Java CICFlowMeter "
            "(ahlashkari/CICFlowMeter, the tool that generated CSE-CIC-IDS2018), NOT the original tool itself. "
            "Its own README states it is not actively maintained."
        ),
        "install_location": "results/pcap_cicflowmeter_reference/reference_venv/ (isolated venv via `python -m venv`; does not touch the project's main Python environments)",
        "dependencies_installed_in_isolated_venv": {},
    },
    "confirmed_reference_tool_issues": [
        "CLI entry point (`cicflowmeter -f ... -c ...`) crashes with AttributeError: 'bool' object has no attribute 'split' - sniffer.py's main() calls create_sniffer() with a positional argument order that does not match its own function signature (args.fields lands in the input_directory parameter, args.verbose lands in the fields parameter). Worked around by calling FlowSession.process() directly per packet (see run_cicflowmeter_reference.py) - the installed package itself was NOT modified.",
        "AsyncSniffer(offline=..., filter=...) requires an external `tcpdump` binary to compile the BPF filter even for offline files on this platform; none is installed. Worked around by reading packets via scapy's rdpcap() (the same function CyberChess's own pcap_reader.py uses) and calling FlowSession.process() per packet with no filter object - safe, since process() already discards any non-TCP/UDP packet itself.",
        "FlowSession.process() adds the very first packet of every new flow TWICE (once in Flow.__init__, once more via an unconditional flow.add_packet() call immediately after) - confirmed empirically via syn_flag_cnt showing 3 for a flow with only 2 real SYN packets, and every flow's forward-direction packet count being inflated by exactly 1 versus the known, deterministically-generated fixture. See feature_comparison.csv's `known_root_cause`/`explanation` columns for exactly which features this affects.",
    ],
}

proc = subprocess.run(
    [str(OUT_DIR / "reference_venv/Scripts/python.exe"), "-m", "pip", "freeze"],
    capture_output=True, text=True,
)
env["reference_tool"]["dependencies_installed_in_isolated_venv"] = dict(
    line.split("==") for line in proc.stdout.strip().splitlines() if "==" in line
)

(OUT_DIR / "environment.json").write_text(json.dumps(env, indent=2), encoding="utf-8")
print(json.dumps(env, indent=2))
