"""
Feature L2.7 - runs the pip-installed `cicflowmeter` 0.5.0 reference
package's FlowSession directly (NOT via its CLI entry point), because the
installed CLI (`cicflowmeter -f ... -c ...`) has a confirmed argument-
passing bug in this version: sniffer.py's main() calls
create_sniffer(args.input_file, args.input_interface, args.output_mode,
args.output, args.fields, args.verbose) positionally, but create_sniffer's
signature is (input_file, input_interface, output_mode, output,
input_directory=None, fields=None, verbose=False) - args.fields lands in
the input_directory slot and args.verbose lands in the fields slot,
raising AttributeError: 'bool' object has no attribute 'split'.

This script is NOT a modification of the installed package (nothing under
reference_venv/ is edited) - it is a small, honest workaround that calls
the SAME public FlowSession API the CLI itself uses (FlowSession.process()
per packet), just with correctly-ordered keyword arguments and a different
packet source.

A SECOND, independent environment limitation was found while building this
workaround: scapy's AsyncSniffer(offline=..., filter=...) requires an
external `tcpdump` binary to compile/apply the BPF filter in offline mode
even on Windows, and no `tcpdump` is installed anywhere in this environment
(confirmed in environment.json). Rather than install tcpdump (a new
dependency, contrary to this task's "do not install a large dependency
stack" instruction, and unnecessary), packets are read directly via
scapy's rdpcap() (the SAME function CyberChess's own pcap_reader.py uses)
and passed to FlowSession.process() one at a time with no filter object at
all. This is safe and behaviour-preserving: process() itself already
starts with `if "TCP" not in pkt and "UDP" not in pkt: return None`, which
is exactly what the "ip and (tcp or udp)" BPF filter would have done.

Must be run with the isolated reference_venv's own Python interpreter (it
imports cicflowmeter).

Usage:
    reference_venv/Scripts/python.exe run_cicflowmeter_reference.py <pcap_path> <output_csv_path>
"""

import sys

from scapy.utils import rdpcap

from cicflowmeter.flow_session import FlowSession


def run(pcap_path: str, output_csv_path: str) -> None:
    session = FlowSession(output_mode="csv", output=output_csv_path, fields=None, verbose=False)
    packets = rdpcap(pcap_path)
    for pkt in packets:
        session.process(pkt)
    session.flush_flows()  # writes every flow still open at end-of-capture (same call process_directory_merged() uses)
    print(f"Wrote CICFlowMeter reference output to {output_csv_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: run_cicflowmeter_reference.py <pcap_path> <output_csv_path>")
    run(sys.argv[1], sys.argv[2])
