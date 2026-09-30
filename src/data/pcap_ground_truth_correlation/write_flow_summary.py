import sys
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from data.pcap.pcap_reader import read_pcap
from data.pcap.flow_reconstruction import reconstruct_flows

PCAP_PATH = ROOT / "results/pcap_ground_truth_correlation/candidate_part2_172.31.69.13.pcap"
OUT_PATH = ROOT / "results/pcap_ground_truth_correlation/candidate_flow_summary.csv"


def main():
    r = read_pcap(PCAP_PATH)
    recon = reconstruct_flows(r.packets)

    with open(OUT_PATH, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "flow_id", "initiator_ip", "initiator_port", "responder_ip", "responder_port", "protocol",
            "start_time_utc_us", "end_time_utc_us", "duration_us", "packet_count", "closed_reason",
        ])
        for fl in recon.flows:
            w.writerow([
                fl.flow_id, fl.initiator_ip, fl.initiator_port, fl.responder_ip, fl.responder_port,
                fl.protocol, fl.start_time_us, fl.end_time_us, fl.end_time_us - fl.start_time_us,
                len(fl.packets), fl.closed_reason,
            ])
    print(f"wrote {OUT_PATH} with {len(recon.flows)} rows")


if __name__ == "__main__":
    main()
