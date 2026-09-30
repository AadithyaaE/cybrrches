"""
Feature L2.9 - flow-level correlation between a real CSE-CIC-IDS2018 PCAP
sample and the existing processed training CSV.

Uses CyberChess's EXISTING, UNMODIFIED PCAP parser/flow-reconstruction
(src/data/pcap/pcap_reader.py, flow_reconstruction.py) - imported only,
never edited. No model is run. No labels are used for matching.

IMPORTANT CONSTRAINT (documented, not worked around): the processed CSV
has NO IP address columns at all (confirmed from its own header - only
Dst Port, Protocol, Timestamp, and flow statistics). Matching is
therefore necessarily based on Dst Port + Protocol + Timestamp (within a
tolerance) + duration + packet/byte counts - not on IP address, which
the CSV format itself does not retain. This is a real, structural
limitation of this correlation, documented explicitly in every output.
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from data.pcap.pcap_reader import read_pcap  # noqa: E402
from data.pcap.flow_reconstruction import reconstruct_flows  # noqa: E402
from data.pcap.flow_features import build_flow_feature_table  # noqa: E402

CSV_PATH = ROOT / "data/raw/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"


def build_candidate_flow_table(pcap_path: Path) -> pd.DataFrame:
    """Reuses CyberChess's existing, unmodified PCAP parser + flow reconstruction + feature computation."""
    r = read_pcap(pcap_path)
    recon = reconstruct_flows(r.packets)
    table = build_flow_feature_table(recon.flows)
    table["_src_ip"] = [f.initiator_ip for f in recon.flows]
    table["_dst_ip"] = [f.responder_ip for f in recon.flows]
    table["_src_port"] = [f.initiator_port for f in recon.flows]
    table["_dst_port"] = [f.responder_port for f in recon.flows]
    table["_closed_reason"] = [f.closed_reason for f in recon.flows]
    return table, len(r.packets), len(r.malformed)


def load_csv_window(ts_min: str, ts_max: str) -> pd.DataFrame:
    df = pd.read_csv(CSV_PATH, low_memory=False)
    ts = pd.to_datetime(df["Timestamp"], dayfirst=True, errors="coerce")
    df = df.copy()
    df["_ts_utc"] = ts
    mask = (ts >= ts_min) & (ts <= ts_max)
    return df.loc[mask].reset_index(drop=True)


def match_flows(cand: pd.DataFrame, csv_window: pd.DataFrame, ts_tolerance_s: int = 2) -> pd.DataFrame:
    """
    For each candidate PCAP flow, look for CSV rows in the SAME window matching:
      - Protocol (exact)
      - Dst Port (exact) - matched against the candidate's RESPONDER port, since a flow's
        "Dst Port" in CICFlowMeter/CyberChess convention is the server/responder side
      - Timestamp within `ts_tolerance_s` seconds of the flow's start
    then scores agreement on Tot Fwd/Bwd Pkts, TotLen Fwd/Bwd Pkts, and Flow Duration
    (all in seconds vs CyberChess's microseconds - converted for comparison).
    """
    rows = []
    for _, c in cand.iterrows():
        proto = c["Protocol"]
        dport = c["_dst_port"]
        cts = c["Timestamp"]
        window = csv_window[
            (csv_window["Protocol"] == proto)
            & (csv_window["Dst Port"] == dport)
            & (csv_window["_ts_utc"].sub(cts).abs() <= pd.Timedelta(seconds=ts_tolerance_s))
        ]
        for _, w in window.iterrows():
            duration_diff_s = abs(c["Flow Duration"] / 1_000_000.0 - w["Flow Duration"] / 1_000_000.0)
            fwd_pkt_diff = abs(int(c["Tot Fwd Pkts"]) - int(w["Tot Fwd Pkts"]))
            bwd_pkt_diff = abs(int(c["Tot Bwd Pkts"]) - int(w["Tot Bwd Pkts"]))
            fwd_byt_diff = abs(int(c["TotLen Fwd Pkts"]) - int(w["TotLen Fwd Pkts"]))
            bwd_byt_diff = abs(int(c["TotLen Bwd Pkts"]) - int(w["TotLen Bwd Pkts"]))
            score = sum([
                duration_diff_s < 0.5,
                fwd_pkt_diff == 0,
                bwd_pkt_diff == 0,
                fwd_byt_diff == 0,
                bwd_byt_diff == 0,
            ])
            rows.append({
                "candidate_src_ip": c["_src_ip"], "candidate_dst_ip": c["_dst_ip"],
                "candidate_src_port": c["_src_port"], "candidate_dst_port": c["_dst_port"],
                "candidate_protocol": proto, "candidate_timestamp": str(cts),
                "candidate_flow_duration_s": c["Flow Duration"] / 1_000_000.0,
                "candidate_tot_fwd_pkts": int(c["Tot Fwd Pkts"]), "candidate_tot_bwd_pkts": int(c["Tot Bwd Pkts"]),
                "candidate_totlen_fwd": int(c["TotLen Fwd Pkts"]), "candidate_totlen_bwd": int(c["TotLen Bwd Pkts"]),
                "csv_row_index": w.name, "csv_timestamp": str(w["_ts_utc"]), "csv_label": w["Label"],
                "csv_flow_duration_s": w["Flow Duration"] / 1_000_000.0,
                "csv_tot_fwd_pkts": int(w["Tot Fwd Pkts"]), "csv_tot_bwd_pkts": int(w["Tot Bwd Pkts"]),
                "csv_totlen_fwd": int(w["TotLen Fwd Pkts"]), "csv_totlen_bwd": int(w["TotLen Bwd Pkts"]),
                "timestamp_diff_s": abs((w["_ts_utc"] - cts).total_seconds()),
                "duration_diff_s": duration_diff_s,
                "fwd_pkt_diff": fwd_pkt_diff, "bwd_pkt_diff": bwd_pkt_diff,
                "fwd_byt_diff": fwd_byt_diff, "bwd_byt_diff": bwd_byt_diff,
                "match_score_0to5": score,
            })
    return pd.DataFrame(rows)
