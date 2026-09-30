"""Feature L3.1 - writes results/sandbox_input_contract/contract_summary.json. Read-only w.r.t. everything else."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from data.sandbox_contract.contract_schema import (  # noqa: E402
    REQUIRED_65_FEATURES, STATE_ORDER_68D, PROTOCOL_ONEHOT_COLUMNS, STATE_DIMENSIONS,
    SEQUENCE_LENGTH, WINDOW_SECONDS, DataProvenance, LabInputForm, RejectionReason,
    REQUIRED_PACKET_FIELDS, REQUIRED_FLOW_TABLE_COLUMNS,
)

OUT_DIR = ROOT / "results/sandbox_input_contract"


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    summary = {
        "status": "CONTRACT DEFINITION ONLY - no Sandbox/lab pipeline is implemented or claimed to work",
        "accepted_input_forms": [e.value for e in LabInputForm],
        "required_65_features_count": len(REQUIRED_65_FEATURES),
        "state_dimensions": STATE_DIMENSIONS,
        "state_order_68d": STATE_ORDER_68D,
        "protocol_onehot_columns": PROTOCOL_ONEHOT_COLUMNS,
        "sequence_length": SEQUENCE_LENGTH,
        "window_seconds": WINDOW_SECONDS,
        "required_packet_fields_for_raw_pcap_form": list(REQUIRED_PACKET_FIELDS),
        "required_flow_table_columns_count": len(REQUIRED_FLOW_TABLE_COLUMNS),
        "data_provenance_categories": [e.value for e in DataProvenance],
        "rejection_reasons": [e.value for e in RejectionReason],
        "known_pcap_limitations_carried_forward": [
            "Most PCAP feature formulas remain unvalidated against the original CICFlowMeter-V3 generation process (L2.5: 6 VALIDATED / 21 PARTIALLY_VALIDATED / 37 UNVALIDATED / 1 NOT_REPRODUCIBLE out of 65; L2.6 corrected 4 of the 37).",
            "The official archive/source is plausible (L2.8: MATCH_PLAUSIBLE) but flow-level PCAP<->CSV correspondence was not established.",
            "The tested part2 candidate (L2.9) was outside the CSV observation window (zero timestamp overlap) - classified NOT_MATCHING for correlation purposes.",
            "IPv6 is currently unsupported by the CyberChess PCAP adapter (src/data/pcap/pcap_reader.py explicitly detects and rejects it).",
        ],
        "governing_document": "docs/sandbox_input_contract/SANDBOX_INPUT_CONTRACT.md",
    }
    (OUT_DIR / "contract_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote {OUT_DIR / 'contract_summary.json'}")


if __name__ == "__main__":
    main()
