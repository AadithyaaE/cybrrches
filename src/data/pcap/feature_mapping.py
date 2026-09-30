"""
Feature L2 - CyberChess <-> PCAP feature mapping table.

This is the SINGLE SOURCE OF TRUTH for how (or whether) each of the 65
required CyberChess numeric features can be derived from an offline PCAP
capture. flow_features.py's computation MUST follow exactly these
formulas; nothing here or there invents a value for a feature just
because its name exists.

CATEGORIES (per the L2 task specification):
    A - directly extractable from a single packet field or a trivial
        per-packet aggregate (count/sum), no flow-timing algorithm needed
    B - derivable from a reconstructed bidirectional flow (needs the full
        packet list for that flow, but a straightforward statistic)
    C - derivable from packet timing/statistics (inter-arrival times, or
        an explicit threshold-based algorithm such as active/idle
        segmentation)
    D - NOT currently reproducible with sufficient semantic confidence -
        the CyberChess/CICFlowMeter definition is itself ambiguous or
        version-inconsistent (e.g. CICFlowMeter's "subflow" splitting
        logic), and no safe, well-defined formula is implemented here

CRITICAL HONESTY NOTE (read before trusting any "A"/"B"/"C" label):
--------------------------------------------------------------------
No CICFlowMeter installation is available in this environment (see
results/pcap/tool_availability_report.json). Every formula below is
implemented from CICFlowMeter's published/documented feature semantics,
but has NOT been empirically cross-checked byte-for-byte against real
CICFlowMeter output. `training_definition_validated` is therefore False
for EVERY feature, without exception. A/B/C only describe HOW a value is
computed (technical extractability), never "proven identical to the
original training feature". See `limitation` for the specific caveat on
each row.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FeatureMappingEntry:
    feature: str
    category: str  # "A" | "B" | "C" | "D"
    level: str  # "packet" | "flow"
    dtype: str
    formula: str
    training_definition_validated: bool
    limitation: str


# Default CICFlowMeter-style thresholds this module uses. Configurable at
# call sites (flow_features.compute_flow_features), never hard-fitted to
# any specific capture.
DEFAULT_ACTIVE_IDLE_THRESHOLD_US = 5_000_000  # 5s - matches CICFlowMeter's published default "activeTimeout"

_VALIDATION_LIMITATION = (
    "Formula follows CICFlowMeter's published/documented definition, but has NOT been "
    "empirically cross-checked against a real CICFlowMeter installation (none available "
    "in this environment - see tool_availability_report.json)."
)

FEATURE_MAPPING: dict[str, FeatureMappingEntry] = {}


def _add(feature, category, level, dtype, formula, limitation=_VALIDATION_LIMITATION):
    FEATURE_MAPPING[feature] = FeatureMappingEntry(
        feature=feature, category=category, level=level, dtype=dtype, formula=formula,
        training_definition_validated=False, limitation=limitation,
    )


# ---------------------------------------------------------------- Category A
_add("Tot Fwd Pkts", "A", "flow", "int64", "count(packets where direction == forward)")
_add("Tot Bwd Pkts", "A", "flow", "int64", "count(packets where direction == backward)")
_add("TotLen Fwd Pkts", "A", "flow", "int64", "sum(IP total length for forward packets)")
_add("TotLen Bwd Pkts", "A", "flow", "int64", "sum(IP total length for backward packets)")
_add("ACK Flag Cnt", "A", "flow", "int64", "count(packets, both directions, with TCP ACK flag set)")
_add("SYN Flag Cnt", "A", "flow", "int64", "count(packets, both directions, with TCP SYN flag set)")
_add("RST Flag Cnt", "A", "flow", "int64", "count(packets, both directions, with TCP RST flag set)")
_add("PSH Flag Cnt", "A", "flow", "int64", "count(packets, both directions, with TCP PSH flag set)")
_add("URG Flag Cnt", "A", "flow", "int64", "count(packets, both directions, with TCP URG flag set)")
_add("ECE Flag Cnt", "A", "flow", "int64", "count(packets, both directions, with TCP ECE flag set)")
_add("Fwd PSH Flags", "A", "flow", "int64", "count(forward packets with TCP PSH flag set)")
_add("Fwd Act Data Pkts", "A", "flow", "int64", "count(forward packets where TCP/UDP payload length > 0)")
_add(
    "Init Fwd Win Byts", "A", "flow", "int64",
    "TCP window field of the FIRST forward packet that carries a TCP header; -1 if the flow is not TCP or no forward TCP packet exists",
    _VALIDATION_LIMITATION + " Not applicable to UDP flows; represented as -1 (CICFlowMeter's own documented convention for 'not applicable'), never fabricated.",
)
_add(
    "Init Bwd Win Byts", "A", "flow", "int64",
    "TCP window field of the FIRST backward packet that carries a TCP header; -1 if not TCP or no backward TCP packet exists",
    _VALIDATION_LIMITATION + " Not applicable to UDP flows; represented as -1, never fabricated.",
)
_add("Fwd Header Len", "A", "flow", "int64", "sum(IP header length + TCP/UDP header length, for forward packets)")
_add("Bwd Header Len", "A", "flow", "int64", "sum(IP header length + TCP/UDP header length, for backward packets)")

# ---------------------------------------------------------------- Category B
_add("Flow Duration", "B", "flow", "int64", "(timestamp of last packet - timestamp of first packet in the flow), microseconds")
_add("Fwd Pkt Len Max", "B", "flow", "int64", "max(IP total length) over forward packets, 0 if none")
_add("Fwd Pkt Len Min", "B", "flow", "int64", "min(IP total length) over forward packets, 0 if none")
_add("Fwd Pkt Len Mean", "B", "flow", "float64", "mean(IP total length) over forward packets, 0.0 if none")
_add("Fwd Pkt Len Std", "B", "flow", "float64", "population std-dev of IP total length over forward packets, 0.0 if <2 packets")
_add("Bwd Pkt Len Max", "B", "flow", "int64", "max(IP total length) over backward packets, 0 if none")
_add("Bwd Pkt Len Min", "B", "flow", "int64", "min(IP total length) over backward packets, 0 if none")
_add("Bwd Pkt Len Mean", "B", "flow", "float64", "mean(IP total length) over backward packets, 0.0 if none")
_add("Bwd Pkt Len Std", "B", "flow", "float64", "population std-dev of IP total length over backward packets, 0.0 if <2 packets")
_add("Pkt Len Max", "B", "flow", "int64", "max(IP total length) over all packets in the flow (both directions)")
_add("Pkt Len Min", "B", "flow", "int64", "min(IP total length) over all packets in the flow (both directions)")
_add("Pkt Len Mean", "B", "flow", "float64", "mean(IP total length) over all packets in the flow (both directions)")
_add("Pkt Len Std", "B", "flow", "float64", "population std-dev of IP total length over all packets (both directions)")
_add("Pkt Len Var", "B", "flow", "float64", "population variance of IP total length over all packets (both directions)")
_add(
    "Pkt Size Avg", "B", "flow", "float64", "sum(IP total length, both directions) / total packet count",
    _VALIDATION_LIMITATION + " Numerically identical to 'Pkt Len Mean' under this implementation; CICFlowMeter's own source has historically defined these two features near-identically, which this module does not attempt to second-guess.",
)
_add(
    "Down/Up Ratio", "B", "flow", "int64", "int(Tot Bwd Pkts / Tot Fwd Pkts) if Tot Fwd Pkts > 0 else 0",
    _VALIDATION_LIMITATION + " Integer-truncating ratio, matching state_schema.json's int64 dtype for this feature.",
)
_add(
    "Flow Byts/s", "B", "flow", "float64",
    "(TotLen Fwd Pkts + TotLen Bwd Pkts) / (Flow Duration in seconds) if Flow Duration > 0; else NaN if total bytes == 0, else Infinity",
    "CORRECTED in Feature L2.6: results/feature_selection_report.txt STEP 5 (Feature 3's own audit, produced from the real "
    "training data) documents that real zero-duration flows with zero bytes yield NaN (0/0), while zero-duration flows with "
    "nonzero bytes yield Infinity. Previously this implementation returned Infinity unconditionally for any zero-duration "
    "flow; corrected to match the documented convention. See results/pcap_formula_corrections/ for the audit trail.",
)
_add(
    "Flow Pkts/s", "B", "flow", "float64", "(Tot Fwd Pkts + Tot Bwd Pkts) / (Flow Duration in seconds); Infinity if Flow Duration == 0",
    _VALIDATION_LIMITATION + " Feature L2.5 confirmed this convention matches real training data 100% (a flow's total packet "
    "count is always >=1, so the 0/0 case never occurs) - unchanged in Feature L2.6.",
)
_add(
    "Fwd Pkts/s", "B", "flow", "float64", "Tot Fwd Pkts / (Flow Duration in seconds) if Flow Duration > 0; else 0.0",
    "CORRECTED in Feature L2.6: Feature L2.5 found ZERO Infinity values for this column anywhere in the real 331,027-row "
    "training dataset, even at zero flow duration. Previously this implementation returned Infinity unconditionally for any "
    "zero-duration flow; corrected to return 0.0, matching the observed real-data convention. See "
    "results/pcap_formula_corrections/ for the audit trail.",
)
_add(
    "Bwd Pkts/s", "B", "flow", "float64", "Tot Bwd Pkts / (Flow Duration in seconds) if Flow Duration > 0; else 0.0",
    "CORRECTED in Feature L2.6: same finding and correction as Fwd Pkts/s - ZERO Infinity values observed anywhere in real "
    "training data for this column. See results/pcap_formula_corrections/ for the audit trail.",
)

# ---------------------------------------------------------------- Category C
_add("Flow IAT Mean", "C", "flow", "float64", "mean(inter-arrival time in microseconds) between consecutive packets, both directions merged and time-sorted")
_add("Flow IAT Std", "C", "flow", "float64", "population std-dev of the same inter-arrival series")
_add("Flow IAT Max", "C", "flow", "int64", "max of the same inter-arrival series")
_add("Flow IAT Min", "C", "flow", "int64", "min of the same inter-arrival series")
_add("Fwd IAT Tot", "C", "flow", "int64", "sum(inter-arrival time in microseconds) between consecutive FORWARD-only packets")
_add("Fwd IAT Mean", "C", "flow", "float64", "mean of the same forward-only inter-arrival series, 0.0 if <2 forward packets")
_add("Fwd IAT Std", "C", "flow", "float64", "population std-dev of the same series, 0.0 if <2 forward packets")
_add("Fwd IAT Max", "C", "flow", "int64", "max of the same series, 0 if <2 forward packets")
_add("Fwd IAT Min", "C", "flow", "int64", "min of the same series, 0 if <2 forward packets")
_add("Bwd IAT Tot", "C", "flow", "int64", "sum(inter-arrival time in microseconds) between consecutive BACKWARD-only packets")
_add("Bwd IAT Mean", "C", "flow", "float64", "mean of the same backward-only inter-arrival series, 0.0 if <2 backward packets")
_add("Bwd IAT Std", "C", "flow", "float64", "population std-dev of the same series, 0.0 if <2 backward packets")
_add("Bwd IAT Max", "C", "flow", "int64", "max of the same series, 0 if <2 backward packets")
_add("Bwd IAT Min", "C", "flow", "int64", "min of the same series, 0 if <2 backward packets")
_ACTIVE_IDLE_NOTE = (
    _VALIDATION_LIMITATION
    + " Uses the explicit, configurable activeIdleThreshold_us parameter (default 5,000,000us / 5s, matching "
    "CICFlowMeter's published default 'activeTimeout') to segment the flow's merged packet timestamps into "
    "bursts ('active' periods) separated by gaps >= threshold ('idle' periods). A flow with 0 or 1 active "
    "periods (no gap ever exceeded the threshold) has no idle statistics at all (0.0/0, not fabricated)."
)
_add("Active Mean", "C", "flow", "float64", "mean(duration of each active burst, microseconds)", _ACTIVE_IDLE_NOTE)
_add("Active Std", "C", "flow", "float64", "population std-dev of active-burst durations", _ACTIVE_IDLE_NOTE)
_add("Active Max", "C", "flow", "int64", "max active-burst duration", _ACTIVE_IDLE_NOTE)
_add("Active Min", "C", "flow", "int64", "min active-burst duration", _ACTIVE_IDLE_NOTE)
_add("Idle Mean", "C", "flow", "float64", "mean(duration of each idle gap >= threshold, microseconds)", _ACTIVE_IDLE_NOTE)
_add("Idle Std", "C", "flow", "float64", "population std-dev of idle-gap durations", _ACTIVE_IDLE_NOTE)
_add("Idle Max", "C", "flow", "int64", "max idle-gap duration", _ACTIVE_IDLE_NOTE)
_add("Idle Min", "C", "flow", "int64", "min idle-gap duration", _ACTIVE_IDLE_NOTE)

# ------------------------------------------------------- Category C (caveated simplification)
_SEG_SIZE_NOTE = (
    _VALIDATION_LIMITATION
    + " Implemented as a direct alias of the corresponding Pkt-Len statistic for that direction. CICFlowMeter's "
    "own 'segment size' terminology is not consistently distinguished from packet length across its published "
    "versions; this module does not invent a different formula to manufacture an artificial distinction."
)
_add("Fwd Seg Size Avg", "C", "flow", "float64", "== Fwd Pkt Len Mean (see limitation)", _SEG_SIZE_NOTE)
_add(
    "Fwd Seg Size Min", "C", "flow", "int64", "min(transport-layer header length) over forward packets",
    "CORRECTED in Feature L2.6: previously aliased to Fwd Pkt Len Min, which Feature L2.5 found matches real training data "
    "in only 2.16% of rows. Real Fwd Seg Size Min takes exactly 10 distinct values {0,8,20,24,28,32,36,40,44,48} that "
    "correlate 100% with Protocol in the training data (Protocol==17/UDP rows -> exactly 8; Protocol==0 rows -> exactly 0; "
    "Protocol==6/TCP rows -> 20 plus 4-byte steps up to 48), matching TCP/UDP transport header length rather than packet "
    "length. This is well-supported circumstantial evidence (discrete value set, exact protocol correlation, min<=mean-"
    "header-length consistency), not a byte-for-byte confirmed CICFlowMeter formula - no raw packets exist in the training "
    "CSV to directly confirm this reconstruction. See results/pcap_formula_corrections/ for the full evidence trail.",
)
_add("Bwd Seg Size Avg", "C", "flow", "float64", "== Bwd Pkt Len Mean (see limitation)", _SEG_SIZE_NOTE)

# ---------------------------------------------------------------- Category D
_SUBFLOW_NOTE = (
    "CICFlowMeter's true subflow-splitting algorithm (bulk-flow/idle-based subdivision of a single flow into "
    "multiple 'subflows') is NOT reimplemented here - published descriptions of it are inconsistent across "
    "CICFlowMeter versions and no reference implementation is available in this environment to validate "
    "against. This module reports the whole flow as a single subflow (Subflow *Pkts/Byts == Tot/TotLen *Pkts), "
    "which is a DOCUMENTED SIMPLIFICATION, not a validated reproduction of the original feature. Flows with "
    "long idle gaps are the most likely to diverge from true CICFlowMeter output for these 4 fields."
)
_add("Subflow Fwd Pkts", "D", "flow", "int64", "== Tot Fwd Pkts (single-subflow simplification)", _SUBFLOW_NOTE)
_add("Subflow Fwd Byts", "D", "flow", "int64", "== TotLen Fwd Pkts (single-subflow simplification)", _SUBFLOW_NOTE)
_add("Subflow Bwd Pkts", "D", "flow", "int64", "== Tot Bwd Pkts (single-subflow simplification)", _SUBFLOW_NOTE)
_add("Subflow Bwd Byts", "D", "flow", "int64", "== TotLen Bwd Pkts (single-subflow simplification)", _SUBFLOW_NOTE)


assert len(FEATURE_MAPPING) == 65, f"FEATURE_MAPPING has {len(FEATURE_MAPPING)} entries, expected 65."

CATEGORY_COUNTS = {cat: sum(1 for e in FEATURE_MAPPING.values() if e.category == cat) for cat in "ABCD"}


def category_of(feature: str) -> str:
    return FEATURE_MAPPING[feature].category


def features_by_category(category: str) -> list[str]:
    return [f for f, e in FEATURE_MAPPING.items() if e.category == category]


def as_report_rows() -> list[dict]:
    return [
        {
            "feature": e.feature,
            "category": e.category,
            "level": e.level,
            "dtype": e.dtype,
            "formula": e.formula,
            "training_definition_validated": e.training_definition_validated,
            "limitation": e.limitation,
        }
        for e in FEATURE_MAPPING.values()
    ]
