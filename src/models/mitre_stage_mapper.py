"""
Feature 14 - Transparent MITRE ATT&CK Stage Mapping.

A deterministic, rule-based, fully inspectable evidence engine. This is
NOT a machine-learning model: there is no fitting, no training, no
learned parameters. Every threshold and rule below is an explicit,
human-readable value.

IMPORTANT PROVENANCE NOTE: the calling feature specification instructed
this module to "reuse the existing reasoning.py implementation" and its
threshold configuration. A repository-wide search (see
evaluate_mitre_stage_mapping.py's startup log) found NO reasoning.py or
any prior threshold definitions anywhere in this project - this is a
from-scratch Python data-science pipeline (src/data, src/models) with no
existing application/reasoning layer. The Impact-stage thresholds below
are therefore defined HERE, fresh, using exactly the numeric values given
in the Feature 14 specification (packets_per_second, bytes_per_second,
connection_frequency, traffic_growth) rather than imported from a
pre-existing module that does not exist in this codebase. This is
recorded explicitly so nobody mistakes these for "re-used" values.

Data-availability caveat (see evaluate_mitre_stage_mapping.py for detail):
CSE-CIC-IDS2018's processed flow CSVs (this project's source data) never
contained source/destination IP addresses. Any stage that fundamentally
depends on host identity (Lateral Movement's "internal destination
count", parts of Initial Access) cannot be evidenced from this dataset
and is structurally limited to UNKNOWN/INSUFFICIENT_EVIDENCE here - this
is a data limitation, not a mapper defect.

Scientific framing:
    Feature 13 answers: "What is the predicted probability of the future
    state being Infiltration?"
    Feature 14 answers: "What ATT&CK stage is the observed/predicted
    network behaviour CONSISTENT WITH?" (never "which stage occurred").

Score is a "Stage Evidence Score" (0-100) - explicitly NOT a probability,
NOT model confidence, NOT an ATT&CK probability, and NOT prediction
accuracy.
"""

from dataclasses import dataclass, field

# ----------------------------------------------------------------------
# Thresholds (explicit, inspectable - never hidden inside opaque code)
# ----------------------------------------------------------------------
# Impact-stage thresholds are given verbatim by the Feature 14 spec.
IMPACT_THRESHOLDS = {
    "packets_per_second": {"normal_max": 50, "high_min": 200},
    "bytes_per_second": {"normal_max": 50000, "high_min": 500000},
    "connection_frequency": {"normal_max": 3, "high_min": 15},
    "traffic_growth_pct": {"medium_min": 50.0, "high_min": 150.0},
}

# Discovery / Reconnaissance thresholds (network-service-discovery proxies).
DISCOVERY_THRESHOLDS = {
    "dst_port_nunique_high": 10,      # distinct destination ports observed in a single 1s window
    "dst_port_nunique_medium": 5,
    "short_flow_duration_us": 1_000_000,  # 1 second, CICFlowMeter Flow Duration is in microseconds
    "min_observation_count_repeated": 5,   # flows in the window, proxy for "repeated" connections
    "low_avg_bytes_per_flow": 200,
}

# Command-and-Control thresholds (beacon-like periodicity proxy).
C2_THRESHOLDS = {
    "iat_regularity_cv_max": 0.30,   # coefficient of variation (std/mean) of inter-arrival time; low = regular/periodic
    "min_observation_count_persistent": 2,
}

# Exfiltration thresholds.
EXFIL_THRESHOLDS = {
    "high_outbound_bytes_per_s": 500_000,   # reuses the Impact "high" byte rate as an "unusually high" anchor
    "high_outbound_inbound_ratio": 10.0,
}

# Reconnaissance shares Discovery's signals but is explicitly capped lower
# (see RECON_MAX_SCORE) because flow telemetry alone cannot distinguish
# external reconnaissance from internal service discovery.
RECON_MAX_SCORE = 55

# Initial Access / Lateral Movement: minimal-to-no reliable network-only evidence available.
INITIAL_ACCESS_MAX_SCORE = 50
LATERAL_MOVEMENT_MAX_SCORE = 0  # structurally 0: no IP data available in this dataset (see module docstring)

MIN_EVIDENCE_THRESHOLD = 30  # below this, primary_stage = UNKNOWN/INSUFFICIENT_EVIDENCE

STAGES = ["Discovery", "Command and Control", "Exfiltration", "Impact", "Reconnaissance", "Initial Access", "Lateral Movement"]

TECHNIQUE_MAP = {
    "Discovery": {"technique_id": "T1046", "technique_name": "Network Service Discovery"},
    "Command and Control": {"technique_id": "T1071", "technique_name": "Application Layer Protocol (C2)"},
    "Exfiltration": {"technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel"},
    "Impact": {"technique_id": "T1498", "technique_name": "Network Denial of Service"},
    "Reconnaissance": {"technique_id": "T1595", "technique_name": "Active Scanning (candidate)"},
    "Initial Access": {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application (candidate)"},
    "Lateral Movement": {"technique_id": "T1021", "technique_name": "Remote Services (candidate)"},
}


# ----------------------------------------------------------------------
# Rule definitions - machine-readable, inspectable
# ----------------------------------------------------------------------
def build_rule_definitions() -> list:
    """Returns the complete, explicit rule table (list of dicts)."""
    return [
        {
            "rule_id": "discovery_high_port_diversity", "stage": "Discovery", "technique_id": "T1046", "technique_name": "Network Service Discovery",
            "conditions": [f"dst_port_nunique >= {DISCOVERY_THRESHOLDS['dst_port_nunique_high']}"],
            "supporting_features": ["dst_port_nunique"], "score_contribution": 40,
            "explanation": "A high number of distinct destination ports contacted within a single 1-second window is consistent with network service discovery.",
            "limitation": "Flow telemetry cannot independently establish attacker intent; high port diversity can also occur from legitimate multi-service clients.",
        },
        {
            "rule_id": "discovery_repeated_short_flows", "stage": "Discovery", "technique_id": "T1046", "technique_name": "Network Service Discovery",
            "conditions": [f"observation_count >= {DISCOVERY_THRESHOLDS['min_observation_count_repeated']}",
                           f"flow_duration_mean_us <= {DISCOVERY_THRESHOLDS['short_flow_duration_us']}"],
            "supporting_features": ["observation_count", "Flow Duration"], "score_contribution": 30,
            "explanation": "Repeated short-duration connections across multiple destination ports are consistent with network service discovery.",
            "limitation": "Short flows can also result from normal application behaviour (e.g. health checks, keep-alives).",
        },
        {
            "rule_id": "discovery_low_bytes_per_flow", "stage": "Discovery", "technique_id": "T1046", "technique_name": "Network Service Discovery",
            "conditions": [f"avg_bytes_per_flow <= {DISCOVERY_THRESHOLDS['low_avg_bytes_per_flow']}"],
            "supporting_features": ["TotLen Fwd Pkts", "observation_count"], "score_contribution": 15,
            "explanation": "Low bytes transferred per flow is consistent with probing rather than substantive data transfer.",
            "limitation": "Low-byte flows are common in many benign protocols (DNS, health checks); this is weak supporting evidence only.",
        },
        {
            "rule_id": "c2_regular_beacon_timing", "stage": "Command and Control", "technique_id": "T1071", "technique_name": "Application Layer Protocol (C2)",
            "conditions": [f"flow_iat_coefficient_of_variation <= {C2_THRESHOLDS['iat_regularity_cv_max']}"],
            "supporting_features": ["Flow IAT Mean", "Flow IAT Std"], "score_contribution": 35,
            "explanation": "Relatively regular inter-arrival timing (low variability) is consistent with beacon-like command-and-control traffic.",
            "limitation": "Cannot confirm a specific T1071 sub-technique or a repeated destination, because source/destination IP is not present in this dataset; regular timing alone can also reflect legitimate polling/heartbeat traffic.",
        },
        {
            "rule_id": "c2_persistent_bidirectional_traffic", "stage": "Command and Control", "technique_id": "T1071", "technique_name": "Application Layer Protocol (C2)",
            "conditions": ["Tot Fwd Pkts > 0", "Tot Bwd Pkts > 0", f"observation_count >= {C2_THRESHOLDS['min_observation_count_persistent']}"],
            "supporting_features": ["Tot Fwd Pkts", "Tot Bwd Pkts", "observation_count"], "score_contribution": 25,
            "explanation": "Persistent, bidirectional communication is consistent with an established command-and-control channel.",
            "limitation": "Bidirectional traffic is the norm for almost all legitimate TCP sessions; only meaningful in combination with regular timing.",
        },
        {
            "rule_id": "exfil_high_outbound_volume", "stage": "Exfiltration", "technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel",
            "conditions": [f"flow_byts_per_s >= {EXFIL_THRESHOLDS['high_outbound_bytes_per_s']}"],
            "supporting_features": ["Flow Byts/s"], "score_contribution": 40,
            "explanation": "Unusually high outbound transfer volume relative to typical flow rates is consistent with possible data exfiltration.",
            "limitation": "High-throughput legitimate transfers (backups, large downloads) produce the same signature; data content/destination cannot be verified.",
        },
        {
            "rule_id": "exfil_high_outbound_inbound_ratio", "stage": "Exfiltration", "technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel",
            "conditions": [f"outbound_inbound_byte_ratio >= {EXFIL_THRESHOLDS['high_outbound_inbound_ratio']}"],
            "supporting_features": ["TotLen Fwd Pkts", "TotLen Bwd Pkts"], "score_contribution": 35,
            "explanation": "The flow shows unusually large outbound transfer volume relative to inbound traffic, which is consistent with possible data exfiltration.",
            "limitation": "Never claims that data was actually exfiltrated; asymmetric flows are also produced by e.g. uploads, backups, telemetry.",
        },
        {
            "rule_id": "impact_high_rate_and_growth", "stage": "Impact", "technique_id": "T1498", "technique_name": "Network Denial of Service",
            "conditions": [f"flow_pkts_per_s >= {IMPACT_THRESHOLDS['packets_per_second']['high_min']}",
                           f"traffic_growth_pct >= {IMPACT_THRESHOLDS['traffic_growth_pct']['high_min']}"],
            "supporting_features": ["Flow Pkts/s", "traffic_growth_pct"], "score_contribution": 50,
            "explanation": "Traffic volume and growth indicate a network availability-disruption pattern consistent with Network Denial of Service.",
            "limitation": "Interpretable evidence only; does not override Random Forest, LSTM, or Feature 13 predictions.",
        },
        {
            "rule_id": "impact_elevated_volume_or_frequency", "stage": "Impact", "technique_id": "T1498", "technique_name": "Network Denial of Service",
            "conditions": [f"flow_pkts_per_s >= {IMPACT_THRESHOLDS['packets_per_second']['high_min']}",
                           f"OR flow_byts_per_s >= {IMPACT_THRESHOLDS['bytes_per_second']['high_min']}",
                           f"OR connection_frequency >= {IMPACT_THRESHOLDS['connection_frequency']['high_min']}"],
            "supporting_features": ["Flow Pkts/s", "Flow Byts/s", "observation_count"], "score_contribution": 30,
            "explanation": "Elevated packet rate, byte rate, or connection frequency (any one) is consistent with a network-availability-disruption pattern.",
            "limitation": "Interpretable evidence only; a single elevated metric does not confirm an active DoS condition.",
        },
        {
            "rule_id": "recon_port_scanning_pattern", "stage": "Reconnaissance", "technique_id": "T1595", "technique_name": "Active Scanning (candidate)",
            "conditions": [f"dst_port_nunique >= {DISCOVERY_THRESHOLDS['dst_port_nunique_medium']}",
                           f"flow_duration_mean_us <= {DISCOVERY_THRESHOLDS['short_flow_duration_us']}"],
            "supporting_features": ["dst_port_nunique", "Flow Duration"], "score_contribution": 45,
            "explanation": "The observed network probing behaviour is consistent with reconnaissance activity, but the available flow telemetry cannot establish attacker intent.",
            "limitation": (
                f"CANDIDATE mapping only, score capped at {RECON_MAX_SCORE}/100: the flow dataset cannot "
                "reliably distinguish external reconnaissance from internal discovery."
            ),
        },
        {
            "rule_id": "initial_access_suspicious_connection_pattern", "stage": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application (candidate)",
            "conditions": ["SYN Flag Cnt > 0", "ACK Flag Cnt < SYN Flag Cnt"],
            "supporting_features": ["SYN Flag Cnt", "ACK Flag Cnt"], "score_contribution": 40,
            "explanation": "The observed traffic is consistent with an attempted network-entry pattern (connection attempts without full handshake completion), but flow telemetry alone cannot confirm successful compromise.",
            "limitation": (
                f"CANDIDATE mapping only, score capped at {INITIAL_ACCESS_MAX_SCORE}/100: no process, "
                "authentication, or host telemetry is available in this dataset; successful Initial Access "
                "can never be confirmed from flow data alone."
            ),
        },
        {
            "rule_id": "lateral_movement_internal_destination_count", "stage": "Lateral Movement", "technique_id": "T1021", "technique_name": "Remote Services (candidate)",
            "conditions": ["NOT COMPUTABLE: requires source/destination IP addresses, which are absent from this dataset"],
            "supporting_features": [], "score_contribution": 0,
            "explanation": "Lateral movement evidence requires tracking one source contacting multiple internal destinations, which requires IP-address identity information.",
            "limitation": (
                "STRUCTURALLY UNAVAILABLE for this dataset: CSE-CIC-IDS2018's processed flow CSVs do not "
                "include source or destination IP addresses. This rule can never fire on this data; Lateral "
                "Movement will always report UNKNOWN/INSUFFICIENT_EVIDENCE here. This is a data limitation, "
                "not a mapper defect."
            ),
        },
    ]


RULE_DEFINITIONS = build_rule_definitions()


def evidence_label(score: float) -> str:
    if score < 30:
        return "LOW"
    if score < 60:
        return "MEDIUM"
    if score < 80:
        return "HIGH"
    return "VERY HIGH"


def _safe_div(a, b, default=0.0):
    return a / b if b not in (0, None) and a is not None else default


@dataclass
class StageResult:
    stage: str
    technique_id: str
    technique_name: str
    evidence_score: float
    evidence_label: str
    triggered_rules: list = field(default_factory=list)
    supporting_features: list = field(default_factory=list)
    explanations: list = field(default_factory=list)
    limitations: list = field(default_factory=list)


def evaluate_rules(evidence: dict) -> dict:
    """
    Pure, deterministic function: evidence dict -> {stage_name: StageResult}.

    `evidence` must contain (None allowed for genuinely unavailable fields):
        dst_port_nunique, flow_duration_mean_us, observation_count,
        avg_bytes_per_flow, flow_iat_coefficient_of_variation,
        tot_fwd_pkts, tot_bwd_pkts, flow_byts_per_s, flow_pkts_per_s,
        outbound_inbound_byte_ratio, traffic_growth_pct,
        connection_frequency, syn_flag_cnt, ack_flag_cnt
    """
    results = {}

    # --- Discovery ---
    triggered, feats, expl, lim, score = [], set(), [], [], 0.0
    for rule in RULE_DEFINITIONS:
        if rule["stage"] != "Discovery":
            continue
        fired = False
        if rule["rule_id"] == "discovery_high_port_diversity":
            v = evidence.get("dst_port_nunique")
            fired = v is not None and v >= DISCOVERY_THRESHOLDS["dst_port_nunique_high"]
        elif rule["rule_id"] == "discovery_repeated_short_flows":
            oc, fd = evidence.get("observation_count"), evidence.get("flow_duration_mean_us")
            fired = (oc is not None and fd is not None
                     and oc >= DISCOVERY_THRESHOLDS["min_observation_count_repeated"]
                     and fd <= DISCOVERY_THRESHOLDS["short_flow_duration_us"])
        elif rule["rule_id"] == "discovery_low_bytes_per_flow":
            v = evidence.get("avg_bytes_per_flow")
            fired = v is not None and v <= DISCOVERY_THRESHOLDS["low_avg_bytes_per_flow"]
        if fired:
            triggered.append(rule["rule_id"]); feats.update(rule["supporting_features"])
            expl.append(rule["explanation"]); lim.append(rule["limitation"]); score += rule["score_contribution"]
    score = min(score, 100.0)
    results["Discovery"] = StageResult("Discovery", *TECHNIQUE_MAP["Discovery"].values(), score, evidence_label(score), triggered, sorted(feats), expl, lim)

    # --- Command and Control ---
    triggered, feats, expl, lim, score = [], set(), [], [], 0.0
    for rule in RULE_DEFINITIONS:
        if rule["stage"] != "Command and Control":
            continue
        fired = False
        if rule["rule_id"] == "c2_regular_beacon_timing":
            cv = evidence.get("flow_iat_coefficient_of_variation")
            fired = cv is not None and cv <= C2_THRESHOLDS["iat_regularity_cv_max"]
        elif rule["rule_id"] == "c2_persistent_bidirectional_traffic":
            fwd, bwd, oc = evidence.get("tot_fwd_pkts"), evidence.get("tot_bwd_pkts"), evidence.get("observation_count")
            fired = (fwd is not None and bwd is not None and oc is not None
                     and fwd > 0 and bwd > 0 and oc >= C2_THRESHOLDS["min_observation_count_persistent"])
        if fired:
            triggered.append(rule["rule_id"]); feats.update(rule["supporting_features"])
            expl.append(rule["explanation"]); lim.append(rule["limitation"]); score += rule["score_contribution"]
    score = min(score, 100.0)
    results["Command and Control"] = StageResult("Command and Control", *TECHNIQUE_MAP["Command and Control"].values(), score, evidence_label(score), triggered, sorted(feats), expl, lim)

    # --- Exfiltration ---
    triggered, feats, expl, lim, score = [], set(), [], [], 0.0
    for rule in RULE_DEFINITIONS:
        if rule["stage"] != "Exfiltration":
            continue
        fired = False
        if rule["rule_id"] == "exfil_high_outbound_volume":
            v = evidence.get("flow_byts_per_s")
            fired = v is not None and v >= EXFIL_THRESHOLDS["high_outbound_bytes_per_s"]
        elif rule["rule_id"] == "exfil_high_outbound_inbound_ratio":
            v = evidence.get("outbound_inbound_byte_ratio")
            fired = v is not None and v >= EXFIL_THRESHOLDS["high_outbound_inbound_ratio"]
        if fired:
            triggered.append(rule["rule_id"]); feats.update(rule["supporting_features"])
            expl.append(rule["explanation"]); lim.append(rule["limitation"]); score += rule["score_contribution"]
    score = min(score, 100.0)
    results["Exfiltration"] = StageResult("Exfiltration", *TECHNIQUE_MAP["Exfiltration"].values(), score, evidence_label(score), triggered, sorted(feats), expl, lim)

    # --- Impact ---
    triggered, feats, expl, lim, score = [], set(), [], [], 0.0
    for rule in RULE_DEFINITIONS:
        if rule["stage"] != "Impact":
            continue
        fired = False
        pkts, byts = evidence.get("flow_pkts_per_s"), evidence.get("flow_byts_per_s")
        growth, conn_freq = evidence.get("traffic_growth_pct"), evidence.get("connection_frequency")
        if rule["rule_id"] == "impact_high_rate_and_growth":
            fired = (pkts is not None and growth is not None
                     and pkts >= IMPACT_THRESHOLDS["packets_per_second"]["high_min"]
                     and growth >= IMPACT_THRESHOLDS["traffic_growth_pct"]["high_min"])
        elif rule["rule_id"] == "impact_elevated_volume_or_frequency":
            fired = (
                (pkts is not None and pkts >= IMPACT_THRESHOLDS["packets_per_second"]["high_min"])
                or (byts is not None and byts >= IMPACT_THRESHOLDS["bytes_per_second"]["high_min"])
                or (conn_freq is not None and conn_freq >= IMPACT_THRESHOLDS["connection_frequency"]["high_min"])
            )
        if fired:
            triggered.append(rule["rule_id"]); feats.update(rule["supporting_features"])
            expl.append(rule["explanation"]); lim.append(rule["limitation"]); score += rule["score_contribution"]
    score = min(score, 100.0)
    results["Impact"] = StageResult("Impact", *TECHNIQUE_MAP["Impact"].values(), score, evidence_label(score), triggered, sorted(feats), expl, lim)

    # --- Reconnaissance (candidate, capped) ---
    triggered, feats, expl, lim, score = [], set(), [], [], 0.0
    for rule in RULE_DEFINITIONS:
        if rule["stage"] != "Reconnaissance":
            continue
        v, fd = evidence.get("dst_port_nunique"), evidence.get("flow_duration_mean_us")
        fired = (v is not None and fd is not None
                 and v >= DISCOVERY_THRESHOLDS["dst_port_nunique_medium"]
                 and fd <= DISCOVERY_THRESHOLDS["short_flow_duration_us"])
        if fired:
            triggered.append(rule["rule_id"]); feats.update(rule["supporting_features"])
            expl.append(rule["explanation"]); lim.append(rule["limitation"]); score += rule["score_contribution"]
    score = min(score, RECON_MAX_SCORE)
    results["Reconnaissance"] = StageResult("Reconnaissance", *TECHNIQUE_MAP["Reconnaissance"].values(), score, evidence_label(score), triggered, sorted(feats), expl, lim)

    # --- Initial Access (candidate, capped) ---
    triggered, feats, expl, lim, score = [], set(), [], [], 0.0
    for rule in RULE_DEFINITIONS:
        if rule["stage"] != "Initial Access":
            continue
        syn, ack = evidence.get("syn_flag_cnt"), evidence.get("ack_flag_cnt")
        fired = syn is not None and ack is not None and syn > 0 and ack < syn
        if fired:
            triggered.append(rule["rule_id"]); feats.update(rule["supporting_features"])
            expl.append(rule["explanation"]); lim.append(rule["limitation"]); score += rule["score_contribution"]
    score = min(score, INITIAL_ACCESS_MAX_SCORE)
    results["Initial Access"] = StageResult("Initial Access", *TECHNIQUE_MAP["Initial Access"].values(), score, evidence_label(score), triggered, sorted(feats), expl, lim)

    # --- Lateral Movement (structurally unavailable for this dataset) ---
    lm_rule = next(r for r in RULE_DEFINITIONS if r["stage"] == "Lateral Movement")
    results["Lateral Movement"] = StageResult(
        "Lateral Movement", *TECHNIQUE_MAP["Lateral Movement"].values(), 0.0, evidence_label(0.0),
        [], [], [], [lm_rule["limitation"]],
    )

    return results


def select_primary_stage(stage_results: dict, min_threshold: float = MIN_EVIDENCE_THRESHOLD) -> str:
    best_stage, best_score = None, -1.0
    for name, r in stage_results.items():
        if r.evidence_score > best_score:
            best_stage, best_score = name, r.evidence_score
    if best_score < min_threshold:
        return "UNKNOWN / INSUFFICIENT_EVIDENCE"
    return best_stage


def build_audit_record(window_identifier, stage_results: dict, feature13_probability=None) -> dict:
    primary = select_primary_stage(stage_results)
    return {
        "window_identifier": window_identifier,
        "primary_stage": primary,
        "feature13_attack_probability": feature13_probability,
        "stages": {
            name: {
                "technique_id": r.technique_id, "technique_name": r.technique_name,
                "evidence_score": round(r.evidence_score, 2), "evidence_label": r.evidence_label,
                "triggered_rules": r.triggered_rules, "supporting_features": r.supporting_features,
                "explanation": " ".join(r.explanations) if r.explanations else "Insufficient evidence for this stage.",
                "limitation": " ".join(sorted(set(r.limitations))) if r.limitations else "",
                "is_primary": name == primary,
            }
            for name, r in stage_results.items()
        },
    }
