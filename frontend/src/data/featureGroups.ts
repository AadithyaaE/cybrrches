/**
 * Presentation-only grouping of the 68 real S(t) feature names (from
 * results/state_schema.json) into CICFlowMeter-style categories, to make the
 * Feature View easier to scan. This grouping is a UI organization choice,
 * not a research finding - the feature names and values themselves are
 * unmodified and traceable back to the original schema.
 */

export interface FeatureGroup {
  title: string;
  features: string[];
}

export const FEATURE_GROUPS: FeatureGroup[] = [
  {
    title: "Flow Duration",
    features: ["Flow Duration"],
  },
  {
    title: "Packet Counts",
    features: ["Tot Fwd Pkts", "Tot Bwd Pkts", "Fwd Act Data Pkts", "Down/Up Ratio", "Subflow Fwd Pkts", "Subflow Bwd Pkts"],
  },
  {
    title: "Packet Length & Size",
    features: [
      "Fwd Pkt Len Max", "Fwd Pkt Len Mean", "Fwd Pkt Len Min", "Fwd Pkt Len Std",
      "Bwd Pkt Len Max", "Bwd Pkt Len Mean", "Bwd Pkt Len Min", "Bwd Pkt Len Std",
      "Pkt Len Max", "Pkt Len Mean", "Pkt Len Min", "Pkt Len Std", "Pkt Len Var", "Pkt Size Avg",
      "Fwd Seg Size Avg", "Fwd Seg Size Min", "Bwd Seg Size Avg",
      "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Subflow Fwd Byts", "Subflow Bwd Byts",
    ],
  },
  {
    title: "Throughput / Rate",
    features: ["Flow Byts/s", "Flow Pkts/s", "Fwd Pkts/s", "Bwd Pkts/s"],
  },
  {
    title: "Inter-Arrival Time (IAT)",
    features: [
      "Flow IAT Mean", "Flow IAT Max", "Flow IAT Min", "Flow IAT Std",
      "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Max", "Fwd IAT Min", "Fwd IAT Std",
      "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Max", "Bwd IAT Min", "Bwd IAT Std",
    ],
  },
  {
    title: "TCP Flags",
    features: ["Fwd PSH Flags", "ACK Flag Cnt", "PSH Flag Cnt", "RST Flag Cnt", "SYN Flag Cnt", "URG Flag Cnt", "ECE Flag Cnt"],
  },
  {
    title: "Header / Window",
    features: ["Fwd Header Len", "Bwd Header Len", "Init Fwd Win Byts", "Init Bwd Win Byts"],
  },
  {
    title: "Activity / Idle",
    features: ["Active Max", "Active Mean", "Active Min", "Active Std", "Idle Max", "Idle Mean", "Idle Min", "Idle Std"],
  },
  {
    title: "Protocol",
    features: ["Protocol_0", "Protocol_6", "Protocol_17"],
  },
];
