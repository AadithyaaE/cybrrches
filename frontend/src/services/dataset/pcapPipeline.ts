/**
 * PCAP is a recognized, first-class input type in the CyberChess ingestion
 * UI, but browser-side packet parsing is NOT implemented in Feature 9. This
 * module exists only to document the intended future architecture and to
 * give the UI a typed, honest "not yet implemented" state to render -
 * nothing here fabricates packet/flow extraction.
 *
 * Future pipeline (backend, not frontend-only):
 *   PCAP file
 *     -> packet extraction (e.g. Scapy / PyShark or an equivalent library,
 *        server-side - full PCAP parsing is not practical to reimplement
 *        safely in the browser for arbitrary capture sizes)
 *     -> flow reconstruction (grouping packets into bidirectional flows,
 *        the same conceptual unit a CICFlowMeter-style CSV row represents)
 *     -> the same 65 numeric + Protocol raw-feature extraction already
 *        defined in data/cyberChessFeatureRequirements.ts
 *     -> the existing frozen CyberChess 68-dimensional state pipeline
 */

export const PCAP_SUPPORTED = false;

export const PCAP_STATUS_MESSAGE =
  "PCAP input is recognized by this interface, but packet-to-flow feature extraction requires a future backend processing stage (e.g. Scapy/PyShark). No PCAP file is parsed or processed in this feature.";

export const PCAP_FUTURE_PIPELINE_STEPS = [
  "PCAP file selected",
  "Packet extraction (future backend stage)",
  "Flow reconstruction (future backend stage)",
  "CyberChess feature extraction (reuses the same 65 numeric + Protocol requirements as CSV)",
  "68-dimensional network state S(t)",
];
