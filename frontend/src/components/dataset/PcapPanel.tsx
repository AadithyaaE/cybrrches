import { IconChevronRight } from "../ui/icons";
import StatusBadge from "../ui/StatusBadge";
import { PCAP_STATUS_MESSAGE, PCAP_FUTURE_PIPELINE_STEPS } from "../../services/dataset/pcapPipeline";
import "./PcapPanel.css";

export default function PcapPanel() {
  return (
    <div className="pcap-panel">
      <div className="pcap-panel__banner">
        <StatusBadge label="Not Implemented" tone="warning" />
        <p>{PCAP_STATUS_MESSAGE}</p>
      </div>
      <div className="pcap-panel__flow">
        {PCAP_FUTURE_PIPELINE_STEPS.map((step, i) => (
          <div className="pcap-panel__step-wrap" key={step}>
            <div className={`pcap-panel__step ${i === 0 ? "pcap-panel__step--current" : ""}`}>{step}</div>
            {i < PCAP_FUTURE_PIPELINE_STEPS.length - 1 && <IconChevronRight className="pcap-panel__arrow" />}
          </div>
        ))}
      </div>
    </div>
  );
}
