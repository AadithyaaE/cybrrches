import StatusBadge from "../ui/StatusBadge";
import "./MitigationHeader.css";

export default function MitigationHeader() {
  return (
    <div className="mitigation-header">
      <div className="mitigation-header__mode">
        <StatusBadge label="Mode: Simulation" tone="warning" />
        <StatusBadge label="No Real Firewall/Network Changes" tone="info" dot={false} />
      </div>
      <p className="mitigation-header__notice">
        <strong>SIMULATION — no real firewall/network changes are being made.</strong> This page runs a
        deterministic mitigation policy engine and a controlled, arithmetic-only simulation of what a
        mitigation action would look like. No shell command, firewall rule, routing change, or packet
        injection is ever executed by this feature.
      </p>
    </div>
  );
}
