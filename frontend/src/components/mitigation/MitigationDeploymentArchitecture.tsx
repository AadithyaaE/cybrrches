import { IconChevronRight, IconAttack, IconMitigation, IconNetwork, IconResearch } from "../ui/icons";
import StatusBadge from "../ui/StatusBadge";
import "./MitigationDeploymentArchitecture.css";

const STEPS = [
  { label: "CyberChess Decision", sub: "Policy engine output", icon: <IconAttack /> },
  { label: "Mitigation Adapter", sub: "SIMULATION ONLY", icon: <IconMitigation />, current: true },
  { label: "Approved Enforcement Mechanism", sub: "Not connected", icon: <IconNetwork /> },
  { label: "Verification", sub: "Simulation verification only", icon: <IconResearch /> },
];

export default function MitigationDeploymentArchitecture() {
  return (
    <div className="mitigation-deployment-architecture">
      <div className="mitigation-deployment-architecture__row">
        {STEPS.map((step, i) => (
          <div className="mitigation-deployment-architecture__step-wrap" key={step.label}>
            <div className={`mitigation-deployment-architecture__step ${step.current ? "mitigation-deployment-architecture__step--current" : ""}`}>
              <span className="mitigation-deployment-architecture__icon">{step.icon}</span>
              <span className="mitigation-deployment-architecture__label">{step.label}</span>
              <span className="mitigation-deployment-architecture__sub">{step.sub}</span>
              {step.current && <StatusBadge label="SIMULATION ONLY" tone="warning" dot={false} />}
            </div>
            {i < STEPS.length - 1 && <IconChevronRight className="mitigation-deployment-architecture__arrow" />}
          </div>
        ))}
      </div>
      <p className="mitigation-deployment-architecture__note">
        This feature implements only the Mitigation Adapter's decision/simulation logic. It is{" "}
        <strong>not connected</strong> to a Windows firewall, Linux iptables/nftables, cloud security groups,
        routers, or any real production network. No destructive command of any kind is issued anywhere in
        this codebase.
      </p>
    </div>
  );
}
