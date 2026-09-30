import { IconChevronRight, IconAttack, IconMitigation, IconNetwork, IconLayers, IconExplain } from "../ui/icons";
import StatusBadge from "../ui/StatusBadge";
import "./RealVerificationArchitecture.css";

const STEPS = [
  { label: "CyberChess Mitigation Decision", sub: "Policy engine output", icon: <IconAttack /> },
  { label: "Mitigation Adapter", sub: "SIMULATION ONLY", icon: <IconMitigation />, current: true },
  { label: "Real Enforcement Mechanism", sub: "Not connected", icon: <IconNetwork /> },
  { label: "Real Network Telemetry", sub: "Not connected", icon: <IconLayers /> },
  { label: "Observed Before/After State", sub: "Not measured", icon: <IconLayers /> },
  { label: "Verification Engine", sub: "This feature - currently simulation-only input", icon: <IconExplain /> },
];

export default function RealVerificationArchitecture() {
  return (
    <div className="real-verification-architecture">
      <div className="real-verification-architecture__row">
        {STEPS.map((step, i) => (
          <div className="real-verification-architecture__step-wrap" key={step.label}>
            <div className={`real-verification-architecture__step ${step.current ? "real-verification-architecture__step--current" : ""}`}>
              <span className="real-verification-architecture__icon">{step.icon}</span>
              <span className="real-verification-architecture__label">{step.label}</span>
              <span className="real-verification-architecture__sub">{step.sub}</span>
              {step.current && <StatusBadge label="SIMULATION ONLY" tone="warning" dot={false} />}
            </div>
            {i < STEPS.length - 1 && <IconChevronRight className="real-verification-architecture__arrow" />}
          </div>
        ))}
      </div>
      <p className="real-verification-architecture__note">
        Future real verification would require measured post-mitigation telemetry (real traffic/flow
        counts observed after a real enforcement action) rather than simulated arithmetic. The same{" "}
        <code>verificationEngine.ts</code> objective checks (threat suppression, legitimate-traffic
        preservation) could then run against that real data - but this feature implements only the
        simulation-input path. No firewall command, shell execution, packet manipulation, network blocking,
        router configuration, or cloud security-group change exists anywhere in this codebase.
      </p>
    </div>
  );
}
