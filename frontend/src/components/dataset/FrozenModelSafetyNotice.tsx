import { IconChevronRight } from "../ui/icons";
import StatusBadge from "../ui/StatusBadge";
import "./FrozenModelSafetyNotice.css";

const UPLOAD_FLOW = ["Uploaded Dataset", "Inspect", "Validate", "Prepare", "Ready for Inference"];

export default function FrozenModelSafetyNotice() {
  return (
    <div className="frozen-model-safety-notice">
      <div className="frozen-model-safety-notice__banner">
        <StatusBadge label="Frozen Model Safety" tone="info" />
        <p>
          Dataset upload does not retrain, tune, overwrite, or modify the frozen CyberChess research
          models. No model fitting happens anywhere in this feature.
        </p>
      </div>

      <div className="frozen-model-safety-notice__compare">
        <div className="frozen-model-safety-notice__col">
          <span className="frozen-model-safety-notice__col-title">This Upload</span>
          <div className="frozen-model-safety-notice__flow">
            {UPLOAD_FLOW.map((step, i) => (
              <span key={step} className="frozen-model-safety-notice__flow-item">
                {step}
                {i < UPLOAD_FLOW.length - 1 && <IconChevronRight className="frozen-model-safety-notice__flow-arrow" />}
              </span>
            ))}
          </div>
        </div>
        <div className="frozen-model-safety-notice__col frozen-model-safety-notice__col--frozen">
          <span className="frozen-model-safety-notice__col-title">Features 1-16 Research Artifacts</span>
          <p className="frozen-model-safety-notice__frozen-text">remain frozen and unchanged</p>
        </div>
      </div>
    </div>
  );
}
