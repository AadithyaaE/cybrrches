import DataTable, { type DataTableColumn } from "../ui/DataTable";
import StatusBadge from "../ui/StatusBadge";
import type { HorizonOutlierDiagnostic } from "../../data/lstmWorldModelData";
import "./OutlierCaveat.css";

interface OutlierCaveatProps {
  diagnostics: HorizonOutlierDiagnostic[];
}

export default function OutlierCaveat({ diagnostics }: OutlierCaveatProps) {
  const columns: DataTableColumn<HorizonOutlierDiagnostic>[] = [
    { key: "horizon", header: "Horizon", render: (r) => `K=${r.horizon}` },
    { key: "officialMse", header: "Official Test MSE (all samples)", align: "right", render: (r) => r.officialMse.toFixed(3) },
    { key: "diagnostic", header: "MSE Excluding Worst Sample", align: "right", render: (r) => r.diagnosticMseExcludingWorstSample.toFixed(3) },
    { key: "dominantFeature", header: "Dominant Feature", render: (r) => r.dominantFeature },
    { key: "worstSampleMse", header: "Worst Sample MSE", align: "right", render: (r) => r.worstSampleMse.toLocaleString(undefined, { maximumFractionDigits: 1 }) },
  ];

  return (
    <div className="outlier-caveat">
      <div className="outlier-caveat__banner">
        <StatusBadge label="Known Outlier" tone="warning" />
        <p>
          The official test MSE at every horizon is strongly influenced by a single extreme <strong>Pkt Len Var</strong> outlier
          in the test rollout (test sequence around id 19,838-19,842 depending on horizon). Its actual scaled value
          (~1874) falls far outside anything the model's scaler ever saw during training (train range approximately
          [-1.12, 11.80]) - a genuine out-of-distribution event, not a data or code bug.
        </p>
      </div>
      <DataTable columns={columns} rows={diagnostics} getRowKey={(r) => `${r.horizon}`} />
      <p className="outlier-caveat__note">
        Excluding this one sample, test MSE at every horizon drops to roughly 0.72-0.77 - close to the
        validation MSE. <strong>MAE remains comparatively stable</strong> across this outlier (MAE is far less
        sensitive to a single extreme squared error than MSE is), so the RMSE/MSE figures above should be read
        alongside MAE, not in isolation. This limitation is disclosed here rather than hidden.
      </p>
    </div>
  );
}
