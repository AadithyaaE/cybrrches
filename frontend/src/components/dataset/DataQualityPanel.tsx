import StatusBadge from "../ui/StatusBadge";
import type { ParsedCsvStats } from "../../types/dataset";
import "./DataQualityPanel.css";

interface DataQualityPanelProps {
  stats: ParsedCsvStats;
}

export default function DataQualityPanel({ stats }: DataQualityPanelProps) {
  const missingEntries = Object.entries(stats.missingValueCounts).filter(([, count]) => count > 0);
  const numericIssueEntries = Object.entries(stats.numericIssueCounts).filter(([, count]) => count > 0);

  return (
    <div className="data-quality-panel">
      {stats.fileTooLargeForFullScan && (
        <div className="data-quality-panel__notice">
          <StatusBadge label="Large File" tone="warning" />
          <p>
            This file is {(stats.totalBytes / (1024 * 1024)).toFixed(1)} MB. To keep the browser responsive,
            detailed per-row statistics below were computed on the first{" "}
            {stats.detailedStatsRowCount.toLocaleString()} rows only (exact row count and header were still
            computed for the full file).
          </p>
        </div>
      )}
      {stats.detailedStatsCapped && !stats.fileTooLargeForFullScan && (
        <div className="data-quality-panel__notice">
          <StatusBadge label="Stats Capped" tone="warning" />
          <p>
            This file has more than {stats.detailedStatsRowCount.toLocaleString()} rows. Detailed per-row
            statistics were computed on the first {stats.detailedStatsRowCount.toLocaleString()} rows only.
          </p>
        </div>
      )}

      <div className="data-quality-panel__grid">
        <div className="data-quality-panel__stat">
          <span className="data-quality-panel__stat-label">Duplicate Rows</span>
          <span className="data-quality-panel__stat-value">{stats.duplicateRowCount.toLocaleString()}</span>
          {stats.duplicateCheckCapped && (
            <span className="data-quality-panel__stat-caveat">
              Checked on the first {stats.duplicateCheckRowLimit.toLocaleString()} rows only.
            </span>
          )}
        </div>
        <div className="data-quality-panel__stat">
          <span className="data-quality-panel__stat-label">Malformed Rows</span>
          <span className="data-quality-panel__stat-value">{stats.malformedRowCount.toLocaleString()}</span>
          <span className="data-quality-panel__stat-caveat">Rows whose field count didn't match the header.</span>
        </div>
        <div className="data-quality-panel__stat">
          <span className="data-quality-panel__stat-label">Timestamp Column</span>
          <span className="data-quality-panel__stat-value">{stats.hasTimestampColumn ? "Present" : "Absent"}</span>
        </div>
      </div>

      <div className="data-quality-panel__section">
        <h4>Missing Values (required columns only)</h4>
        {missingEntries.length === 0 ? (
          <p className="data-quality-panel__ok">No missing values found in any required column (within the scanned rows).</p>
        ) : (
          <ul className="data-quality-panel__list">
            {missingEntries.map(([col, count]) => (
              <li key={col}>
                <span className="data-quality-panel__col">{col}</span>: {count.toLocaleString()} missing
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="data-quality-panel__section">
        <h4>Numeric Conversion Issues (required numeric columns only)</h4>
        {numericIssueEntries.length === 0 ? (
          <p className="data-quality-panel__ok">No non-numeric values found in any required numeric column (within the scanned rows).</p>
        ) : (
          <ul className="data-quality-panel__list">
            {numericIssueEntries.map(([col, count]) => (
              <li key={col}>
                <span className="data-quality-panel__col">{col}</span>: {count.toLocaleString()} non-numeric value(s)
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
