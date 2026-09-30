import MetricCard from "../ui/MetricCard";
import { IconDatasets, IconClock, IconLayers, IconNetwork } from "../ui/icons";
import type { DatasetFileInfo, ParsedCsvStats } from "../../types/dataset";
import "./DatasetSummaryCard.css";

interface DatasetSummaryCardProps {
  fileInfo: DatasetFileInfo;
  stats: ParsedCsvStats;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export default function DatasetSummaryCard({ fileInfo, stats }: DatasetSummaryCardProps) {
  return (
    <div className="dataset-summary-card">
      <div className="dataset-summary-card__grid">
        <MetricCard
          eyebrow="Filename"
          value={fileInfo.filename}
          detail={formatBytes(fileInfo.fileSizeBytes)}
          statusLabel={fileInfo.fileType.toUpperCase()}
          statusTone="info"
          accent="cyan"
          icon={<IconDatasets />}
        />
        <MetricCard
          eyebrow="Rows"
          value={stats.rowCount.toLocaleString()}
          detail={stats.rowCountExact ? "Exact count" : "Estimated"}
          statusLabel={stats.detailedStatsCapped ? "Stats Capped" : "Full Scan"}
          statusTone={stats.detailedStatsCapped ? "warning" : "success"}
          accent="violet"
          icon={<IconLayers />}
        />
        <MetricCard
          eyebrow="Columns"
          value={stats.columnCount.toString()}
          detail="Raw CSV header columns"
          statusLabel="Detected"
          statusTone="success"
          accent="cyan"
          icon={<IconNetwork />}
        />
        <MetricCard
          eyebrow="Timestamp / Label"
          value={stats.hasTimestampColumn ? "Timestamp present" : "No Timestamp"}
          detail={stats.hasLabelColumn ? `Label present (${stats.detectedLabels.length} class${stats.detectedLabels.length === 1 ? "" : "es"} seen)` : "No Label column"}
          statusLabel={stats.hasTimestampColumn ? "Ready" : "Missing"}
          statusTone={stats.hasTimestampColumn ? "success" : "warning"}
          accent="violet"
          icon={<IconClock />}
        />
      </div>
      {stats.detectedLabels.length > 0 && (
        <p className="dataset-summary-card__labels">
          Detected labels: {stats.detectedLabels.join(", ")}
          {stats.labelDetectionCapped ? " (based on rows scanned; more distinct values may exist)" : ""}
        </p>
      )}
    </div>
  );
}
