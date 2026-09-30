import DataTable, { type DataTableColumn } from "../ui/DataTable";
import type { ParsedCsvStats } from "../../types/dataset";
import "./SamplePreviewTable.css";

interface SamplePreviewTableProps {
  stats: ParsedCsvStats;
}

interface PreviewRow {
  index: number;
  cells: string[];
}

export default function SamplePreviewTable({ stats }: SamplePreviewTableProps) {
  const previewColumns = stats.header.slice(0, 8);
  const rows: PreviewRow[] = stats.previewRows.map((cells, i) => ({ index: i + 1, cells }));

  const columns: DataTableColumn<PreviewRow>[] = [
    { key: "__row", header: "#", render: (r) => r.index },
    ...previewColumns.map((col, colIdx): DataTableColumn<PreviewRow> => ({
      key: col,
      header: col,
      render: (r) => r.cells[colIdx] ?? "",
    })),
  ];

  return (
    <div className="sample-preview-table">
      <DataTable columns={columns} rows={rows} getRowKey={(r) => `row-${r.index}`} />
      <p className="sample-preview-table__note">
        Showing the first {rows.length} data rows and the first {previewColumns.length} of{" "}
        {stats.header.length} columns - a bounded preview, not the full dataset.
      </p>
    </div>
  );
}
