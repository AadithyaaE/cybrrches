import {
  REQUIRED_NUMERIC_FEATURES,
  PROTOCOL_RAW_COLUMN,
  TIMESTAMP_COLUMN,
  LABEL_COLUMN,
  DST_PORT_COLUMN,
} from "../../data/cyberChessFeatureRequirements";
import type { ParsedCsvStats, CsvParseError } from "../../types/dataset";

/**
 * Browser-side, streaming CSV inspection engine. Never loads the whole file
 * into memory as one string/array - it reads the File in chunks
 * (File.stream()), buffers only the current partial line across chunk
 * boundaries, and accumulates bounded counters/samples as it goes.
 *
 * Known limitation (documented, not silently ignored): the line splitter
 * does not handle quoted fields containing embedded newlines. CICFlowMeter-
 * style CSVs (the target schema family) do not use this pattern.
 */

const HARD_BYTE_LIMIT = 500 * 1024 * 1024; // 500 MB: above this, no scanning at all
const LARGE_FILE_BYTE_THRESHOLD = 50 * 1024 * 1024; // 50 MB: above this, UI flags the file as "large" (caps below still apply regardless of size)
const DETAILED_STATS_ROW_CAP = 300_000; // missing-value / numeric-issue / label counters stop updating after this many data rows
const DUPLICATE_ROW_CAP = 150_000; // duplicate-hash Set stops growing after this many data rows
const PREVIEW_ROW_CAP = 20;
const DETECTED_LABELS_CAP = 50;

function splitCsvLine(line: string): string[] {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        current += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      fields.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}

// cyrb53 - fast, well-distributed non-cryptographic string hash, used only for bounded duplicate-row detection.
function hashRow(row: string): number {
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < row.length; i++) {
    const ch = row.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

function isNumericCell(value: string): boolean {
  if (value.trim() === "") return true; // empty is a "missing value", not a "numeric issue" - counted separately
  return Number.isFinite(Number(value));
}

export async function parseCsvFile(file: File): Promise<{ stats: ParsedCsvStats } | { error: CsvParseError }> {
  if (file.size === 0) {
    return { error: { code: "EMPTY_FILE", message: "The selected file is empty (0 bytes)." } };
  }
  if (file.size > HARD_BYTE_LIMIT) {
    return {
      error: {
        code: "READ_ERROR",
        message: `This file is ${(file.size / (1024 * 1024)).toFixed(0)} MB, above the ${(HARD_BYTE_LIMIT / (1024 * 1024)).toFixed(0)} MB limit this browser-side inspector supports. It was not read.`,
      },
    };
  }

  let header: string[] | null = null;
  let columnCount = 0;
  const previewRows: string[][] = [];
  const missingValueCounts: Record<string, number> = {};
  const numericIssueCounts: Record<string, number> = {};
  const seenHashes = new Set<number>();
  let duplicateRowCount = 0;
  let duplicateCheckCapped = false;
  let malformedRowCount = 0;
  let rowCount = 0;
  let detailedStatsRowCount = 0;
  let detailedStatsCapped = false;
  const detectedLabelsSet = new Set<string>();
  let labelDetectionCapped = false;

  let trackedColumns: string[] = [];
  let labelColumnIndex = -1;

  const reader = file.stream().getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";

  function processLine(line: string) {
    if (line === "") return;

    if (header === null) {
      header = splitCsvLine(line).map((c) => c.trim());
      columnCount = header.length;
      trackedColumns = header.filter(
        (c) =>
          REQUIRED_NUMERIC_FEATURES.includes(c) ||
          c === TIMESTAMP_COLUMN ||
          c === LABEL_COLUMN ||
          c === PROTOCOL_RAW_COLUMN ||
          c === DST_PORT_COLUMN,
      );
      for (const c of trackedColumns) {
        missingValueCounts[c] = 0;
        if (REQUIRED_NUMERIC_FEATURES.includes(c)) numericIssueCounts[c] = 0;
      }
      labelColumnIndex = header.indexOf(LABEL_COLUMN);
      return;
    }

    rowCount++;

    const fields = splitCsvLine(line);
    if (fields.length !== columnCount) {
      malformedRowCount++;
    }

    if (rowCount <= PREVIEW_ROW_CAP) {
      previewRows.push(fields);
    }

    if (detailedStatsRowCount < DETAILED_STATS_ROW_CAP) {
      detailedStatsRowCount++;
      for (const col of trackedColumns) {
        const idx = header!.indexOf(col);
        const value = idx >= 0 && idx < fields.length ? fields[idx] : "";
        if (value.trim() === "") {
          missingValueCounts[col]++;
        } else if (col in numericIssueCounts && !isNumericCell(value)) {
          numericIssueCounts[col]++;
        }
      }

      if (labelColumnIndex >= 0 && detectedLabelsSet.size < DETECTED_LABELS_CAP) {
        const labelValue = fields[labelColumnIndex]?.trim();
        if (labelValue) detectedLabelsSet.add(labelValue);
      } else if (labelColumnIndex >= 0 && detectedLabelsSet.size >= DETECTED_LABELS_CAP) {
        labelDetectionCapped = true;
      }
    } else {
      detailedStatsCapped = true;
    }

    if (!duplicateCheckCapped) {
      if (rowCount > DUPLICATE_ROW_CAP) {
        duplicateCheckCapped = true;
      } else {
        const h = hashRow(line);
        if (seenHashes.has(h)) {
          duplicateRowCount++;
        } else {
          seenHashes.add(h);
        }
      }
    }
  }

  try {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let newlineIndex: number;
      // eslint-disable-next-line no-cond-assign
      while ((newlineIndex = buffer.indexOf("\n")) !== -1) {
        const rawLine = buffer.slice(0, newlineIndex);
        buffer = buffer.slice(newlineIndex + 1);
        processLine(rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine);
      }
    }
    buffer += decoder.decode();
    if (buffer.length > 0) {
      processLine(buffer.endsWith("\r") ? buffer.slice(0, -1) : buffer);
    }
  } catch {
    return { error: { code: "READ_ERROR", message: "The file could not be read (browser file-read error)." } };
  }

  if (header === null) {
    return { error: { code: "NO_HEADER", message: "No header row was found - the file appears to be empty or unreadable as text." } };
  }
  if (rowCount === 0) {
    return { error: { code: "EMPTY_FILE", message: "The file contains a header row but no data rows." } };
  }

  const headerRow = header as string[];
  const stats: ParsedCsvStats = {
    header: headerRow,
    columnCount,
    rowCount,
    rowCountExact: true,
    detailedStatsRowCount,
    detailedStatsCapped,
    previewRows,
    missingValueCounts,
    numericIssueCounts,
    duplicateRowCount,
    duplicateCheckCapped,
    duplicateCheckRowLimit: DUPLICATE_ROW_CAP,
    malformedRowCount,
    hasTimestampColumn: headerRow.includes(TIMESTAMP_COLUMN),
    hasLabelColumn: headerRow.includes(LABEL_COLUMN),
    hasProtocolColumn: headerRow.includes(PROTOCOL_RAW_COLUMN),
    hasDstPortColumn: headerRow.includes(DST_PORT_COLUMN),
    detectedLabels: Array.from(detectedLabelsSet).sort(),
    labelDetectionCapped,
    fileTooLargeForFullScan: file.size > LARGE_FILE_BYTE_THRESHOLD,
    scanBytesProcessed: file.size,
    totalBytes: file.size,
  };

  return { stats };
}
