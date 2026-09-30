import { useMemo, useState } from "react";
import SectionHeader from "../components/ui/SectionHeader";
import StatusBadge from "../components/ui/StatusBadge";
import EmptyState from "../components/ui/EmptyState";
import SummarySection from "../components/overview/SummarySection";
import DatasetUpload from "../components/dataset/DatasetUpload";
import PcapPanel from "../components/dataset/PcapPanel";
import DatasetSummaryCard from "../components/dataset/DatasetSummaryCard";
import SchemaDetectionPanel from "../components/dataset/SchemaDetectionPanel";
import FeatureCompatibilityTable from "../components/dataset/FeatureCompatibilityTable";
import DataQualityPanel from "../components/dataset/DataQualityPanel";
import SamplePreviewTable from "../components/dataset/SamplePreviewTable";
import InferenceReadinessPanel from "../components/dataset/InferenceReadinessPanel";
import FrozenModelSafetyNotice from "../components/dataset/FrozenModelSafetyNotice";
import ProcessingFlowDiagram from "../components/dataset/ProcessingFlowDiagram";
import { IconAttack } from "../components/ui/icons";
import { parseCsvFile } from "../services/dataset/csvParser";
import { buildCompatibilityReport, buildInferenceReadiness } from "../services/dataset/datasetCompatibility";
import { detectSchemaFamily } from "../services/dataset/schemaDetection";
import type { InputType, ParsedCsvStats, CsvParseError, DatasetFileInfo } from "../types/dataset";
import "./DatasetsPage.css";

export default function DatasetsPage() {
  const [inputType, setInputType] = useState<InputType>("csv");
  const [fileInfo, setFileInfo] = useState<DatasetFileInfo | null>(null);
  const [isParsing, setIsParsing] = useState(false);
  const [parseError, setParseError] = useState<CsvParseError | null>(null);
  const [stats, setStats] = useState<ParsedCsvStats | null>(null);

  const compatibility = useMemo(() => (stats ? buildCompatibilityReport(stats) : null), [stats]);
  const readiness = useMemo(() => (compatibility ? buildInferenceReadiness(compatibility) : null), [compatibility]);
  const schemaDetection = useMemo(() => (stats ? detectSchemaFamily(stats.header) : null), [stats]);

  function reset() {
    setFileInfo(null);
    setStats(null);
    setParseError(null);
    setIsParsing(false);
  }

  async function handleFileSelected(file: File) {
    reset();
    const detectedType: InputType = file.name.toLowerCase().endsWith(".csv") || file.type === "text/csv"
      ? "csv"
      : file.name.toLowerCase().match(/\.(pcap|pcapng|cap)$/)
        ? "pcap"
        : "unsupported";
    setInputType(detectedType);
    setFileInfo({ filename: file.name, fileType: detectedType, fileSizeBytes: file.size, mimeType: file.type || "unknown" });

    if (detectedType !== "csv") return;

    setIsParsing(true);
    const result = await parseCsvFile(file);
    setIsParsing(false);
    if ("error" in result) {
      setParseError(result.error);
    } else {
      setStats(result.stats);
    }
  }

  return (
    <div>
      <SectionHeader
        title="Dataset Ingestion & Compatibility"
        description="The front door of the CyberChess inference pipeline: upload, identify, validate, and prepare network-traffic data for the frozen research models."
        actions={<StatusBadge label="Offline / No Inference Run" tone="warning" />}
      />

      <div className="datasets-page__sections">
        <SummarySection title="Dataset Upload">
          <DatasetUpload
            inputType={inputType}
            onInputTypeChange={setInputType}
            onFileSelected={handleFileSelected}
            selectedFileName={fileInfo?.filename ?? null}
            onReset={reset}
            isParsing={isParsing}
          />
        </SummarySection>

        {((inputType === "pcap" && !fileInfo) || fileInfo?.fileType === "pcap") && (
          <SummarySection title="Input Type: PCAP">
            <PcapPanel />
          </SummarySection>
        )}

        {fileInfo?.fileType === "unsupported" && (
          <SummarySection title="Unsupported File Type">
            <EmptyState
              icon={<IconAttack />}
              title="Unsupported file type"
              description={`"${fileInfo.filename}" is not a recognized CSV or PCAP file. CyberChess accepts .csv (network-traffic telemetry) and, as a defined-but-not-yet-implemented input type, .pcap/.pcapng/.cap capture files. No other file types are supported.`}
            />
          </SummarySection>
        )}

        {parseError && (
          <SummarySection title="Unable to Parse File">
            <EmptyState icon={<IconAttack />} title={parseError.code.replace(/_/g, " ")} description={parseError.message} />
          </SummarySection>
        )}

        {stats && fileInfo && compatibility && readiness && schemaDetection && (
          <>
            <SummarySection title="Dataset Summary">
              <DatasetSummaryCard fileInfo={fileInfo} stats={stats} />
            </SummarySection>

            <SummarySection title="Schema / Dataset Detection">
              <SchemaDetectionPanel detection={schemaDetection} />
            </SummarySection>

            <SummarySection
              title="CyberChess Feature Compatibility"
              description={compatibility.statusReason}
              evalLabel={compatibility.status.replace(/_/g, " ")}
            >
              <FeatureCompatibilityTable compatibility={compatibility} />
            </SummarySection>

            <SummarySection title="Data Quality">
              <DataQualityPanel stats={stats} />
            </SummarySection>

            <SummarySection title="Sample Preview">
              <SamplePreviewTable stats={stats} />
            </SummarySection>

            <SummarySection title="Inference Readiness">
              <InferenceReadinessPanel readiness={readiness} />
            </SummarySection>
          </>
        )}

        <SummarySection title="Frozen Research Model Safety">
          <FrozenModelSafetyNotice />
        </SummarySection>

        <SummarySection title="CyberChess Processing Flow">
          <ProcessingFlowDiagram />
        </SummarySection>

        <SummarySection title="Relationship to Feature 16 (Generalization)">
          <p className="datasets-page__relationship">
            Feature 16 performed a frozen cross-capture generalization evaluation using verified
            CSE-CIC-IDS2018 capture days (see the Generalization page). Feature 9 is the user-facing
            ingestion layer that prepares network-traffic input for future CyberChess inference. Feature 9
            itself does not run inference and does not prove generalization - a dataset being{" "}
            <em>compatible</em> here is not automatically evidence that the model <em>generalizes well</em>{" "}
            to it; that question is what Feature 16-style evaluation is for.
          </p>
        </SummarySection>
      </div>
    </div>
  );
}
