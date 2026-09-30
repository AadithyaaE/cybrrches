import { useRef, useState } from "react";
import type { DragEvent } from "react";
import Button from "../ui/Button";
import StatusBadge from "../ui/StatusBadge";
import type { InputType } from "../../types/dataset";
import "./DatasetUpload.css";

interface DatasetUploadProps {
  inputType: InputType;
  onInputTypeChange: (type: InputType) => void;
  onFileSelected: (file: File) => void;
  selectedFileName: string | null;
  onReset: () => void;
  isParsing: boolean;
}

function classifyFile(file: File): InputType {
  const name = file.name.toLowerCase();
  if (name.endsWith(".csv") || file.type === "text/csv") return "csv";
  if (name.endsWith(".pcap") || name.endsWith(".pcapng") || name.endsWith(".cap")) return "pcap";
  return "unsupported";
}

export default function DatasetUpload({
  inputType,
  onInputTypeChange,
  onFileSelected,
  selectedFileName,
  onReset,
  isParsing,
}: DatasetUploadProps) {
  const [isDragOver, setIsDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  function handleFiles(files: FileList | null) {
    const file = files?.[0];
    if (!file) return;
    const detected = classifyFile(file);
    onInputTypeChange(detected);
    onFileSelected(file);
  }

  function handleDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setIsDragOver(false);
    handleFiles(e.dataTransfer.files);
  }

  return (
    <div className="dataset-upload">
      <div className="dataset-upload__type-tabs">
        {(["csv", "pcap"] as InputType[]).map((t) => (
          <button
            key={t}
            type="button"
            className={`dataset-upload__type-tab ${inputType === t ? "dataset-upload__type-tab--active" : ""}`}
            onClick={() => onInputTypeChange(t)}
          >
            {t.toUpperCase()}
          </button>
        ))}
      </div>

      <div
        className={`dataset-upload__dropzone ${isDragOver ? "dataset-upload__dropzone--active" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragOver(true);
        }}
        onDragLeave={() => setIsDragOver(false)}
        onDrop={handleDrop}
      >
        {selectedFileName ? (
          <div className="dataset-upload__selected">
            <StatusBadge label={isParsing ? "Parsing..." : "File Selected"} tone={isParsing ? "info" : "success"} />
            <span className="dataset-upload__filename">{selectedFileName}</span>
            <Button variant="ghost" onClick={onReset}>
              Remove
            </Button>
          </div>
        ) : (
          <>
            <p className="dataset-upload__prompt">Drag and drop a {inputType === "pcap" ? "PCAP" : "CSV"} file here, or</p>
            <Button variant="primary" onClick={() => inputRef.current?.click()}>
              Choose File
            </Button>
          </>
        )}
        <input
          ref={inputRef}
          type="file"
          accept=".csv,.pcap,.pcapng,.cap,text/csv"
          className="dataset-upload__input"
          onChange={(e) => handleFiles(e.target.files)}
        />
      </div>

      <p className="dataset-upload__note">
        CyberChess accepts compatible network-traffic telemetry and validates whether uploaded data can be
        mapped to its common network-state representation. It does not work with any arbitrary dataset.
      </p>
    </div>
  );
}
