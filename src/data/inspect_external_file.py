"""
Ad-hoc chunked inspection helper for external CSE-CIC-IDS2018 capture-day
files (used only for the external-dataset preparation task; not a
numbered pipeline feature). Reads the file in chunks to bound memory,
computes label distribution, timestamp coverage, embedded-header-row
count, duplicate-row count, and Infinity/NaN counts. INSPECTION ONLY -
never writes to or modifies the source file.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

CHUNK_SIZE = 200_000


def inspect(path: Path) -> dict:
    header = pd.read_csv(path, nrows=0).columns.tolist()
    header_as_row = {c: c for c in header}

    total_rows = 0
    label_counts = {}
    protocol_counts = {}
    ts_min, ts_max = None, None
    n_ts_valid, n_ts_invalid = 0, 0
    unique_ts = set()
    embedded_header_rows = 0
    duplicate_rows_within_chunks = 0  # approximate: duplicates are checked per-chunk only (memory-bounded)
    flow_byts_inf = 0
    flow_pkts_inf = 0
    literal_nan_strings = {}
    missing_label = 0
    missing_timestamp = 0
    row_hashes_seen = set()
    exact_duplicate_rows = 0

    for chunk in pd.read_csv(path, chunksize=CHUNK_SIZE, dtype=str, low_memory=False):
        total_rows += len(chunk)

        # embedded header rows: every cell equals its own column name
        is_header_row = (chunk == pd.Series(header_as_row)).all(axis=1)
        embedded_header_rows += int(is_header_row.sum())

        clean_chunk = chunk.loc[~is_header_row]

        # label
        if "Label" in clean_chunk.columns:
            vc = clean_chunk["Label"].value_counts(dropna=False)
            for k, v in vc.items():
                label_counts[k] = label_counts.get(k, 0) + int(v)
            missing_label += int(clean_chunk["Label"].isna().sum())

        # protocol
        if "Protocol" in clean_chunk.columns:
            vc = clean_chunk["Protocol"].value_counts(dropna=False)
            for k, v in vc.items():
                protocol_counts[k] = protocol_counts.get(k, 0) + int(v)

        # timestamp
        if "Timestamp" in clean_chunk.columns:
            missing_timestamp += int(clean_chunk["Timestamp"].isna().sum())
            parsed = pd.to_datetime(clean_chunk["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
            valid = parsed.dropna()
            n_ts_valid += len(valid)
            n_ts_invalid += int(parsed.isna().sum()) - missing_timestamp if False else int(parsed.isna().sum())
            if len(valid) > 0:
                cmin, cmax = valid.min(), valid.max()
                ts_min = cmin if ts_min is None or cmin < ts_min else ts_min
                ts_max = cmax if ts_max is None or cmax > ts_max else ts_max
            unique_ts.update(valid.astype(str).tolist())

        # Flow Byts/s and Flow Pkts/s Infinity / literal NaN strings
        for col, counter_name in [("Flow Byts/s", "flow_byts"), ("Flow Pkts/s", "flow_pkts")]:
            if col in clean_chunk.columns:
                literal_nan_count = int((clean_chunk[col] == "NaN").sum())
                literal_nan_strings[col] = literal_nan_strings.get(col, 0) + literal_nan_count
                is_inf = clean_chunk[col] == "Infinity"
                if counter_name == "flow_byts":
                    flow_byts_inf += int(is_inf.sum())
                else:
                    flow_pkts_inf += int(is_inf.sum())

        # exact duplicate rows: use a hash of the full row; cross-chunk duplicate
        # detection via a running hash set (memory: ~1 hash per row, bounded)
        row_hashes = pd.util.hash_pandas_object(clean_chunk, index=False)
        for h in row_hashes:
            if h in row_hashes_seen:
                exact_duplicate_rows += 1
            else:
                row_hashes_seen.add(h)

    return {
        "file": str(path),
        "total_rows_including_embedded_headers": total_rows,
        "embedded_header_rows": embedded_header_rows,
        "total_rows_excluding_embedded_headers": total_rows - embedded_header_rows,
        "exact_duplicate_rows_hash_based": exact_duplicate_rows,
        "label_distribution": {str(k): v for k, v in label_counts.items()},
        "protocol_distribution": {str(k): v for k, v in protocol_counts.items()},
        "timestamp_min": str(ts_min) if ts_min is not None else None,
        "timestamp_max": str(ts_max) if ts_max is not None else None,
        "timestamp_valid_count": n_ts_valid,
        "timestamp_invalid_count": n_ts_invalid,
        "timestamp_unique_count": len(unique_ts),
        "missing_label_count": missing_label,
        "missing_timestamp_count": missing_timestamp,
        "flow_byts_per_s_infinity_count": flow_byts_inf,
        "flow_pkts_per_s_infinity_count": flow_pkts_inf,
        "literal_nan_string_counts": literal_nan_strings,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    result = inspect(Path(args.file))
    Path(args.out).write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    print(json.dumps(result, indent=2, default=str))
