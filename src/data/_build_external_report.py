"""Ad-hoc report builder for the external dataset preparation task (not a numbered pipeline feature)."""
import json
from pathlib import Path

raw = {}
for key, fname in [("wed28", "Wednesday-28-02-2018"), ("wed14", "Wednesday-14-02-2018"), ("wed21", "Wednesday-21-02-2018")]:
    with open(f"results/external_dataset_preparation/_raw_inspect_{key}.json") as f:
        raw[fname] = json.load(f)

report = {
    "objective": "Download, verify, organize, and inspect (NOT clean or preprocess) three new CSE-CIC-IDS2018 capture days for future frozen-model evaluation. No training, no model/artifact modification.",
    "source": "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/ (public, --no-sign-request)",
    "files": {},
    "schema_compatibility": {
        "reference_schema": "80 columns, identical names/order to data/processed/Thursday-01-03-2018_TrafficForML_CICFlowMeter_clean.csv (Features 1-15 development dataset).",
        "all_three_files_match_reference_exactly": True,
        "verified_via": "pandas header read (nrows=0) column-by-column comparison against the reference file column list.",
    },
    "feature_compatibility": {
        "existing_artifacts_reviewed": {
            "results/feature_selection_report.json": "66 core network features recommended for baseline modelling.",
            "results/model_feature_list.json": "66 selected_features (same list).",
            "results/state_schema.json": "68 state features (66 core + Protocol one-hot expanded to 3 columns).",
            "data/processed/temporal/temporal_aggregation_policy.json": "18 SUM-aggregated + 50 MEAN-aggregated features for 1-second window construction.",
        },
        "conclusion": (
            "Because all three downloaded files share the exact 80-column schema (same names, same order, "
            "including Timestamp/Label/Protocol/Dst Port) as the current development dataset, the existing "
            "Feature 2-6 pipeline code should apply to them without modification to the 68-feature state "
            "representation, the feature inventory, or the temporal aggregation policy. This has NOT been "
            "executed in this task (explicitly out of scope) - it is a structural compatibility finding only."
        ),
    },
    "existing_artifact_integrity": {
        "method": "MD5 hash of 14 key Feature 1-15 artifacts (models, splits, scaler, schemas, current cleaned dataset) recorded before this task began, re-hashed after all downloads/inspection completed.",
        "files_checked": 14,
        "mismatches_found": 0,
        "conclusion": "VERIFIED: no existing Feature 1-15 artifact, the current development dataset, or any prior report was modified by this task.",
    },
    "important_findings": [],
}

for fname, d in raw.items():
    report["files"][fname] = d

report["important_findings"].append({
    "finding": "Embedded header rows vary by file",
    "detail": {fn: raw[fn]["embedded_header_rows"] for fn in raw},
    "note": ("Wednesday-28-02-2018 has 33 embedded header rows (same known CICFlowMeter artifact as the "
             "current dev dataset, which had 25). Wednesday-14-02-2018 and Wednesday-21-02-2018 have 0 "
             "(independently spot-checked via grep for the literal header string - confirmed only the "
             "single genuine top-of-file header exists in each)."),
})

report["important_findings"].append({
    "finding": "Exact duplicate row rate varies dramatically by file and is explainable",
    "detail": {fn: raw[fn]["exact_duplicate_rows_hash_based"] for fn in raw},
    "note": (
        "Wednesday-14-02-2018 has an unusually high duplicate rate (225,628 of 1,048,575 rows = 21.5%), "
        "verified independently with pandas.duplicated(). Investigated: duplicates are concentrated almost "
        "entirely in the attack classes (173,620 FTP-BruteForce + 84,807 SSH-Bruteforce occurrences within "
        "duplicate groups, vs only 2,602 Benign). This is consistent with automated brute-force tooling "
        "producing many flows with byte-identical CICFlowMeter feature vectors (same port 21/22, same "
        "protocol, same second-level timestamp, same packet/byte counts per failed login attempt) - a "
        "genuine characteristic of this attack traffic, not necessarily a pipeline artifact to blindly "
        "deduplicate the way Feature 2 did for the current dev dataset. This must be decided carefully in "
        "a future cleaning step, not assumed."
    ),
})

report["important_findings"].append({
    "finding": "CRITICAL: Wednesday-14-02-2018 and Wednesday-21-02-2018 both contain exactly 1,048,575 rows",
    "detail": {
        "wednesday_14_02_2018_rows": 1048575,
        "wednesday_21_02_2018_rows": 1048575,
        "note_on_number": "1,048,575 = 2^20 - 1, i.e. exactly Microsoft Excel maximum worksheet row limit (1,048,576) minus one header row.",
    },
    "interpretation": (
        "This exact match for both larger files is very unlikely to be coincidental. It strongly suggests "
        "these two files were truncated at some point during dataset preparation/export (e.g. opened and "
        "re-saved in Excel), and may not represent the complete capture for that day. This is not a "
        "download error: each file byte size on S3 is fully self-consistent with containing exactly this "
        "many rows (verified: ~341.6 bytes/row for Wed-14, ~313.6 bytes/row for Wed-21, both close to the "
        "~325.7 bytes/row baseline from the complete, untruncated current dev-day file) - meaning any "
        "truncation happened upstream, before the file was written to the public S3 bucket, not during "
        "this download."
    ),
    "corroborating_evidence": {
        "wednesday_21_02_2018_max_timestamp": "2018-02-21 10:43:21",
        "comparison": ("The current dev dataset and Wednesday-28-02-2018 both run to approximately 12:59:59 "
                       "(a consistent ~01:00-13:00 capture window across days). Wednesday-21-02-2018 stops "
                       "at 10:43:21 - over two hours earlier than this pattern - consistent with the file "
                       "being cut off mid-capture rather than ending naturally."),
        "wednesday_14_02_2018_max_timestamp": "2018-02-14 12:59:59",
        "wednesday_14_note": ("Reaches the expected ~12:59:59 end time, so it is less clearly truncated by "
                              "this particular signal than Wednesday-21-02-2018, but the exact 1,048,575-row "
                              "coincidence remains unexplained and should not be assumed safe without "
                              "further verification."),
    },
    "recommendation": (
        "Treat both Wednesday-14-02-2018 and Wednesday-21-02-2018 as possibly incomplete captures, "
        "particularly Wednesday-21-02-2018 whose attack window may extend past 10:43:21 in reality. Do "
        "not assume these files contain 100 percent of the true day traffic when designing evaluation "
        "splits. If exact completeness matters, cross-check against independent CIC documentation of "
        "expected total row counts per day, or attempt to source these two files from a non-Excel-mediated "
        "channel."
    ),
})

report["important_findings"].append({
    "finding": "5 rows in Wednesday-14-02-2018 have implausible pre-2018 timestamps",
    "detail": {
        "affected_rows": 5,
        "out_of_total_rows": 1048575,
        "pct": 0.0005,
        "raw_timestamp_values": ["05/01/1970 03:01:17", "08/01/1970 07:32:33", "12/01/1970 07:17:56", "12/01/1970 09:15:10", "12/01/1970 09:44:12"],
        "common_traits": "All 5 rows have Dst Port=0, Protocol=0, Label=Benign.",
    },
    "note": (
        "These timestamps parse successfully (not malformed strings) but represent implausible dates for a "
        "2018 capture. This is a genuine, pre-existing data-quality issue in the source file (not "
        "introduced by download or by this inspection), affecting a negligible 0.0005 percent of rows. Not "
        "modified or removed here per the inspection-only scope; must be handled explicitly (not silently "
        "dropped) in a future cleaning step."
    ),
})

report["important_findings"].append({
    "finding": "Flow Byts/s and Flow Pkts/s Infinity values present in 2 of 3 files, absent in the third",
    "detail": {
        fn: {"flow_byts_per_s_infinity": raw[fn]["flow_byts_per_s_infinity_count"], "flow_pkts_per_s_infinity": raw[fn]["flow_pkts_per_s_infinity_count"]}
        for fn in raw
    },
    "note": (
        "Consistent with the known CICFlowMeter zero-duration-flow division-by-zero behaviour already "
        "documented for the current dev dataset in Feature 2. Wednesday-21-02-2018 (DDoS traffic) shows "
        "zero Infinity values, plausibly because high-volume DDoS flows rarely have zero measured duration. "
        "No literal NaN strings were found in either rate column in any of the 3 files (differs from the "
        "dev dataset, which had 1,834 literal NaN strings in Flow Byts/s)."
    ),
})

report["not_performed_per_scope"] = [
    "No cleaning, deduplication, or embedded-header removal was performed on any of the 3 files.",
    "No preprocessing pipeline was fit on the new data.",
    "No scaled sequences, LSTM inputs, model predictions, or new model checkpoints were created.",
    "No existing Feature 1-15 artifact, split, or preprocessing pipeline was modified.",
]

Path("results/external_dataset_preparation/external_dataset_inspection.json").write_text(
    json.dumps(report, indent=2, default=str), encoding="utf-8"
)
print("Wrote external_dataset_inspection.json")
