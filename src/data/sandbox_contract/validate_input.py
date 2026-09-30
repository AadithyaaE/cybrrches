"""
Feature L3.1 - Sandbox/Lab Input Contract: validation (gatekeeper) logic.

This module ONLY validates whether a candidate lab input satisfies the
contract declared in contract_schema.py. It NEVER computes a missing
feature, NEVER fills a gap with zero/mean/an unrelated feature, and NEVER
proceeds to state-preparation, windowing, sequencing, preprocessing, or
model inference - all of that remains Feature L1/L2/L2.6's existing,
unmodified responsibility, invoked (by a FUTURE feature, not this one)
only after this contract accepts the input.

No training. No fitting. No mitigation. No live networking.
"""

import math
from pathlib import Path

import numpy as np
import pandas as pd

from .contract_schema import (
    ContractValidationResult, LabInputForm, RejectionReason,
    REQUIRED_65_FEATURES, REQUIRED_FLOW_TABLE_COLUMNS, FEATURE_DTYPES_68D,
    TIMESTAMP_COLUMN, PROTOCOL_COLUMN,
)

_SUPPORTED_PROTOCOL_NUMBERS = {0, 6, 17}  # matches Protocol_0/6/17 - the only training-compatible values


def validate_flow_table_contract(df: pd.DataFrame) -> ContractValidationResult:
    """
    Validates a LabInputForm.PRECOMPUTED_FLOW_TABLE candidate: a table
    already claiming to be in the "clean_df" shape (Timestamp, Protocol,
    65 named numeric features) that Feature L1's
    build_model_ready_table_unlabeled() expects.

    Returns accepted=True only if EVERY required column is present with a
    plausible dtype, Timestamp is present/parseable, and Protocol values
    are all in the training-compatible set {0, 6, 17}. Never mutates `df`.
    """
    reasons = []
    detail = []

    missing_cols = [c for c in REQUIRED_FLOW_TABLE_COLUMNS if c not in df.columns]
    if missing_cols:
        reasons.append(RejectionReason.MISSING_REQUIRED_COLUMN)
        detail.append(f"Missing required column(s): {sorted(missing_cols)}")

    if TIMESTAMP_COLUMN in df.columns:
        parsed = pd.to_datetime(df[TIMESTAMP_COLUMN], errors="coerce")
        n_bad = int(parsed.isna().sum())
        if n_bad > 0:
            reasons.append(RejectionReason.TIMESTAMP_MISSING_OR_UNPARSEABLE)
            detail.append(f"{n_bad} row(s) have a missing or unparseable Timestamp value.")
    else:
        reasons.append(RejectionReason.TIMESTAMP_MISSING_OR_UNPARSEABLE)
        detail.append("Timestamp column is entirely absent.")

    if PROTOCOL_COLUMN in df.columns:
        observed = set(pd.to_numeric(df[PROTOCOL_COLUMN], errors="coerce").dropna().unique().tolist())
        unsupported = {int(v) for v in observed if int(v) not in _SUPPORTED_PROTOCOL_NUMBERS}
        if unsupported:
            reasons.append(RejectionReason.UNSUPPORTED_PROTOCOL_OTHER)
            detail.append(f"Protocol value(s) {sorted(unsupported)} are not in the training-compatible set {sorted(_SUPPORTED_PROTOCOL_NUMBERS)}.")

    if "Label" in df.columns:
        reasons.append(RejectionReason.LABEL_COLUMN_PRESENT_AND_REQUIRED_ABSENT)
        detail.append(
            "A 'Label' column is present. This contract's downstream consumer (Feature L1) is label-free by "
            "design and must never read, require, or infer a label from lab input - reject rather than risk "
            "silent label leakage or a fabricated label."
        )

    for feature in REQUIRED_65_FEATURES:
        if feature not in df.columns:
            continue  # already reported via MISSING_REQUIRED_COLUMN above
        expected_dtype = FEATURE_DTYPES_68D.get(feature)
        col = df[feature]
        if expected_dtype == "int64":
            non_numeric = pd.to_numeric(col, errors="coerce").isna() & col.notna()
        else:
            non_numeric = pd.to_numeric(col, errors="coerce").isna() & col.notna()
        n_bad = int(non_numeric.sum())
        if n_bad > 0:
            reasons.append(RejectionReason.FEATURE_VALUE_TYPE_MISMATCH)
            detail.append(f"Column '{feature}' has {n_bad} value(s) that are not numeric (expected {expected_dtype}).")
            break  # one representative type-mismatch report is enough; do not flood the result

    accepted = len(reasons) == 0
    return ContractValidationResult(
        accepted=accepted,
        input_form=LabInputForm.PRECOMPUTED_FLOW_TABLE,
        reasons=tuple(reasons),
        detail=tuple(detail),
    )


def validate_raw_pcap_form_declared_fields(field_names) -> ContractValidationResult:
    """
    Validates that a candidate raw-PCAP-derived packet representation
    declares (at minimum) every field this contract's RAW_PCAP_FILE form
    requires - i.e. that whatever parser produced it (today, Feature L2's
    read_pcap(); a different parser in the future must also satisfy this)
    exposes the full REQUIRED_PACKET_FIELDS set. This checks field
    PRESENCE/NAMING only - it does not re-parse or re-validate packet
    content, which remains Feature L2's existing, unmodified
    responsibility.
    """
    from .contract_schema import REQUIRED_PACKET_FIELDS

    missing = [f for f in REQUIRED_PACKET_FIELDS if f not in field_names]
    if missing:
        return ContractValidationResult(
            accepted=False,
            input_form=LabInputForm.RAW_PCAP_FILE,
            reasons=(RejectionReason.MISSING_REQUIRED_PACKET_FIELD,),
            detail=(f"Candidate packet representation is missing required field(s): {missing}",),
        )
    return ContractValidationResult(
        accepted=True, input_form=LabInputForm.RAW_PCAP_FILE, reasons=(), detail=(),
    )
