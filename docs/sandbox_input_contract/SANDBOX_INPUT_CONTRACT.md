# CyberChess Sandbox/Lab Input Contract (Feature L3.1)

**Status: contract definition only. No Sandbox/lab pipeline is implemented or claimed to work by this document.**

This document defines the exact interface between a future Sandbox/lab traffic
source and CyberChess. It does not modify, and must never be read as modifying,
Features 1–16, Feature L1, or Features L2/L2.5/L2.6/L2.7/L2.8/L2.9. It performs
no training, no fitting, no live mitigation, and no live networking.

The machine-readable half of this contract lives in
[`src/data/sandbox_contract/contract_schema.py`](../../src/data/sandbox_contract/contract_schema.py)
and [`src/data/sandbox_contract/validate_input.py`](../../src/data/sandbox_contract/validate_input.py).
Every fact below (feature names, counts, order, dtypes) is loaded from the
existing frozen artifacts at runtime — nothing here is a second, independently
maintained copy that could silently drift.

---

## 1. Accepted lab input forms

Exactly two forms are accepted. Anything else is rejected outright — this
contract does not attempt to guess the shape of an unrecognized input.

| Form | Description | Existing implementation reused |
|---|---|---|
| `RAW_PCAP_FILE` | An offline `.pcap`/`.pcapng` capture | Feature L2's `src/data/pcap/{pcap_reader,flow_reconstruction,flow_features}.py`, unmodified |
| `PRECOMPUTED_FLOW_TABLE` | A table already in the `clean_df` shape (`Timestamp`, `Protocol`, the 65 named numeric features) | Feature L1's `src/data/prepare_unlabeled_state.py`, unmodified |

Live interface capture, NetFlow/IPFIX exports, vendor SIEM exports, or any
other wire format are explicitly **out of scope** until a future feature
extends `LabInputForm` and defines its own field contract.

## 2. Required packet/flow fields

**For `RAW_PCAP_FILE`:** the parsed packet representation must expose at
least `REQUIRED_PACKET_FIELDS` (`timestamp_us`, `src_ip`, `dst_ip`, `src_port`,
`dst_port`, `protocol`, `ip_total_len`, `ip_header_len`,
`transport_header_len`, `payload_len`, `tcp_flags`, `tcp_window`) — exactly
the fields Feature L2's `PacketRecord` already provides. A test asserts this
tuple stays a subset of the real dataclass's fields, so the two can never
silently drift apart.

**For `PRECOMPUTED_FLOW_TABLE`:** every one of the 65 required feature
columns (loaded from `results/model_feature_list.json`, never hardcoded a
second time) plus `Timestamp` and `Protocol` — 67 columns total.

## 3. Mapping from lab input → CyberChess's 65 features + Protocol

For `RAW_PCAP_FILE`, the mapping is exactly Feature L2's existing
`src/data/pcap/feature_mapping.py` — the single source of truth for how each
of the 65 features is derived from packet/flow data, including each
feature's extractability category (A/B/C/D) and, as of Feature L2.6, its
correction history. **This contract does not redefine or duplicate those
formulas.** It only requires that any future non-PCAP lab source producing a
`PRECOMPUTED_FLOW_TABLE` directly documents its own per-feature formula with
the same rigor `feature_mapping.py` already does — an equivalent mapping
table is a prerequisite for that source to be accepted, not something this
contract can generate on the source's behalf.

For `PRECOMPUTED_FLOW_TABLE`, there is no "mapping" step at all — by
definition, the table must already contain the 65 features under their exact
canonical names.

## 4. Timestamp requirements

- Every record must carry a genuine, parseable timestamp — never inferred,
  interpolated, or defaulted.
- Timestamps must be monotonically non-decreasing **within a single flow**
  (Feature L2's `flow_reconstruction.py` already enforces this by
  re-sorting packets by `(timestamp_us, index)` before building flows).
- The 1-second window boundary convention is `timestamp.floor("1s")`,
  exactly as Feature L1's `build_windows_unlabeled()` already implements —
  reused unmodified, not redefined here.
- No timezone is assumed by this contract. Feature L2.9 established, through
  direct evidence (not assumption), that the *existing* CSE-CIC-IDS2018
  training data's own `Timestamp` column is UTC; any new lab source must
  independently document its own timestamp timezone/convention as a
  precondition of acceptance — this contract does not infer it.

## 5. Flow identity requirements

A flow's identity is the canonical, order-independent key
`{(ip_a, port_a), (ip_b, port_b), protocol}`, with "forward" defined as the
direction of the first packet observed (the initiator) — exactly Feature
L2's `flow_reconstruction.py` convention, reused unmodified. A
`PRECOMPUTED_FLOW_TABLE` input has no packet-level flow identity to
reconstruct; each row IS a flow, and its identity is simply that row.
Ambiguous flow identity (e.g., a `PRECOMPUTED_FLOW_TABLE` row that cannot be
associated with a single, unambiguous time bucket) is a rejection condition
(`AMBIGUOUS_FLOW_IDENTITY`), never resolved by guessing.

## 6. Required handling when a feature cannot be derived

Three distinct cases, handled three distinct ways — never conflated:

1. **Feature computed via a *validated* formula.** Proceed. (Per Feature
   L2.5/L2.6, this currently applies to only a minority of the 65 features —
   see §13.)
2. **Feature computed via an *unvalidated or partially-validated* formula.**
   Proceed, but the resulting value's `DataProvenance` tag (§11) and any
   downstream report **must** carry its L2.5/L2.6 validation status
   (`VALIDATED` / `PARTIALLY_VALIDATED` / `UNVALIDATED` / `NOT_REPRODUCIBLE`)
   alongside it. Silently presenting an unvalidated feature as equivalent to
   a validated one is itself a contract violation.
3. **Feature genuinely cannot be derived at all** (a required raw field is
   absent, the protocol is unsupported, or the input form doesn't carry
   enough information). **Reject the affected record outright.** Never
   substitute a zero, a mean, an unrelated feature, or a guess. This mirrors
   Feature L1's own "no label invention" principle, applied to features
   instead of labels.

## 7. Required 68-dimensional state ordering

Exactly `results/temporal_feature_order.json`'s `feature_order`: the 65
named features in alphabetical order, followed by `Protocol_0`, `Protocol_6`,
`Protocol_17` (one-hot, reindexed to these exact training-time columns with
`fill_value=0` — Feature L1's `build_model_ready_table_unlabeled()`
convention, reused unmodified). `contract_schema.STATE_ORDER_68D` loads this
list directly from the artifact; a test asserts it always has exactly 68
entries and ends with those three columns in that order.

## 8. Required 1-second window representation

Exactly Feature L1's `build_windows_unlabeled()` (itself reusing Feature 6's
`build_aggregation_policy()` unmodified): group by
`timestamp.floor("1s")`, SUM or MEAN per feature per the existing policy, one
row per window with `window_id`, `window_start`, `window_end`,
`observation_count`, `segment_id`, and the 68 feature columns. No
label-derived columns (`benign_count`, `attack_count`, `attack_ratio`,
`dominant_label`) are ever present for lab input, since lab input is
label-free by definition (§6, rejection condition
`LABEL_COLUMN_PRESENT_AND_REQUIRED_ABSENT`).

## 9. Required 10-step sequence representation

Exactly Feature L1's `build_sequences_unlabeled()`: gap/segment-safe,
10 consecutive windows as input plus 1 target window, producing
`X_sequences` of shape `(N, 10, 68)` and `next_window_features` of shape
`(N, 68)`. `target_window_binary_target` and `target_window_label` are always
`None` for lab input — genuinely unknown, never guessed.

## 10. How the existing frozen preprocessing transform is applied

Exactly Feature L1's `transform_unlabeled_windows()`: the frozen,
train-fitted pipeline at
`data/processed/splits/preprocessing_pipeline_train_fitted.joblib` is loaded
via `prepare_external_dataset.load_reference_artifacts()` (read-only) and
applied via `.transform()` **only**. `check_is_fitted()` is asserted first;
if it fails, that is a hard rejection
(`PREPROCESSING_PIPELINE_NOT_FITTED`), never a silent refit. This contract
reiterates, rather than re-implements, that guarantee — no `.fit()` or
`.fit_transform()` call is introduced anywhere by this feature or any future
Sandbox feature that honors this contract.

## 11. Explicit separation of provenance categories

Every artifact produced anywhere downstream of a Sandbox/lab input **must**
be tagged with exactly one `DataProvenance` value:

| Value | Meaning |
|---|---|
| `OBSERVED_LAB_TRAFFIC` | Raw packets/flows exactly as captured — no computation applied |
| `DERIVED_FLOW_FEATURE` | One of the 65 computed features, or the 68D state vector |
| `MODEL_STATE` | The 68D vector(s) as consumed/produced inside the LSTM world model |
| `MODEL_FORECAST` | A predicted **future** state (K-step forecast) — never an observation |
| `ATTACK_PROBABILITY` | Classifier/probability output — a model judgment, not a fact |
| `MITRE_EVIDENCE` | MITRE ATT&CK stage-mapping output — a research-derived annotation |

A consumer (frontend, analyst, or any future automated system) must never be
able to confuse one category for another — e.g., a `MODEL_FORECAST` value
must never be rendered or logged as if it were `OBSERVED_LAB_TRAFFIC`. This
formalizes the "OBSERVED/FORECAST/RESEARCH-DERIVED/SIMULATED" honesty
discipline already established across the frontend features.

## 12. Failure conditions where inference must be rejected

Exactly the `RejectionReason` enum in `contract_schema.py` — reproduced here
for completeness:

- `MISSING_REQUIRED_COLUMN` / `MISSING_REQUIRED_PACKET_FIELD`
- `UNSUPPORTED_PROTOCOL_IPV6` / `UNSUPPORTED_PROTOCOL_OTHER`
- `TIMESTAMP_MISSING_OR_UNPARSEABLE` / `TIMESTAMP_NOT_MONOTONIC_WITHIN_FLOW`
- `AMBIGUOUS_FLOW_IDENTITY`
- `FEATURE_VALUE_TYPE_MISMATCH`
- `FEATURE_NOT_DERIVABLE_FROM_INPUT`
- `PREPROCESSING_PIPELINE_NOT_FITTED`
- `LABEL_COLUMN_PRESENT_AND_REQUIRED_ABSENT`
- `UNSUPPORTED_INPUT_FORM`

Any one of these means the affected input (or the specific affected
record/flow) must be **rejected**, with the reason surfaced, never worked
around.

---

## 13. Known PCAP limitations (carried forward from Features L2.5–L2.9 — not re-litigated here)

This contract does not resolve, hide, or soften any of the following
already-established findings. A future Sandbox pipeline built on top of this
contract inherits every one of them:

- **Most PCAP feature formulas remain unvalidated against the original
  CICFlowMeter-V3 generation process.** Feature L2.5's audit of all 65
  features against the real 331,027-row training CSV found only 6
  `VALIDATED`, 21 `PARTIALLY_VALIDATED`, 37 `UNVALIDATED`, and 1
  `NOT_REPRODUCIBLE` (later corrected to `PARTIALLY_VALIDATED` in L2.6).
  L2.6 corrected 4 concrete formula/edge-case problems
  (`Fwd Seg Size Min`, `Flow Byts/s`, `Fwd Pkts/s`, `Bwd Pkts/s`); the
  remaining 37 `UNVALIDATED` features (all IAT statistics, all Active/Idle
  statistics, Header Len, `Pkt Len` family, etc.) are **unchanged** by this
  feature.
- **The official archive/source is plausible but flow-level PCAP↔CSV
  correspondence was not established.** Feature L2.8 found a genuine,
  officially-sourced candidate PCAP archive (`MATCH_PLAUSIBLE`) for the
  training day; Feature L2.9 attempted actual flow-level correlation and
  found the one candidate segment it inspected had **zero timestamp overlap**
  with the training CSV's covered window, classified `NOT_MATCHING` for
  correlation purposes (the archive itself remains a plausible source, per
  L2.8 — only that specific segment failed to correlate).
- **The tested part2 candidate was outside the CSV observation window.**
  Specifically: the CSV covers `2018-03-01 01:00:00`–`12:59:59` UTC; the
  inspected candidate covered `14:03:49`–`14:35:53` UTC — a ~1 hour, 4 minute
  gap with no overlap at all.
- **IPv6 is currently unsupported by the CyberChess PCAP adapter.** Feature
  L2's `pcap_reader.py` explicitly detects and rejects IPv6 frames
  (`"IPv6 packet - not supported by the IPv4-only CyberChess Protocol_0/6/17
  schema."`) rather than silently coercing or dropping them without
  explanation. This contract's `UNSUPPORTED_PROTOCOL_IPV6` rejection reason
  exists specifically to carry this limitation forward into any future
  Sandbox pipeline.

**Net effect: this contract defines how a future Sandbox/lab pipeline must
be *shaped* — it does not claim, and must not be read as claiming, that a
working Sandbox pipeline exists, or that PCAP-derived features are
trustworthy enough for frozen-model inference. That remains explicitly
unresolved, per L2.5 through L2.9.**
