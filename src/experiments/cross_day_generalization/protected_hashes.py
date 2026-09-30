"""
Feature 17 - protected-artifact hashing.

Hashes every file that must remain unmodified by this feature: Feature
1-16 artifacts (results/, data/processed/{model_ready,states,temporal,splits}),
frozen model weights, Feature L1/L2.x/L3.1/L3.2 code+results, and the
frontend. Excludes this feature's own new output area
(results/cross_day_generalization/, src/experiments/) and the external-day
raw/processed caches that Feature 16 already legitimately owns (those are
read, never written, by this feature - but they are pre-existing, not
"protected artifacts" this feature could accidentally corrupt via writes,
since this feature never writes there).
"""

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent

PROTECTED_DIRS = [
    ROOT / "results",
    ROOT / "data/processed",
    ROOT / "src/data",
    ROOT / "src/models",
    ROOT / "frontend",
]
EXCLUDE_PREFIXES = [
    ROOT / "results/cross_day_generalization",
    ROOT / "src/experiments",
    ROOT / "src/data/__pycache__",
    ROOT / "src/models/__pycache__",
    ROOT / "frontend/node_modules",
    ROOT / "frontend/dist",
    ROOT / "results/pcap",  # L2.x's own output areas, tracked by their own feature tests already
    ROOT / "results/pcap_validation",
    ROOT / "results/pcap_formula_corrections",
    ROOT / "results/pcap_cicflowmeter_reference",
    ROOT / "results/pcap_ground_truth_discovery",
    ROOT / "results/pcap_ground_truth_correlation",
    ROOT / "results/sandbox_input_contract",
    ROOT / "results/sandbox_capture",
]
PROTECTED_FILES = [
    ROOT / "data/raw/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
    ROOT / "data/raw/external_evaluation/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
    ROOT / "data/raw/external_evaluation/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    ROOT / "data/raw/external_evaluation/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
]


def file_md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_protected_state() -> dict:
    paths = list(PROTECTED_FILES)
    for d in PROTECTED_DIRS:
        if d.exists():
            paths.extend(
                p for p in d.rglob("*")
                if p.is_file() and not any(str(p).startswith(str(ex)) for ex in EXCLUDE_PREFIXES)
            )
    return {str(p): file_md5(p) for p in set(paths) if p.exists()}
