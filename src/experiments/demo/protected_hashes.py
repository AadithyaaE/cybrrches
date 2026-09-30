"""
Feature 18 - protected-artifact hashing (own copy, does NOT modify or import
Feature 17's src/experiments/cross_day_generalization/protected_hashes.py,
per instruction not to touch Feature 17 experiment code).

Hashes every file that must remain unmodified by this feature: Feature
1-16 artifacts, Feature 17's own results/cross_day_generalization/ output,
Feature L1/L2.x/L3.1/L3.2 code+results, and the frontend SOURCE (not the
new /demo page files this feature adds, and not node_modules/dist).
"""

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent

PROTECTED_DIRS = [
    ROOT / "results",
    ROOT / "data/processed",
    ROOT / "src/data",
    ROOT / "src/models",
    ROOT / "src/experiments/cross_day_generalization",
    ROOT / "frontend/src",
]
EXCLUDE_PREFIXES = [
    ROOT / "results/demo",
    ROOT / "src/experiments/demo",
    ROOT / "src/data/__pycache__",
    ROOT / "src/models/__pycache__",
    ROOT / "frontend/node_modules",
    ROOT / "frontend/dist",
    # this feature's own new frontend files - listed explicitly, never a broad "new files are OK" rule
    ROOT / "frontend/src/pages/DemoPage.tsx",
    ROOT / "frontend/src/pages/DemoPage.css",
    ROOT / "frontend/src/services/demoService.ts",
    ROOT / "frontend/src/data/crossDayGeneralizationData.ts",
    ROOT / "frontend/src/types/demo.ts",
    ROOT / "frontend/public/data/demo_manifest.json",
    # intentionally modified by this feature (adds the /demo route + nav entry only) - excluded from the
    # "must be byte-identical" hash set; the diff for these two files is reviewed manually instead (see
    # the final report's "files modified" section) rather than asserted to be zero.
    ROOT / "frontend/src/routes/AppRoutes.tsx",
    ROOT / "frontend/src/routes/navConfig.tsx",
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
