"""Compare flows extracted from a pcap with published CICIDS2017 rows, feature by feature.

    python tools/parity_check.py Friday.pcap GeneratedLabelledFlows.zip --day Friday --out reports/parity

Rows are paired on the 5-tuple, flow duration and packet order inside that group.
The script writes <out>_<profile>.csv with one row per feature.
"""
from __future__ import annotations

import argparse
import sys
import time
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.flow_extractor import extract_flows  # noqa: E402

KEY = ["source ip", "source port", "destination ip", "destination port", "protocol", "flow duration"]
NON_FEATURES = set(KEY) | {"flow id", "timestamp", "label", "flow start us", "pair"}


def load_published(archive: Path, day: str) -> pd.DataFrame:
    frames = []
    with zipfile.ZipFile(archive) as bundle:
        for name in sorted(bundle.namelist()):
            if day.lower() in name.lower() and name.endswith(".csv"):
                frame = pd.read_csv(bundle.open(name), encoding="latin-1", low_memory=False)
                frame.columns = frame.columns.str.strip().str.lower()
                frames.append(frame)
    if not frames:
        raise SystemExit(f"No CSV for {day} in {archive}")
    published = pd.concat(frames, ignore_index=True)
    missing = set(KEY) - set(published.columns)
    if missing:
        raise ValueError(f"Full GeneratedLabelledFlows CSVs are required, not MachineLearningCSV; missing identity columns: {sorted(missing)}")
    published = published.dropna(subset=["source ip"])
    for column in published.columns:
        if column not in {"flow id", "source ip", "destination ip", "timestamp", "label"}:
            published[column] = pd.to_numeric(published[column], errors="coerce")
    return published


def pair_rows(published: pd.DataFrame, extracted: pd.DataFrame) -> pd.DataFrame:
    left = published.assign(pair=published.groupby(KEY, sort=False).cumcount())
    right = extracted.sort_values("flow start us")
    right = right.assign(pair=right.groupby(KEY, sort=False).cumcount())
    return left.merge(right, on=KEY + ["pair"], suffixes=("_published", "_extracted"))


def three_significant_digits(values: np.ndarray) -> np.ndarray:
    """The published CSVs hold values of 10 million or more to 3 significant digits."""
    rounded = values.copy()
    large = np.isfinite(values) & (np.abs(values) >= 1e7)
    magnitude = 10.0 ** (np.floor(np.log10(np.abs(values[large]))) - 2)
    rounded[large] = np.round(values[large] / magnitude) * magnitude
    return rounded


def agreement(paired: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    rows = []
    for feature in features:
        a = paired[f"{feature}_published"].astype(float).to_numpy()
        b = paired[f"{feature}_extracted"].astype(float).to_numpy()
        same = np.isclose(a, three_significant_digits(b), rtol=1e-6, atol=1e-6, equal_nan=True)
        finite = np.isfinite(a) & np.isfinite(b)
        rows.append({
            "feature": feature,
            "match_share": same.mean(),
            "median_published": float(np.nanmedian(a[finite])) if finite.any() else np.nan,
            "median_extracted": float(np.nanmedian(b[finite])) if finite.any() else np.nan,
        })
    return pd.DataFrame(rows).sort_values("match_share")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("published_zip", type=Path)
    parser.add_argument("--day", required=True)
    parser.add_argument("--profile", default="training")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    published = load_published(args.published_zip, args.day)
    started = time.time()
    extracted = extract_flows(args.pcap, args.profile)
    print(f"extracted {len(extracted):,} flows in {time.time() - started:.0f}s", flush=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    extracted.to_parquet(f"{args.out}_{args.profile}_flows.parquet", index=False)

    paired = pair_rows(published, extracted)
    print(f"published {len(published):,} rows, paired {len(paired):,} ({len(paired) / len(published):.2%})")
    share = paired.groupby("label").size() / published.groupby("label").size()
    print(share.round(4).to_string())

    features = [c for c in extracted.columns if c not in NON_FEATURES and c in published.columns]
    table = agreement(paired, features)
    table.to_csv(f"{args.out}_{args.profile}.csv", index=False)
    print(f"\n{(table['match_share'] >= 0.99).sum()} of {len(table)} features match on at least 99% of paired rows")
    print(table.head(30).to_string(index=False))
