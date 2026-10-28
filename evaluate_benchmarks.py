
"""Evaluate SQLGuard-C, Bandit, and Semgrep against the labeled dataset.

Run from the SQLGuard-C project root:
    py -3.12 evaluate_benchmarks.py

Scoring protocol:
    unsafe = positive class
    safe and tricky = negative class

The tricky category is also reported separately. Results describe this
dataset only and should not be interpreted as real-world guarantees.
"""

from __future__ import annotations

import csv
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

from sqlguard.analysis.taint import analyze_file


ROOT = Path(__file__).resolve().parent
DATASET_DIR = ROOT / "dataset"
DATASET_LABELS = DATASET_DIR / "labels.csv"

BANDIT_RESULTS = ROOT / "results" / "bandit" / "bandit_raw.json"
SEMGREP_RESULTS = ROOT / "results" / "semgrep" / "semgrep_raw.json"
RESULTS_DIR = ROOT / "results"

VALID_LABELS = {"safe", "tricky", "unsafe"}


def normalize_path(value: str) -> str:
    """Normalize dataset-relative paths to forward-slash form."""
    value = str(value).strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    if value.startswith("dataset/"):
        value = value[len("dataset/"):]
    return value


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(
            f"Required tool output was not found: {path}\n"
            "Run the corresponding Bandit/Semgrep scan first."
        )

    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object in {path}")

    return data


def load_dataset() -> list[dict[str, str]]:
    """Read labels and reject malformed, duplicate, or missing examples."""
    if not DATASET_LABELS.is_file():
        raise FileNotFoundError(f"Dataset labels not found: {DATASET_LABELS}")

    with DATASET_LABELS.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)

        if reader.fieldnames != ["file", "label"]:
            raise ValueError(
                "labels.csv must have exactly these headers: file,label"
            )

        rows = []
        seen = set()

        for line_number, row in enumerate(reader, start=2):
            filename = normalize_path(row.get("file", ""))
            label = str(row.get("label", "")).strip().lower()

            if not filename:
                raise ValueError(
                    f"Empty file path in labels.csv at line {line_number}"
                )
            if label not in VALID_LABELS:
                raise ValueError(
                    f"Invalid label {label!r} at line {line_number}; "
                    f"allowed labels are {sorted(VALID_LABELS)}"
                )
            if filename in seen:
                raise ValueError(f"Duplicate dataset entry: {filename}")

            # Prevent paths from escaping the dataset directory.
            resolved = (DATASET_DIR / Path(*filename.split("/"))).resolve()
            if not resolved.is_relative_to(DATASET_DIR.resolve()):
                raise ValueError(f"Dataset path escapes dataset directory: {filename}")
            if not resolved.is_file():
                raise FileNotFoundError(
                    f"Dataset entry does not exist: {resolved}"
                )

            seen.add(filename)
            rows.append({"filename": filename, "expected_label": label})

    if not rows:
        raise ValueError("labels.csv contains no examples.")

    counts = Counter(row["expected_label"] for row in rows)
    print(f"Dataset category counts: {dict(sorted(counts.items()))}")

    missing_categories = VALID_LABELS - set(counts)
    if missing_categories:
        raise ValueError(
            f"Dataset is missing label categories: {sorted(missing_categories)}"
        )

    return rows


def load_flagged_files(path: Path, tool: str):
    """Return normalized flagged paths and source finding details."""
    data = load_json(path)
    results = data.get("results", [])

    if not isinstance(results, list):
        raise ValueError(f"'results' must be a list in {path}")

    flagged = set()
    details: dict[str, list[dict[str, Any]]] = {}

    for result in results:
        if not isinstance(result, dict):
            continue

        if tool == "bandit":
            raw_path = result.get("filename")
            filename = normalize_path(raw_path) if raw_path else ""
            detail = {
                "test_id": result.get("test_id"),
                "issue_text": result.get("issue_text"),
                "line_number": result.get("line_number"),
                "issue_severity": result.get("issue_severity"),
                "issue_confidence": result.get("issue_confidence"),
            }
        elif tool == "semgrep":
            raw_path = result.get("path")
            filename = normalize_path(raw_path) if raw_path else ""
            start = result.get("start") or {}
            extra = result.get("extra") or {}
            detail = {
                "check_id": result.get("check_id"),
                "line_number": start.get("line"),
                "message": extra.get("message"),
                "severity": extra.get("severity"),
            }
        else:
            raise ValueError(f"Unsupported tool: {tool}")

        if not filename:
            continue

        flagged.add(filename)
        details.setdefault(filename, []).append(detail)

    return flagged, details


def safe_divide(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def compute_metrics(
    records: list[dict[str, Any]],
    flagged_key: str,
) -> dict[str, Any]:
    """Calculate unsafe-positive binary metrics plus label breakdowns."""
    tp = sum(
        row["expected_label"] == "unsafe" and row[flagged_key]
        for row in records
    )
    fn = sum(
        row["expected_label"] == "unsafe" and not row[flagged_key]
        for row in records
    )

    fp_by_label = {
        label: sum(
            row["expected_label"] == label and row[flagged_key]
            for row in records
        )
        for label in ("safe", "tricky")
    }
    tn_by_label = {
        label: sum(
            row["expected_label"] == label and not row[flagged_key]
            for row in records
        )
        for label in ("safe", "tricky")
    }

    fp = sum(fp_by_label.values())
    tn = sum(tn_by_label.values())
    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    f1 = safe_divide(2 * precision * recall, precision + recall)

    per_category = {}
    for label in ("safe", "tricky", "unsafe"):
        subset = [r for r in records if r["expected_label"] == label]
        flagged_count = sum(r[flagged_key] for r in subset)
        per_category[label] = {
            "total": len(subset),
            "flagged": flagged_count,
            "not_flagged": len(subset) - flagged_count,
        }

    return {
        "total_examples": len(records),
        "TP": tp,
        "FP": fp,
        "FP_breakdown": fp_by_label,
        "FN": fn,
        "TN": tn,
        "TN_breakdown": tn_by_label,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "per_category": per_category,
    }


def finding_to_dict(finding: Any) -> dict[str, Any]:
    """Serialize a finding without assuming it is already a dictionary."""
    if isinstance(finding, dict):
        return finding
    if hasattr(finding, "to_dict"):
        return finding.to_dict()

    fields = ("file", "line", "severity", "message", "source", "sink",
              "variable", "path", "repair")
    result = {}
    for field in fields:
        if hasattr(finding, field):
            result[field] = getattr(finding, field)
    return result or {"description": str(finding)}


def write_csv(path: Path, records: list[dict[str, Any]], headers: list[str]):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        for record in records:
            writer.writerow({key: record.get(key, "") for key in headers})


def run_evaluation() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    dataset = load_dataset()
    bandit_flagged, bandit_details = load_flagged_files(
        BANDIT_RESULTS, "bandit"
    )
    semgrep_flagged, semgrep_details = load_flagged_files(
        SEMGREP_RESULTS, "semgrep"
    )

    records = []
    sqlguard_details: dict[str, list[dict[str, Any]]] = {}

    for item in dataset:
        filename = item["filename"]
        expected = item["expected_label"]
        file_path = DATASET_DIR / Path(*filename.split("/"))

        findings = analyze_file(str(file_path))
        serialized_findings = [finding_to_dict(f) for f in findings]
        sqlguard_hit = bool(findings)
        sqlguard_details[filename] = serialized_findings

        records.append({
            "filename": filename,
            "expected_label": expected,
            "bandit_result": "vulnerable" if filename in bandit_flagged else "safe",
            "semgrep_result": "vulnerable" if filename in semgrep_flagged else "safe",
            "sqlguard_result": "vulnerable" if sqlguard_hit else "safe",
            "bandit_flagged": filename in bandit_flagged,
            "semgrep_flagged": filename in semgrep_flagged,
            "sqlguard_flagged": sqlguard_hit,
            "sqlguard_finding_count": len(findings),
        })

    # Same scoring protocol for all three tools.
    metric_results = {
        "Bandit": compute_metrics(records, "bandit_flagged"),
        "Semgrep": compute_metrics(records, "semgrep_flagged"),
        "SQLGuard-C": compute_metrics(records, "sqlguard_flagged"),
    }

    summary_headers = [
        "filename", "expected_label",
        "bandit_result", "semgrep_result", "sqlguard_result",
        "sqlguard_finding_count",
    ]
    write_csv(RESULTS_DIR / "summary.csv", records, summary_headers)
    write_csv(
        RESULTS_DIR / "comparison_summary.csv",
        records,
        summary_headers,
    )

    summaries = {
        "bandit": {
            "tool": "Bandit",
            "metrics": metric_results["Bandit"],
            "details": bandit_details,
        },
        "semgrep": {
            "tool": "Semgrep",
            "metrics": metric_results["Semgrep"],
            "details": semgrep_details,
        },
        "sqlguard": {
            "tool": "SQLGuard-C",
            "metrics": metric_results["SQLGuard-C"],
            "details": sqlguard_details,
        },
    }

    for name, summary in summaries.items():
        with (RESULTS_DIR / f"{name}_summary.json").open(
            "w", encoding="utf-8"
        ) as handle:
            json.dump(summary, handle, indent=2)

    report = {
        "dataset": str(DATASET_LABELS.relative_to(ROOT)),
        "total_examples": len(records),
        "scoring_convention": (
            "unsafe = positive; safe and tricky = negative; "
            "tricky cases are also reported separately"
        ),
        "label_counts": dict(Counter(r["expected_label"] for r in records)),
        "metrics": metric_results,
        "limitations": [
            "Results apply only to the current labeled dataset.",
            "The tricky category is scored as negative by convention.",
            "This benchmark does not establish real-world detection accuracy.",
            "Tool configurations and versions should be documented separately.",
        ],
    }
    with (RESULTS_DIR / "benchmark_report.json").open(
        "w", encoding="utf-8"
    ) as handle:
        json.dump(report, handle, indent=2)

    print(f"\nEvaluation completed: {len(records)} examples")
    print(f"Label counts: {report['label_counts']}")
    print("Scoring: unsafe = positive; safe and tricky = negative")

    for name, metrics in metric_results.items():
        print(
            f"\n{name}: "
            f"TP={metrics['TP']} FP={metrics['FP']} "
            f"FN={metrics['FN']} TN={metrics['TN']} "
            f"precision={metrics['precision']:.4f} "
            f"recall={metrics['recall']:.4f} "
            f"F1={metrics['f1_score']:.4f}"
        )
        print(f"  Category breakdown: {metrics['per_category']}")

    print("\nGenerated reports:")
    for name in (
        "summary.csv",
        "comparison_summary.csv",
        "bandit_summary.json",
        "semgrep_summary.json",
        "sqlguard_summary.json",
        "benchmark_report.json",
    ):
        print(f"  results/{name}")


if __name__ == "__main__":
    run_evaluation()
