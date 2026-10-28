
# SQLGuard-C Benchmark

## Objective

Evaluate SQLGuard-C's SQL injection detection against a labeled Python
dataset and compare its results with Bandit and Semgrep.

## Dataset

The current dataset contains 25 examples:

- 7 labeled `safe`
- 12 labeled `unsafe`
- 6 labeled `tricky`

The labels are maintained in `dataset/labels.csv`. Each entry must
correspond to an existing source file under `dataset/`.

## Scoring protocol

For binary metrics, `unsafe` is the positive class. `safe` and `tricky`
are treated as negative examples.

- True positive (TP): an unsafe example is flagged.
- False positive (FP): a safe or tricky example is flagged.
- False negative (FN): an unsafe example is not flagged.
- True negative (TN): a safe or tricky example is not flagged.

The evaluator also reports safe and tricky cases separately so that
the effect of the scoring convention remains visible.

Precision = TP / (TP + FP)

Recall = TP / (TP + FN)

F1 = 2 * Precision * Recall / (Precision + Recall)

If a metric has a zero denominator, the evaluator reports 0.

## Running the evaluation

Run commands from the repository root.

1. Install the project's development dependencies, including pytest,
   Bandit, and Semgrep, if they are not already installed.
2. Generate fresh Bandit and Semgrep JSON results using the project's
   configured scans.
3. Save those results at the paths configured in `evaluate_benchmarks.py`.
4. Run:

   `py -3.12 evaluate_benchmarks.py`

5. Run the test suite:

   `py -3.12 -m pytest -q`

## Generated outputs

- `results/summary.csv`: per-example classifications.
- `results/comparison_summary.csv`: comparison table.
- `results/bandit_summary.json`: Bandit metrics and findings.
- `results/semgrep_summary.json`: Semgrep metrics and findings.
- `results/sqlguard_summary.json`: SQLGuard-C metrics and findings.
- `results/benchmark_report.json`: combined metrics and limitations.

## Interpreting results

The benchmark measures behavior on the current labeled examples only.
A perfect score on a small, manually constructed dataset does not establish
perfect detection on unseen code or production applications.

Fair comparisons require the same source files, labels, and a documented
configuration for each tool. Record tool versions, rule sets, commands,
and dataset changes for reproducibility.

## Known limitations to investigate

- Interprocedural data flow and function return values.
- Aliases and indirect assignments.
- Conditional and path-sensitive taint propagation.
- Dynamic SQL construction and database-specific syntax.
- Query builders, ORM-generated SQL, and custom database wrappers.
- Repair correctness and preservation of application behavior.

The analyzer's results should be treated as static-analysis findings,
not as a substitute for code review or security testing.
