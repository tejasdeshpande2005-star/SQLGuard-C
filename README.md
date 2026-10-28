# SQLGuard-C

**A compiler-inspired prototype to detect, explain, and help repair SQL injection in Python code.**

SQLGuard-C parses Python source into an Abstract Syntax Tree (AST), tracks simple untrusted-input flows through assignments/string construction, and reports potential flows into SQL execution calls. It provides source-to-sink explanations and parameterization repair guidance.

## Quick start (Python 3.10+ recommended)

From the project root:

```bash
python -m sqlguard.cli analyze examples/vulnerable_example.py
python -m sqlguard.cli analyze examples/safe_example.py
python -m sqlguard.cli analyze dataset/unsafe/unsafe_01_concat_basic.py
python -m sqlguard.cli analyze dataset/safe/safe_01_param_qmark.py
python -m sqlguard.cli analyze examples/vulnerable_example.py --json
python -m sqlguard.verification.attack_runner
```

No third-party dependencies are required for the core prototype.

## Current prototype scope

- Python AST parsing and simple intraprocedural taint propagation.
- Detects common concatenation, f-string, `%` formatting, and `.format()` flows when the resulting SQL string reaches a cursor-like `execute()` call.
- Reports source, sink, line, taint path, and recommended parameterized-query repair.
- Includes a SQLite parameter-binding verification demonstration.

## Important limitations

This is an academic prototype, not a production security scanner. It does not implement a complete control-flow graph, interprocedural analysis, full alias analysis, or safe automatic source rewriting. It may miss flows through function parameters/returns or complex objects and can produce false positives/negatives. A clean result is not proof that a program is secure. Always use parameterized queries and review results manually.

## Benchmark comparison

`evaluate_benchmarks.py` compares existing Bandit and Semgrep raw outputs against `dataset/labels.csv`. Ensure the tools have been run and the raw JSON files are current before using the reported metrics. Those metrics describe the saved tool outputs, not SQLGuard-C's detection performance.
