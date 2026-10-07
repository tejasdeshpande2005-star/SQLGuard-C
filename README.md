# SQLGuard-C

**A Compiler-Based Tool to Detect, Explain, Repair and Verify SQL Injection in Python Code**

## Overview

SQLGuard-C is a static analysis tool that uses compiler-design techniques to detect SQL injection vulnerabilities in Python source code. It parses Python files into an AST, performs taint propagation analysis, explains the vulnerability path, suggests repairs, and verifies fixes via automated attack testing.

## Project Structure

```
SQLGuard-C/
├── sqlguard/             # Core tool package
│   ├── cli.py            # Command-line interface entry point
│   ├── frontend/         # Python AST parsing and traversal
│   ├── analysis/         # Taint propagation and SQL injection detection
│   ├── explain/          # Source-to-sink path explanation
│   ├── repair/           # Automated repair prototype
│   └── verification/     # Before/after attack verification
├── tests/                # Test programs (vulnerable, safe, repaired)
├── dataset/              # Labelled dataset
├── examples/             # Demonstration examples
└── docs/                 # Architecture and documentation
```

## Team

| Member              | Responsibilities                                                        |
|---------------------|-------------------------------------------------------------------------|
| Inba Senthil Kumar  | Problem/background, labelled dataset, Bandit/Semgrep comparison, setup  |
| Vidit Agrawal       | Compiler frontend, AST walker, symbol table, CFG, taint propagation     |
| Tejas Deshpande     | Path explanation, repair prototype, verification prototype, novelty     |

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Analyze a Python file for SQL injection vulnerabilities
sqlguard analyze file.py
```

## License

This project is for academic/educational purposes.
