"""
sqlguard.cli
~~~~~~~~~~~~

Command-line interface entry point for SQLGuard-C.

Intended usage:
    sqlguard analyze <file.py>

This module will parse CLI arguments and dispatch to the appropriate
analysis pipeline.  Full implementation pending.
"""

import argparse
import sys


def main():
    """Entry point for the sqlguard CLI."""
    parser = argparse.ArgumentParser(
        prog="sqlguard",
        description="SQLGuard-C: Detect, explain, repair and verify SQL injection in Python code.",
    )
    subparsers = parser.add_subparsers(dest="command")

    # --- analyze sub-command (placeholder) ---
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a Python file for SQL injection vulnerabilities.",
    )
    analyze_parser.add_argument(
        "file",
        help="Path to the Python file to analyze.",
    )

    args = parser.parse_args()

    if args.command == "analyze":
        print(f"[SQLGuard-C] Analysis of '{args.file}' is not yet implemented.")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
