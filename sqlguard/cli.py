"""Command-line interface for SQLGuard-C."""
import argparse, json, sys
from sqlguard.analysis.taint import analyze_file
from sqlguard.explain.path_explainer import explain_finding
from sqlguard.repair.repair_v0 import repair_file


def main():
    parser = argparse.ArgumentParser(
        prog="sqlguard",
        description="SQLGuard-C: detect and explain possible SQL injection in Python code."
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # Analyze command
    a = sub.add_parser("analyze", help="Analyze a Python file")
    a.add_argument("file")
    a.add_argument("--json", action="store_true", help="Output findings as JSON")

    # Repair command
    r = sub.add_parser("repair", help="Repair a supported SQL query")
    r.add_argument("file", help="Original Python file")
    r.add_argument(
        "-o", "--output",
        default=None,
        help="Output path for the repaired file"
    )

    args = parser.parse_args()

    # Handle repair separately
    if args.command == "repair":
        import os

        output = args.output or (
            os.path.splitext(args.file)[0] + "_repaired.py"
        )

        result = repair_file(args.file, output)

        if result["success"]:
            print("[SQLGuard-C] " + result["message"])
            print("Output:", result["output"])
            print("Next: re-analyze the output and verify its behavior.")
            return 0

        print("[SQLGuard-C] Repair not applied:", result["message"])
        return 1

    # Existing analysis command
    try:
        findings = analyze_file(args.file)
    except (OSError, ValueError) as e:
        print(f"[SQLGuard-C] Error: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))

    elif findings:
        print(
            f"SQLGuard-C analysis: {args.file}\n"
            f"Found {len(findings)} potential SQL injection issue(s).\n"
        )

        for i, f in enumerate(findings, 1):
            if i > 1:
                print("\n" + "-" * 60 + "\n")
            print(explain_finding(f))

    else:
        print(
            f"SQLGuard-C analysis: {args.file}\n"
            "No SQL injection flow detected by the current prototype."
        )
        print(
            "Note: this prototype uses heuristic, intraprocedural analysis; "
            "a clean result is not a security guarantee."
        )

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
