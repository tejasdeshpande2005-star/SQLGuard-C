
"""End-to-end repair and verification workflow for SQLGuard-C.

The SQLite checks demonstrate parameterized-query behavior. They do not
execute arbitrary repaired application files and do not prove that a
complete application is secure.
"""

import argparse
import sqlite3
from pathlib import Path

from sqlguard.analysis.taint import analyze_file
from sqlguard.repair.repair_v0 import repair_file


def verify_parameterized_query():
    """Compare unsafe concatenation with safe parameterized SQL."""
    connection = sqlite3.connect(":memory:")

    try:
        cursor = connection.cursor()
        cursor.execute("CREATE TABLE users (username TEXT NOT NULL)")
        cursor.executemany(
            "INSERT INTO users(username) VALUES (?)",
            [("alice",), ("bob",)],
        )

        payload = "' OR '1'='1"

        # Safe case: user input is supplied as data, not SQL syntax.
        cursor.execute(
            "SELECT username FROM users WHERE username = ?",
            (payload,),
        )
        malicious_parameterized_rows = cursor.fetchall()

        # Control case: an ordinary username should still work.
        cursor.execute(
            "SELECT username FROM users WHERE username = ?",
            ("alice",),
        )
        normal_rows = cursor.fetchall()

        # Demonstration only: intentionally vulnerable query construction.
        # Never use this pattern in production code.
        unsafe_query = (
            "SELECT username FROM users WHERE username = '"
            + payload
            + "'"
        )
        cursor.execute(unsafe_query)
        unsafe_rows = cursor.fetchall()

        payload_is_literal = len(malicious_parameterized_rows) == 0
        normal_query_works = normal_rows == [("alice",)]
        unsafe_control_exposes_issue = len(unsafe_rows) > 1

        passed = (
            payload_is_literal
            and normal_query_works
            and unsafe_control_exposes_issue
        )

        return {
            "payload": payload,
            "parameterized_rows_returned": len(
                malicious_parameterized_rows
            ),
            # Backward-compatible key used by the existing tests.
            "rows_returned": len(malicious_parameterized_rows),
            "normal_query_rows": [list(row) for row in normal_rows],
            "normal_query_passed": normal_query_works,
            "unsafe_query_rows_returned": len(unsafe_rows),
            "unsafe_control_passed": unsafe_control_exposes_issue,
            "passed": passed,
            "explanation": (
                "The payload returned no rows in the parameterized query; "
                "the legitimate username returned its expected row; and "
                "the intentionally unsafe control demonstrated the risk "
                "of concatenating SQL input."
                if passed
                else (
                    "One or more SQLite checks failed. Inspect the "
                    "parameterized query and unsafe control separately."
                )
            ),
        }
    finally:
        connection.close()


def run_pipeline(input_path, output_path=None):
    """Detect, repair, re-analyze, and run an independent SQLite check."""
    source = Path(input_path)

    if output_path is None:
        output_path = source.with_name(source.stem + "_repaired.py")

    destination = Path(output_path)

    print("\n========== SQLGuard-C REPORT ==========\n")

    try:
        original_findings = analyze_file(str(source))
    except (OSError, ValueError, SyntaxError, UnicodeError) as exc:
        print("[FAIL] Original analysis:", exc)
        return 1

    if not original_findings:
        print("[FAIL] No vulnerability detected in original file.")
        print("Use a known vulnerable example for this demonstration.")
        return 1

    print(
        f"[PASS] Original vulnerability detected "
        f"({len(original_findings)} finding(s))"
    )

    repair_result = repair_file(str(source), str(destination))

    if not repair_result["success"]:
        print("[FAIL] Repair:", repair_result["message"])
        return 1

    print("[PASS] Candidate repaired file created:", destination)

    try:
        repaired_findings = analyze_file(str(destination))
    except (OSError, ValueError, SyntaxError, UnicodeError) as exc:
        print("[FAIL] Re-analysis:", exc)
        return 1

    if repaired_findings:
        print(
            "[FAIL] Repaired file still has "
            f"{len(repaired_findings)} potential finding(s)."
        )
        for finding in repaired_findings:
            print(f"  - {finding}")
        return 1

    print("[PASS] No SQL injection flow detected after repair")

    test_result = verify_parameterized_query()

    if test_result["passed"]:
        print("[PASS] SQLite parameterized-query behavior checks")
    else:
        print("[FAIL] SQLite parameterized-query behavior checks")

    print(test_result["explanation"])
    print("\nImportant limitations:")
    print("- The repaired application source is not executed by this workflow.")
    print("- The SQLite check is an independent demonstration.")
    print("- A clean static-analysis result does not prove application safety.")
    print("- Review and test the candidate repair in its real application.")

    passed = test_result["passed"]

    print(
        "\nOverall: DEMONSTRATION CHECKS PASSED"
        if passed
        else "\nOverall: DEMONSTRATION CHECKS FAILED"
    )
    print("=======================================\n")

    return 0 if passed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SQLGuard-C end-to-end repair demonstration"
    )
    parser.add_argument(
        "file",
        nargs="?",
        default="examples/vulnerable_example.py",
        help="Vulnerable Python example to repair",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output path for repaired code",
    )
    args = parser.parse_args()

    raise SystemExit(run_pipeline(args.file, args.output))
