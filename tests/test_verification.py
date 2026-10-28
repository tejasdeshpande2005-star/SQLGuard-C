
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlguard.verification.attack_runner import (
    run_pipeline,
    verify_parameterized_query,
)


class SQLGuardVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def write_source(self, filename, source):
        path = self.root / filename
        path.write_text(source, encoding="utf-8")
        return path

    def vulnerable_source(self):
        return '''import sqlite3

def find_user(username):
    cursor = sqlite3.connect(":memory:").cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
'''

    def test_parameterized_query_treats_payload_as_literal(self):
        result = verify_parameterized_query()

        self.assertTrue(result["passed"])
        self.assertEqual(result["parameterized_rows_returned"], 0)
        self.assertEqual(result["rows_returned"], 0)

    def test_legitimate_parameterized_query_still_works(self):
        result = verify_parameterized_query()

        self.assertTrue(result["normal_query_passed"])
        self.assertEqual(result["normal_query_rows"], [["alice"]])

    def test_unsafe_control_demonstrates_injection_behavior(self):
        result = verify_parameterized_query()

        self.assertTrue(result["unsafe_control_passed"])
        self.assertGreater(result["unsafe_query_rows_returned"], 1)

    def test_pipeline_rejects_safe_input(self):
        source = self.write_source(
            "safe.py",
            '''def find_user(username):
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
''',
        )
        output = self.root / "safe_repaired.py"

        with patch("builtins.print"):
            result = run_pipeline(source, output)

        self.assertEqual(result, 1)
        self.assertFalse(output.exists())

    def test_pipeline_rejects_missing_input(self):
        missing = self.root / "does_not_exist.py"
        output = self.root / "repaired.py"

        with patch("builtins.print"):
            result = run_pipeline(missing, output)

        self.assertEqual(result, 1)
        self.assertFalse(output.exists())

    def test_pipeline_repairs_supported_vulnerable_input(self):
        source = self.write_source("vulnerable.py", self.vulnerable_source())
        output = self.root / "repaired.py"

        with patch("builtins.print"):
            result = run_pipeline(source, output)

        self.assertEqual(result, 0)
        self.assertTrue(output.exists())

    def test_pipeline_does_not_claim_success_for_unsupported_pattern(self):
        source = self.write_source(
            "unsupported.py",
            '''def find_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
''',
        )
        output = self.root / "unsupported_repaired.py"

        with patch("builtins.print"):
            result = run_pipeline(source, output)

        self.assertEqual(result, 1)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
