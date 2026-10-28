
import ast
import tempfile
import unittest
from pathlib import Path

from sqlguard.analysis.taint import analyze_file
from sqlguard.repair.repair_v0 import repair_file


class SQLGuardRepairTests(unittest.TestCase):
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

    def test_supported_query_is_repaired(self):
        source = self.write_source("vulnerable.py", self.vulnerable_source())
        output = self.root / "repaired.py"

        result = repair_file(source, output)

        self.assertTrue(result["success"], result["message"])
        self.assertTrue(output.exists())

        repaired_code = output.read_text(encoding="utf-8")
        ast.parse(repaired_code)

        self.assertIn("username = ?", repaired_code)
        self.assertIn("(username,)", repaired_code)

    def test_original_file_is_preserved(self):
        original_code = self.vulnerable_source()
        source = self.write_source("vulnerable.py", original_code)
        output = self.root / "repaired.py"

        result = repair_file(source, output)

        self.assertTrue(result["success"], result["message"])
        self.assertEqual(source.read_text(encoding="utf-8"), original_code)

    def test_repaired_file_has_no_current_analyzer_finding(self):
        source = self.write_source("vulnerable.py", self.vulnerable_source())
        output = self.root / "repaired.py"

        result = repair_file(source, output)

        self.assertTrue(result["success"], result["message"])
        self.assertEqual(analyze_file(str(output)), [])

    def test_unsupported_fstring_is_not_modified(self):
        source_code = '''def find_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
'''
        source = self.write_source("unsupported.py", source_code)
        output = self.root / "unsupported_repaired.py"

        result = repair_file(source, output)

        self.assertFalse(result["success"])
        self.assertFalse(output.exists())
        self.assertEqual(source.read_text(encoding="utf-8"), source_code)

    def test_same_input_and_output_path_is_rejected(self):
        source = self.write_source("vulnerable.py", self.vulnerable_source())
        original_code = source.read_text(encoding="utf-8")

        result = repair_file(source, source)

        self.assertFalse(result["success"])
        self.assertEqual(source.read_text(encoding="utf-8"), original_code)

    def test_query_with_existing_parameters_is_rejected(self):
        source_code = '''def find_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query, (username,))
'''
        source = self.write_source("existing_params.py", source_code)
        output = self.root / "existing_params_repaired.py"

        result = repair_file(source, output)

        self.assertFalse(result["success"])
        self.assertFalse(output.exists())
        self.assertEqual(source.read_text(encoding="utf-8"), source_code)

    def test_reassignment_of_parameter_is_rejected(self):
        source_code = '''def find_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    username = "alice"
    cursor.execute(query)
'''
        source = self.write_source("parameter_reassigned.py", source_code)
        output = self.root / "parameter_reassigned_repaired.py"

        result = repair_file(source, output)

        self.assertFalse(result["success"])
        self.assertFalse(output.exists())
        self.assertEqual(source.read_text(encoding="utf-8"), source_code)

    def test_reassignment_of_query_is_rejected(self):
        source_code = '''def find_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    query = "SELECT * FROM users"
    cursor.execute(query)
'''
        source = self.write_source("query_reassigned.py", source_code)
        output = self.root / "query_reassigned_repaired.py"

        result = repair_file(source, output)

        self.assertFalse(result["success"])
        self.assertFalse(output.exists())
        self.assertEqual(source.read_text(encoding="utf-8"), source_code)

    def test_multiple_execute_calls_are_rejected(self):
        source_code = '''def find_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    another_cursor.execute(query)
'''
        source = self.write_source("multiple_execute.py", source_code)
        output = self.root / "multiple_execute_repaired.py"

        result = repair_file(source, output)

        self.assertFalse(result["success"])
        self.assertFalse(output.exists())
        self.assertEqual(source.read_text(encoding="utf-8"), source_code)

    def test_invalid_python_is_rejected(self):
        source = self.write_source("invalid.py", "def broken(:\n    pass\n")
        output = self.root / "invalid_repaired.py"

        result = repair_file(source, output)

        self.assertFalse(result["success"])
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
