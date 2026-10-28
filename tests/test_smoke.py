
import unittest

from sqlguard.analysis.taint import analyze_source


class SQLGuardSmokeTests(unittest.TestCase):

    def test_detects_concat(self):
        source = '''import sqlite3

def f(name):
    c = sqlite3.connect(":memory:").cursor()
    q = "SELECT * FROM users WHERE name = '" + name + "'"
    c.execute(q)
'''
        self.assertTrue(analyze_source(source))

    def test_parameterized_query_is_not_flagged(self):
        source = '''import sqlite3

def f(name):
    c = sqlite3.connect(":memory:").cursor()
    c.execute("SELECT * FROM users WHERE name = ?", (name,))
'''
        self.assertFalse(analyze_source(source))

    def test_custom_execute_not_flagged(self):
        source = '''class E:
    def execute(self, x):
        pass

def f(x):
    e = E()
    e.execute("run_" + x)
'''
        self.assertFalse(analyze_source(source))

    def test_dead_false_branch_ignored(self):
        source = '''import sqlite3

def f(name):
    c = sqlite3.connect(":memory:").cursor()
    if False:
        c.execute("SELECT * FROM users WHERE name='" + name + "'")
    c.execute("SELECT 1")
'''
        self.assertFalse(analyze_source(source))

    def test_detects_tainted_sql_fragment_with_parameterized_value(self):
        source = '''import sqlite3

def search_users():
    username = input("Username: ")
    sort_column = input("Sort by: ")

    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    query = (
        "SELECT * FROM users WHERE username = ? ORDER BY "
        + sort_column
    )
    cursor.execute(query, (username,))
'''
        findings = analyze_source(source, "mixed_parameterization_test.py")

        self.assertTrue(findings)
        self.assertTrue(any("execute" in f.sink for f in findings))

    def test_safe_whitelist_lookup_not_flagged(self):
        source = '''
import sqlite3

ALLOWED_SORT_COLUMNS = {
    "name": "name",
    "price": "price",
    "date": "created_at",
}

def list_products(sort_by, category_id):
    column = ALLOWED_SORT_COLUMNS.get(sort_by, "id")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT id, name, price FROM products WHERE category_id = ? ORDER BY {column}"
    cursor.execute(query, (category_id,))
'''
        self.assertFalse(analyze_source(source, "safe_whitelist_test.py"))

    def test_safe_generated_placeholders_not_flagged(self):
        source = '''
import sqlite3

def get_products_by_ids(id_list):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    placeholders = ", ".join(["?"] * len(id_list))
    query = f"SELECT id, name FROM items WHERE id IN ({placeholders})"
    cursor.execute(query, id_list)
'''
        self.assertFalse(analyze_source(source, "safe_placeholder_test.py"))

    def test_detects_mixed_parameterization(self):
        source = '''
import sqlite3

def search_users():
    username = input("Enter username: ")
    sort_column = input("Sort by column: ")

    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    query = (
        "SELECT * FROM users WHERE username = ? ORDER BY "
        + sort_column
    )
    cursor.execute(query, (username,))
'''
        findings = analyze_source(source, "mixed_parameterization_test.py")

        self.assertTrue(findings)
        self.assertTrue(
            any(f.sink == "cursor.execute()" for f in findings)
        )

    def test_multiple_tainted_inputs_appear_in_path(self):
        source = '''
import sqlite3

def search_users():
    username = input("Username: ")
    email = input("Email: ")

    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND email = '"
        + email
        + "'"
    )
    cursor.execute(query)
'''
        findings = analyze_source(source, "multiple_inputs_test.py")

        self.assertTrue(findings, "Expected a SQL injection finding")

        finding = findings[0]
        path_text = " ".join(finding.path)

        self.assertIn("username", path_text)
        self.assertIn("email", path_text)
        self.assertIn("execute", finding.sink)


if __name__ == "__main__":
    unittest.main()
