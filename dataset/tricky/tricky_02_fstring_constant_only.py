"""
Tricky Case 2: f-string query construction using only trusted compile-time constants.
AST-only linters flagging all f-string SQL queries will trigger a false positive.
"""
import sqlite3

TABLE_NAME = "audit_records"
DEFAULT_LIMIT = 50

def get_recent_audit_records():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # f-string interpolates only module constants, no untrusted taint
    query = f"SELECT id, action, timestamp FROM {TABLE_NAME} LIMIT {DEFAULT_LIMIT}"
    cursor.execute(query)
    return cursor.fetchall()

if __name__ == "__main__":
    print(get_recent_audit_records())
