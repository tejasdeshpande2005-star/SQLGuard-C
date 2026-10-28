"""
Tricky Case 1: User input is collected but never flows into the SQL sink.
Input is used solely for logging/printing, while the executed query is static.
Naive source-presence checks will raise false positives.
"""
import sqlite3

def audit_and_fetch_active_roles():
    search_term = input("Search term: ")
    print(f"User searched for keyword: {search_term}")  # Input consumed here

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # SQL query is completely constant; search_term never reaches this sink
    cursor.execute("SELECT role_id, role_name FROM roles WHERE is_enabled = 1")
    return cursor.fetchall()

if __name__ == "__main__":
    print(audit_and_fetch_active_roles())
