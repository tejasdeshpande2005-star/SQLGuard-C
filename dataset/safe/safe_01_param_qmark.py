"""
Safe Case 1: Parameterized SQL query using positional '?' placeholders.
User input is bound through DB-API parameters, preventing SQL injection.
"""
import sqlite3

def get_user_by_id(user_id: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT id, username, email FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()

if __name__ == "__main__":
    user_id = input("Enter user ID: ")
    print(get_user_by_id(user_id))
