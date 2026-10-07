"""
Safe Case 2: Parameterized SQL query using named ':name' placeholders.
User input is supplied safely via a parameter mapping dictionary.
"""
import sqlite3

def get_user_by_username(username: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT id, username FROM users WHERE username = :uname AND active = 1"
    cursor.execute(query, {"uname": username})
    return cursor.fetchall()

if __name__ == "__main__":
    uname = input("Enter username: ")
    print(get_user_by_username(uname))
