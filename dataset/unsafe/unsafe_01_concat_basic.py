"""
Unsafe Case 1: Direct string concatenation (+) with untrusted input in SQL sink.
Vulnerable to authentication bypass (e.g. admin' --).
"""
import sqlite3

def authenticate_user(username: str, password: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT id, username FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()

if __name__ == "__main__":
    uname = input("Username: ")
    pwd = input("Password: ")
    print(authenticate_user(uname, pwd))
