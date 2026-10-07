"""
Unsafe Case 7: str.format() method using named placeholders.
Untrusted user input passed as keyword arguments to format template.
"""
import sqlite3

def delete_session(session_token: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "DELETE FROM user_sessions WHERE token = '{token}'".format(token=session_token)
    cursor.execute(query)
    conn.commit()

if __name__ == "__main__":
    token = input("Session token: ")
    delete_session(token)
