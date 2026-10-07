"""
Unsafe Case 3: Direct f-string interpolation with untrusted input.
Python f-strings interpolate expressions directly into the query string.
"""
import sqlite3

def get_account_details(account_id: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT account_id, balance, owner FROM accounts WHERE account_id = '{account_id}'"
    cursor.execute(query)
    return cursor.fetchone()

if __name__ == "__main__":
    acc_id = input("Enter account ID: ")
    print(get_account_details(acc_id))
