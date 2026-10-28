"""Intentionally vulnerable demonstration example. Do not use in production."""
import sqlite3

def find_user(username):
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

if __name__ == '__main__':
    user = input('Username: ')
    print(find_user(user))
