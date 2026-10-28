"""Safe pattern demonstration using SQLite parameter binding."""
import sqlite3

def find_user(username):
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    query = 'SELECT * FROM users WHERE username = ?'
    cursor.execute(query, (username,))
    return cursor.fetchall()

if __name__ == '__main__':
    user = input('Username: ')
    print(find_user(user))
