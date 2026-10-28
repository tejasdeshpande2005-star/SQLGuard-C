
import sqlite3

def fetch_user(cursor, username):
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))

def main():
    username = input("Enter username: ")
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()
    fetch_user(cursor, username)

if __name__ == "__main__":
    main()
