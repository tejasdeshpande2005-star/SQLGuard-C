
import sqlite3

def search_users():
    username = input("Enter username: ")
    sort_column = input("Sort by column: ")

    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    query = (
        "SELECT * FROM users WHERE username = ? ORDER BY "
        + sort_column
    )

    cursor.execute(query, (username,))
