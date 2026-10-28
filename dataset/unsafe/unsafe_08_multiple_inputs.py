
import sqlite3

def search_users():
    username = input("Enter username: ")
    email = input("Enter email: ")

    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND email = '"
        + email
        + "'"
    )

    cursor.execute(query)
