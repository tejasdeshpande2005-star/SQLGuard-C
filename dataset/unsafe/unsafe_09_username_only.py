
import sqlite3

def search_users():
    username = input("Enter username: ")
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
