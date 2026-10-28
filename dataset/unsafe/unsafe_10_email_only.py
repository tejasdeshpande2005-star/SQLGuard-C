
import sqlite3

def search_users():
    email = input("Enter email: ")
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    query = "SELECT * FROM users WHERE email = '" + email + "'"
    cursor.execute(query)
