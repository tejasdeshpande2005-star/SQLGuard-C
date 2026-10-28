def find_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)