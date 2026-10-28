"""
Unsafe Case 4: Multiline f-string with untrusted input in UPDATE query.
Tainted values are directly formatted into both SET and WHERE clauses.
"""
import sqlite3

def update_user_email(user_id: str, new_email: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"""
        UPDATE users
        SET email = '{new_email}'
        WHERE user_id = {user_id}
    """
    cursor.execute(query)
    conn.commit()

if __name__ == "__main__":
    uid = input("User ID: ")
    email = input("New Email: ")
    update_user_email(uid, email)
