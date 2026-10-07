"""
Tricky Case 5: String formatting is used for logging, while SQL query is parameterized.
Analyzers flagging the presence of .format() near cursor.execute() produce false positives.
"""
import sqlite3
import logging

logging.basicConfig(level=logging.INFO)

def fetch_user_record(user_id: str):
    # .format() is used exclusively on a logging string
    log_message = "Audit Log: query initiated for user id {}".format(user_id)
    logging.info(log_message)

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # SQL sink itself is safe and parameterized
    cursor.execute("SELECT id, name FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

if __name__ == "__main__":
    uid = input("User ID: ")
    print(fetch_user_record(uid))
