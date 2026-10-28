"""
Tricky Case 6: Vulnerable query construction resides inside unreachable dead code.
Control-flow insensitive tools flag the dead branch as vulnerable.
"""
import sqlite3

def query_user_profile(user_id: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    if False:
        # Dead code: unreachable vulnerable execution
        dead_query = "SELECT * FROM profiles WHERE uid = '" + user_id + "'"
        cursor.execute(dead_query)

    # Active execution path is parameterized and safe
    cursor.execute("SELECT * FROM profiles WHERE uid = ?", (user_id,))
    return cursor.fetchone()

if __name__ == "__main__":
    uid = input("Enter User ID: ")
    print(query_user_profile(uid))
