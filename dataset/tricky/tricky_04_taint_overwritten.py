"""
Tricky Case 4: Tainted variable is overwritten with a safe constant before sink.
Without flow-sensitive taint tracking (kill sets), analyzers produce false positives.
"""
import sqlite3

def get_config_value():
    user_setting = input("Enter config key: ")

    # Overwrite tainted variable with a known safe constant
    user_setting = "max_connections"

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT val FROM settings WHERE key = '{user_setting}'"
    cursor.execute(query)
    return cursor.fetchone()

if __name__ == "__main__":
    print(get_config_value())
