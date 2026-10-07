"""
Unsafe Case 6: str.format() method with positional placeholder interpolation.
Untrusted input is injected directly via .format(...) into the SQL query string.
"""
import sqlite3

def fetch_order_by_status(status: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT order_id, total, status FROM orders WHERE status = '{}'".format(status)
    cursor.execute(query)
    return cursor.fetchall()

if __name__ == "__main__":
    order_status = input("Order status: ")
    print(fetch_order_by_status(order_status))
