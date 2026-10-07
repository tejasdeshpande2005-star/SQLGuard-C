"""
Safe Case 3: Constant SQL query with no dynamic input or string construction.
The query string literal is completely static and safe.
"""
import sqlite3

def get_all_active_products():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT id, name, price, stock FROM products WHERE stock > 0"
    cursor.execute(query)
    return cursor.fetchall()

if __name__ == "__main__":
    print(get_all_active_products())
