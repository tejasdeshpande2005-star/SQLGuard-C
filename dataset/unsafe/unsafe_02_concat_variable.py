"""
Unsafe Case 2: Multi-step string concatenation through intermediate variables (+=).
Tainted data propagates across multiple assignments before reaching execute().
"""
import sqlite3

def search_products(category: str, min_price: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE 1=1"
    query += " AND category = '" + category + "'"
    query += " AND price >= " + min_price
    cursor.execute(query)
    return cursor.fetchall()

if __name__ == "__main__":
    cat = input("Category: ")
    price = input("Min price: ")
    print(search_products(cat, price))
