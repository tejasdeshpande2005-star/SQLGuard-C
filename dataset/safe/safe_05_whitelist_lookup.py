"""
Safe Case 5: Safe dynamic query construction using a strict whitelist.
Dynamic identifiers (e.g., sort column) are safely mapped to trusted constants,
and filter values are properly parameterized.
"""
import sqlite3

ALLOWED_SORT_COLUMNS = {
    "name": "name",
    "price": "price",
    "date": "created_at"
}

def list_products(sort_by: str, category_id: int):
    column = ALLOWED_SORT_COLUMNS.get(sort_by, "id")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT id, name, price FROM products WHERE category_id = ? ORDER BY {column}"
    cursor.execute(query, (category_id,))
    return cursor.fetchall()

if __name__ == "__main__":
    sort_key = input("Sort by: ")
    cat_id = input("Category ID: ")
    print(list_products(sort_key, int(cat_id)))
