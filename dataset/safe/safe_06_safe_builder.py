"""
Safe Case 6: Safe query construction with dynamic IN clause placeholders.
The string formatting injects only trusted '?' placeholder markers,
while user-provided values are safely passed as parameters.
"""
import sqlite3

def get_products_by_ids(id_list: list):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # Generate trusted placeholder string like "?, ?, ?"
    placeholders = ", ".join(["?"] * len(id_list))
    query = f"SELECT id, name FROM items WHERE id IN ({placeholders})"
    cursor.execute(query, id_list)
    return cursor.fetchall()

if __name__ == "__main__":
    sample_ids = ["1", "2", "3"]
    print(get_products_by_ids(sample_ids))
