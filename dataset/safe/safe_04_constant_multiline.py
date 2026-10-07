"""
Safe Case 4: Static multiline SQL query containing joins and aggregations.
Even though the query is complex, it contains no variable interpolations.
"""
import sqlite3

def generate_monthly_report():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = """
        SELECT departments.name, COUNT(employees.id) AS total_emp
        FROM departments
        JOIN employees ON departments.id = employees.dept_id
        GROUP BY departments.name
        ORDER BY total_emp DESC
    """
    cursor.execute(query)
    return cursor.fetchall()

if __name__ == "__main__":
    print(generate_monthly_report())
