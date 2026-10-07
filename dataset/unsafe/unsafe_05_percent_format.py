"""
Unsafe Case 5: Legacy % string formatting operator with untrusted input.
Using %s interpolation into SQL strings leads directly to injection vulnerabilities.
"""
import sqlite3

def find_employees_by_department(dept_name: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT id, name, salary FROM employees WHERE department = '%s'" % dept_name
    cursor.execute(query)
    return cursor.fetchall()

if __name__ == "__main__":
    department = input("Department: ")
    print(find_employees_by_department(department))
