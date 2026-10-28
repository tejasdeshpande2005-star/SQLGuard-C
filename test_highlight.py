from sqlguard.analysis.taint import analyze_source

code = """
def search(cursor):
    username = input("Username: ")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
"""

findings = analyze_source(code)

for finding in findings:
    print(finding.to_dict())
