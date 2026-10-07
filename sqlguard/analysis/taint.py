"""
sqlguard.analysis.taint
~~~~~~~~~~~~~~~~~~~~~~~~

Responsible for:
  - Taint propagation analysis over the AST / CFG.
  - Marking user-input sources (e.g., input(), request.args) as tainted.
  - Tracking taint flow through variable assignments and string operations.
  - Detecting when tainted data reaches a SQL execution sink
    (e.g., cursor.execute()).
  - Reporting detected SQL injection vulnerabilities with source/sink info.

Owner: Vidit Agrawal

Implementation pending.
"""
