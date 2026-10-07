"""
sqlguard.frontend.ast_walker
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Responsible for:
  - Parsing Python source files into an AST (using the built-in `ast` module).
  - Walking/traversing the AST to extract relevant nodes such as:
      * Function definitions
      * Variable assignments
      * Calls to execute(), cursor.execute(), etc.
      * String concatenation and f-string usage in SQL contexts.
  - Building a symbol table for variable tracking.
  - Constructing a basic Control Flow Graph (CFG).

Owner: Vidit Agrawal

Implementation pending.
"""
