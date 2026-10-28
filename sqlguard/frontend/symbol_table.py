"""
sqlguard.frontend.symbol_table
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Symbol table for tracking variable definitions, references, and
assigned expression types across a Python source file.

Used by the AST walker to record what each variable was assigned
(constant, input_call, string_concat, fstring, …) and where it
was referenced.  Downstream taint analysis consumes this to
decide whether a variable carries tainted data at each point.

Owner: Vidit Agrawal
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class SymbolEntry:
    """Tracks a single symbol (variable / parameter) across the source."""

    name: str
    definition_lines: List[int] = field(default_factory=list)
    reference_lines: List[int] = field(default_factory=list)
    assigned_types: List[str] = field(default_factory=list)
    # Each element corresponds to the definition at the same index.
    # Possible values: 'constant', 'variable', 'string_concat', 'fstring',
    # 'percent_format', 'format_call', 'input_call', 'call', 'parameter',
    # 'attribute', 'subscript', 'other', 'unknown'

    @property
    def last_assigned_type(self) -> Optional[str]:
        """Most recent expression type assigned to this symbol."""
        return self.assigned_types[-1] if self.assigned_types else None


class SymbolTable:
    """Container for all symbols discovered during AST analysis."""

    def __init__(self) -> None:
        self._symbols: Dict[str, SymbolEntry] = {}

    # -- mutators -----------------------------------------------------------

    def define(self, name: str, line: int, assigned_type: str = "unknown") -> None:
        """Record a variable definition / (re-)assignment."""
        entry = self._symbols.setdefault(name, SymbolEntry(name=name))
        entry.definition_lines.append(line)
        entry.assigned_types.append(assigned_type)

    def reference(self, name: str, line: int) -> None:
        """Record a variable read-reference."""
        entry = self._symbols.setdefault(name, SymbolEntry(name=name))
        entry.reference_lines.append(line)

    # -- queries ------------------------------------------------------------

    def lookup(self, name: str) -> Optional[SymbolEntry]:
        """Return the entry for *name*, or ``None``."""
        return self._symbols.get(name)

    def all_symbols(self) -> Dict[str, SymbolEntry]:
        """Return a shallow copy of the full symbol map."""
        return dict(self._symbols)

    def defined_names(self) -> List[str]:
        """Names that have at least one definition."""
        return [n for n, e in self._symbols.items() if e.definition_lines]

    # -- dunder helpers -----------------------------------------------------

    def __contains__(self, name: str) -> bool:
        return name in self._symbols

    def __len__(self) -> int:
        return len(self._symbols)

    def __repr__(self) -> str:
        return f"SymbolTable({list(self._symbols.keys())})"
