# SQLGuard-C Architecture

## Compiler Phases

```
Source (.py)
    │
    ▼
┌──────────────┐
│  1. Frontend │   AST parsing & traversal (ast_walker.py)
│              │   Symbol table + basic CFG construction
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  2. Analysis │   Taint propagation (taint.py)
│              │   Source/sink identification
│              │   SQL injection detection
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  3. Explain  │   Source-to-sink path explanation (path_explainer.py)
│              │   Human-readable vulnerability report
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  4. Repair   │   Auto-repair prototype (repair_v0.py)
│              │   String concat → parameterised query
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  5. Verify   │   Before/after attack testing (attack_runner.py)
│              │   SQLite test harness
└──────────────┘
```

## Module Ownership

| Module                   | Owner              |
|--------------------------|--------------------|
| `sqlguard/frontend/`     | Vidit Agrawal      |
| `sqlguard/analysis/`     | Vidit Agrawal      |
| `sqlguard/explain/`      | Tejas Deshpande    |
| `sqlguard/repair/`       | Tejas Deshpande    |
| `sqlguard/verification/` | Tejas Deshpande    |
| `dataset/`               | Inba Senthil Kumar |
| `docs/`                  | All                |

## Data Flow

1. **Input**: Python source file path via CLI (`sqlguard analyze file.py`).
2. **Frontend**: Parse into AST → walk nodes → build symbol table & CFG.
3. **Analysis**: Run taint propagation over the CFG → detect tainted sinks.
4. **Explain**: Convert taint paths into a human-readable report.
5. **Repair**: Generate a patched version of the source using parameterised queries.
6. **Verify**: Execute attack payloads against original and repaired code; compare.
