
"""FastAPI backend for the SQLGuard-C dashboard."""

import ast
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from sqlguard.analysis.taint import analyze_file

app = FastAPI(title="SQLGuard-C API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

MAX_SOURCE_CHARACTERS = 100_000


class AnalyzeRequest(BaseModel):
    code: str = Field(min_length=1, max_length=MAX_SOURCE_CHARACTERS)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "SQLGuard-C"}


@app.post("/api/analyze")
def analyze_code(request: AnalyzeRequest):
    """Statically analyze submitted Python source without executing it."""
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="Enter Python code to analyze.")

    # Validate syntax first, so malformed source gets a useful error.
    try:
        ast.parse(request.code)
    except SyntaxError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "syntax_error",
                "message": exc.msg,
                "line": exc.lineno,
                "column": exc.offset,
            },
        ) from exc

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            encoding="utf-8",
            delete=False,
        ) as temp_file:
            temp_file.write(request.code)
            temp_path = Path(temp_file.name)

        findings = analyze_file(str(temp_path))
        serialized = []

        for finding in findings:
            if hasattr(finding, "to_dict"):
                item = finding.to_dict()
            else:
                item = {
                    "line": getattr(finding, "line", None),
                    "severity": getattr(finding, "severity", "medium"),
                    "message": getattr(finding, "message", str(finding)),
                    "source": getattr(finding, "source", None),
                    "sink": getattr(finding, "sink", None),
                    "variable": getattr(finding, "variable", None),
                    "path": getattr(finding, "path", None),
                    "repair": getattr(finding, "repair", None),
                }

            # Avoid showing the temporary system path in the dashboard.
            item["file"] = "submitted_code.py"
            serialized.append(item)

        count = len(serialized)

        return {
            "success": True,
            "filename": "submitted_code.py",
            "findings_count": count,
            "status": "vulnerable" if count else "no_findings",
            "findings": serialized,
            "message": (
                "Potential SQL injection findings were detected."
                if count
                else "No SQL injection findings were reported by the analyzer."
            ),
            "note": (
                "Static analysis only. Submitted code was not executed. "
                "No findings does not prove the code is secure."
            ),
        }

    except HTTPException:
        raise
    except Exception as exc:
        # Log the actual error in the backend terminal for debugging.
        print(f"SQLGuard-C analysis error: {type(exc).__name__}: {exc}")
        raise HTTPException(
            status_code=500,
            detail="Analysis failed. Check the backend terminal.",
        ) from exc
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
