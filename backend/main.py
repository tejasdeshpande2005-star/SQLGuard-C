"""FastAPI backend for the SQLGuard-C dashboard."""

import ast
import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from sqlguard.analysis.taint import analyze_file
from sqlguard.repair.repair_v0 import repair_file

app = FastAPI(title="SQLGuard-C API", version="1.1.0")

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


class RepairRequest(BaseModel):
    code: str = Field(min_length=1, max_length=MAX_SOURCE_CHARACTERS)


def _parse_source(code: str) -> None:
    if not code.strip():
        raise HTTPException(status_code=400, detail="Enter Python code.")
    try:
        ast.parse(code)
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


def _analyze_source_text(code: str) -> list[Any]:
    """Write source to a temporary file and run the existing analyzer."""
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", encoding="utf-8", delete=False
        ) as temp_file:
            temp_file.write(code)
            temp_path = Path(temp_file.name)
        return analyze_file(str(temp_path))
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def _serialize_finding(finding: Any) -> dict[str, Any]:
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
            "expression": getattr(finding, "expression", None),
            "highlight_ranges": getattr(finding, "highlight_ranges", []),
        }
    item["file"] = "submitted_code.py"
    return item


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "SQLGuard-C"}


@app.post("/api/analyze")
def analyze_code(request: AnalyzeRequest):
    """Statically analyze submitted Python source without executing it."""
    _parse_source(request.code)
    try:
        findings = _analyze_source_text(request.code)
        serialized = [_serialize_finding(finding) for finding in findings]
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
        print(f"SQLGuard-C analysis error: {type(exc).__name__}: {exc}")
        raise HTTPException(
            status_code=500,
            detail="Analysis failed. Check the backend terminal.",
        ) from exc


@app.post("/api/repair")
def generate_repair(request: RepairRequest):
    """
    Generate a repair candidate using the existing limited repair prototype.
    The submitted source is not overwritten or executed.
    """
    _parse_source(request.code)
    source_path = None
    repaired_path = None

    try:
        # The repair module writes to a separate temporary destination.
        with tempfile.TemporaryDirectory(prefix="sqlguard_repair_") as tmp:
            source_path = Path(tmp) / "submitted.py"
            repaired_path = Path(tmp) / "submitted_repaired.py"
            source_path.write_text(request.code, encoding="utf-8")

            original_findings = analyze_file(str(source_path))
            if not original_findings:
                return {
                    "success": False,
                    "message": (
                        "No potential vulnerability was detected. "
                        "Select a vulnerable sample before generating a repair."
                    ),
                    "repaired_code": None,
                }

            repair_result = repair_file(str(source_path), str(repaired_path))
            if not isinstance(repair_result, dict):
                return {
                    "success": False,
                    "message": "The repair prototype returned an unexpected result.",
                    "repaired_code": None,
                }

            if not repair_result.get("success"):
                return {
                    "success": False,
                    "message": repair_result.get(
                        "message", "No supported repair pattern was found."
                    ),
                    "repaired_code": None,
                }

            if not repaired_path.exists():
                return {
                    "success": False,
                    "message": (
                        "The repair prototype reported success but did not "
                        "create an output file."
                    ),
                    "repaired_code": None,
                }

            repaired_code = repaired_path.read_text(encoding="utf-8")
            try:
                ast.parse(repaired_code)
            except SyntaxError as exc:
                return {
                    "success": False,
                    "message": (
                        "The generated candidate has invalid Python syntax: "
                        f"{exc.msg} (line {exc.lineno})."
                    ),
                    "repaired_code": None,
                }

            remaining_findings = analyze_file(str(repaired_path))
            return {
                "success": True,
                "message": "A repair candidate was generated. Review and test it before use.",
                "repaired_code": repaired_code,
                "original_findings_count": len(original_findings),
                "remaining_findings_count": len(remaining_findings),
                "validation_passed": len(remaining_findings) == 0,
                "warning": (
                    "This is a candidate repair, not a security guarantee. "
                    "Review the code and run application tests."
                ),
            }
    except HTTPException:
        raise
    except Exception as exc:
        print(f"SQLGuard-C repair error: {type(exc).__name__}: {exc}")
        raise HTTPException(
            status_code=500,
            detail="Repair failed. Check the backend terminal.",
        ) from exc
