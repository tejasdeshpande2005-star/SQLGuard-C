import { useRef, useState } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { python } from "@codemirror/lang-python";
import { EditorView } from "@codemirror/view";
import {
  setUnsafeRangesEffect,
  unsafeHighlightField,
  unsafeHighlightTheme,
} from "./highlightExtension";
import "./App.css";

const vulnerableSample = `def search_user(cursor):
    username = input("Enter username: ")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
`;

const safeSample = `def search_user(cursor, username):
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
`;

const API_BASE = "http://127.0.0.1:8000";

export default function App() {
  const [code, setCode] = useState(vulnerableSample);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [selectedLine, setSelectedLine] = useState(null);
  const [repairResult, setRepairResult] = useState(null);
  const [repairLoading, setRepairLoading] = useState(false);
  const editorViewRef = useRef(null);

  const extensions = [
    python(),
    unsafeHighlightField,
    unsafeHighlightTheme,
    EditorView.lineWrapping,
  ];

  function clearHighlights() {
    const view = editorViewRef.current;
    if (view) {
      view.dispatch({ effects: setUnsafeRangesEffect.of([]) });
    }
  }

  function resetResults() {
    setResult(null);
    setError("");
    setSelectedLine(null);
    setRepairResult(null);
    clearHighlights();
  }

  function applyHighlights(findings) {
    const view = editorViewRef.current;
    if (!view) return;
    const ranges = findings.flatMap((finding) =>
      Array.isArray(finding.highlight_ranges) ? finding.highlight_ranges : []
    );
    view.dispatch({ effects: setUnsafeRangesEffect.of(ranges) });
  }

  async function readApiResponse(response, fallbackMessage) {
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = data.detail;
      const message =
        typeof detail === "string"
          ? detail
          : detail?.message || detail?.error || fallbackMessage;
      throw new Error(message);
    }
    return data;
  }

  async function analyzeCode() {
    setLoading(true);
    setError("");
    setResult(null);
    setRepairResult(null);
    setSelectedLine(null);
    clearHighlights();

    try {
      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      const data = await readApiResponse(response, "Analysis request failed.");
      const findings = data.findings ?? [];
      setResult(data);
      applyHighlights(findings);
    } catch (err) {
      setError(
        err.message === "Failed to fetch"
          ? "Cannot reach the Python backend. Make sure it is running on port 8000."
          : err.message
      );
    } finally {
      setLoading(false);
    }
  }

  async function generateRepair() {
    setRepairLoading(true);
    setError("");
    setRepairResult(null);

    try {
      const response = await fetch(`${API_BASE}/api/repair`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      const data = await readApiResponse(response, "Repair request failed.");
      setRepairResult(data);
    } catch (err) {
      setError(
        err.message === "Failed to fetch"
          ? "Cannot reach the Python backend. Make sure it is running on port 8000."
          : err.message
      );
    } finally {
      setRepairLoading(false);
    }
  }

  function downloadRepairedFile() {
    if (!repairResult?.success || typeof repairResult.repaired_code !== "string") {
      return;
    }
    const blob = new Blob([repairResult.repaired_code], {
      type: "text/x-python;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "repaired_candidate.py";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  async function handleFileUpload(event) {
    const file = event.target.files?.[0];
    if (!file) return;

    if (!file.name.trim().toLowerCase().endsWith(".py")) {
      setError("Please upload a Python (.py) file.");
      event.target.value = "";
      return;
    }
    if (file.size > 100_000) {
      setError("The Python file must be smaller than 100 KB.");
      event.target.value = "";
      return;
    }

    try {
      const contents = await file.text();
      setCode(contents);
      resetResults();
    } catch {
      setError("Could not read the selected file.");
    }
    event.target.value = "";
  }

  function jumpToFinding(finding) {
    const view = editorViewRef.current;
    if (!view) {
      setError("The code editor is not ready yet.");
      return;
    }

    const doc = view.state.doc;
    const lineNumber = Number(finding.line ?? finding.line_number);
    const ranges = Array.isArray(finding.highlight_ranges)
      ? finding.highlight_ranges
      : [];
    const validRange = ranges.find(
      (range) =>
        Number.isInteger(range.start_offset) &&
        Number.isInteger(range.end_offset) &&
        range.start_offset >= 0 &&
        range.end_offset > range.start_offset &&
        range.end_offset <= doc.length
    );

    let start;
    let end;
    if (validRange) {
      start = validRange.start_offset;
      end = validRange.end_offset;
    } else if (
      Number.isInteger(lineNumber) &&
      lineNumber >= 1 &&
      lineNumber <= doc.lines
    ) {
      const line = doc.line(lineNumber);
      start = line.from;
      end = line.to;
    } else {
      setError("This finding does not contain a valid source location.");
      return;
    }

    setSelectedLine(lineNumber);
    setError("");
    view.dispatch({
      selection: { anchor: start, head: end },
      effects: EditorView.scrollIntoView(start, { y: "center" }),
    });
    view.focus();
  }

  const findings = result?.findings ?? [];
  const findingCount = result?.findings_count ?? findings.length;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">S</div>
          <div>
            <strong>SQLGuard-C</strong>
            <small>Security analyzer</small>
          </div>
        </div>
        <p className="nav-heading">WORKSPACE</p>
        <div className="nav-link active">⌕ &nbsp; Code analysis</div>
        <div className="sidebar-footer">
          <span className="status-dot" />
          Local static analysis
        </div>
      </aside>

      <main className="main">
        <header className="header">
          <div>
            <p className="breadcrumb">Workspace / Code analysis</p>
            <h1>SQL Injection Analyzer</h1>
            <p className="subtitle">
              Inspect Python source code for potential SQL injection vulnerabilities.
            </p>
          </div>
          <span className="engine-label">⬡ SQLGuard-C engine</span>
        </header>

        <section className="stats">
          <div className="stat">
            <span>SUBMITTED CHARACTERS</span>
            <strong>{code.length}</strong>
          </div>
          <div className="stat">
            <span>FINDINGS</span>
            <strong>{result ? findingCount : "—"}</strong>
          </div>
          <div className="stat">
            <span>STATUS</span>
            <strong className="status-text">
              {loading || repairLoading
                ? "Running…"
                : repairResult
                  ? "Repair ready"
                  : result
                    ? "Complete"
                    : "Ready"}
            </strong>
          </div>
        </section>

        {error && (
          <div className="error-box" role="alert">
            <strong>Request error</strong>
            <p>{error}</p>
          </div>
        )}

        <section className="workspace">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h2>01 / Source code</h2>
                <p>Paste Python code, type it, or upload a file.</p>
              </div>
              <span className="file-badge">PYTHON</span>
            </div>

            <div className="samples">
              <button
                type="button"
                onClick={() => {
                  setCode(vulnerableSample);
                  resetResults();
                }}
              >
                Vulnerable sample
              </button>
              <button
                type="button"
                onClick={() => {
                  setCode(safeSample);
                  resetResults();
                }}
              >
                Safe sample
              </button>
              <label className="upload-button">
                ↑ Upload .py file
                <input
                  type="file"
                  accept=".py,text/x-python"
                  onChange={handleFileUpload}
                  hidden
                />
              </label>
            </div>

            <div className="code-editor">
              <CodeMirror
                value={code}
                height="390px"
                extensions={extensions}
                onCreateEditor={(view) => {
                  editorViewRef.current = view;
                }}
                onChange={(value) => {
                  setCode(value);
                  resetResults();
                }}
                editable={!loading && !repairLoading}
                basicSetup={{
                  lineNumbers: true,
                  foldGutter: true,
                  highlightActiveLine: true,
                  bracketMatching: true,
                  autocompletion: true,
                }}
                aria-label="Python code to analyze"
              />
            </div>

            {selectedLine && (
              <p className="selected-line">
                Navigated to finding at line {selectedLine}. Unsafe ranges are
                marked in red when available.
              </p>
            )}

            <button
              className="analyze-button"
              onClick={analyzeCode}
              disabled={loading || repairLoading || !code.trim()}
            >
              {loading ? "Analyzing…" : "⌕ Analyze code"}
            </button>
            <button
              className="secondary-button"
              onClick={generateRepair}
              disabled={
                loading ||
                repairLoading ||
                !result ||
                findingCount === 0
              }
            >
              {repairLoading ? "Generating repair…" : "Generate Repair"}
            </button>
            <p className="hint">
              Static analysis only — submitted Python code is not executed.
            </p>
          </div>

          <div className="panel results-panel">
            <div className="panel-header">
              <div>
                <h2>02 / Findings</h2>
                <p>Click a finding to navigate to its source location.</p>
              </div>
            </div>

            {!result && !loading && (
              <div className="empty-state">
                <div className="empty-symbol">⬡</div>
                <h3>Ready to analyze</h3>
                <p>
                  Submit code to view findings and navigate to potentially
                  vulnerable expressions.
                </p>
              </div>
            )}

            {loading && (
              <div className="empty-state">
                <h3>Analyzing source…</h3>
              </div>
            )}

            {result && (
              <div className="results">
                <div className={findingCount ? "verdict danger" : "verdict safe"}>
                  <strong>
                    {findingCount
                      ? `⚠ ${findingCount} potential finding${findingCount === 1 ? "" : "s"} detected`
                      : "✓ No findings reported"}
                  </strong>
                  <p>{result.message}</p>
                </div>

                {findings.length > 0 && (
                  <div className="findings-toolbar">
                    Click any finding to select its corresponding source range.
                  </div>
                )}

                {findings.map((finding, index) => {
                  const line = Number(finding.line ?? finding.line_number);
                  const isSelected = selectedLine === line;
                  return (
                    <article
                      className={`finding finding-clickable ${
                        isSelected ? "finding-selected" : ""
                      }`}
                      key={`${line}-${index}`}
                      role="button"
                      tabIndex={0}
                      aria-label={`Finding ${index + 1}, line ${line}. Click to navigate to source code.`}
                      onClick={() => jumpToFinding(finding)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          jumpToFinding(finding);
                        }
                      }}
                    >
                      <div className="finding-title">
                        <strong>
                          Finding {index + 1}:{" "}
                          {finding.message || "Potential SQL injection"}
                        </strong>
                        <span>{finding.severity || "MEDIUM"}</span>
                      </div>
                      {Number.isInteger(line) && line > 0 && <p>Line: {line}</p>}
                      {finding.expression && (
                        <div className="finding-expression">
                          <strong>Reported expression</strong>
                          <code>{finding.expression}</code>
                        </div>
                      )}
                      {finding.source && <p>Source: {String(finding.source)}</p>}
                      {finding.sink && <p>Sink: {String(finding.sink)}</p>}
                      {finding.path && (
                        <p>
                          <strong>Source-to-sink path:</strong>{" "}
                          {Array.isArray(finding.path)
                            ? finding.path.join(" → ")
                            : String(finding.path)}
                        </p>
                      )}
                      {finding.repair && (
                        <div className="repair">
                          <strong>Suggested remediation</strong>
                          <p>{finding.repair}</p>
                        </div>
                      )}
                      <p className="click-hint">
                        {isSelected
                          ? "Finding selected in editor"
                          : "Click to navigate to source →"}
                      </p>
                    </article>
                  );
                })}

                {findingCount === 0 && (
                  <p className="disclaimer">
                    No findings were reported. This does not prove the code is secure.
                  </p>
                )}
                {result.note && <p className="disclaimer">{result.note}</p>}
              </div>
            )}
          </div>
        </section>

        {repairResult && (
          <section className="panel repair-preview">
            <div className="panel-header">
              <div>
                <h2>03 / Repair Preview</h2>
                <p>Review the generated candidate before using it.</p>
              </div>
              {repairResult.success && (
                <span className="file-badge">PYTHON</span>
              )}
            </div>

            <div className={`verdict ${repairResult.success ? (repairResult.validation_passed ? "safe" : "danger") : "danger"} repair-status`}>
              <strong>
                {!repairResult.success
                  ? "Repair not generated"
                  : repairResult.validation_passed
                    ? "Candidate generated — no findings reported on re-analysis"
                    : "Candidate generated — findings remain"}
              </strong>
              <p>{repairResult.message}</p>
              {repairResult.success && (
                <p>
                  Original findings: {repairResult.original_findings_count} ·
                  Remaining findings: {repairResult.remaining_findings_count}
                </p>
              )}
            </div>

            {repairResult.success && (
              <>
                <pre className="repaired-code">
                  <code>{repairResult.repaired_code}</code>
                </pre>
                <button
                  type="button"
                  className="analyze-button download-button"
                  onClick={downloadRepairedFile}
                >
                  Download repaired_candidate.py
                </button>
                <p className="disclaimer repair-warning">
                  {repairResult.warning}
                </p>
              </>
            )}
          </section>
        )}

        <footer>
          SQLGuard-C · Compiler-based security analysis · Local development
        </footer>
      </main>
    </div>
  );
}
