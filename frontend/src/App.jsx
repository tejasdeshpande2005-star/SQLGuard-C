
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

export default function App() {
  const [code, setCode] = useState(vulnerableSample);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [selectedLine, setSelectedLine] = useState(null);

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
      view.dispatch({
        effects: setUnsafeRangesEffect.of([]),
      });
    }
  }

  function resetResults() {
    setResult(null);
    setError("");
    setSelectedLine(null);
    clearHighlights();
  }

  function applyHighlights(findings) {
    const view = editorViewRef.current;
    if (!view) return;

    const ranges = findings.flatMap((finding) =>
      Array.isArray(finding.highlight_ranges)
        ? finding.highlight_ranges
        : []
    );

    view.dispatch({
      effects: setUnsafeRangesEffect.of(ranges),
    });
  }

  async function analyzeCode() {
    setLoading(true);
    setError("");
    setResult(null);
    setSelectedLine(null);
    clearHighlights();

    try {
      const response = await fetch("http://127.0.0.1:8000/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });

      const data = await response.json();

      if (!response.ok) {
        const detail = data.detail;
        const message =
          typeof detail === "string"
            ? detail
            : detail?.message ||
              detail?.error ||
              "Analysis request failed.";

        throw new Error(message);
      }

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

    let start;
    let end;

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
              Inspect Python source code for potential SQL injection
              vulnerabilities.
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
              {loading ? "Running…" : result ? "Complete" : "Ready"}
            </strong>
          </div>
        </section>

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
                editable={!loading}
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
                Navigated to finding at line {selectedLine}.
                Unsafe source ranges are marked in red when available.
              </p>
            )}

            <button
              className="analyze-button"
              onClick={analyzeCode}
              disabled={loading || !code.trim()}
            >
              {loading ? "Analyzing…" : "⌕ Analyze code"}
            </button>

            <p className="hint">
              Static analysis only — submitted code is not executed.
            </p>
          </div>

          <div className="panel results-panel">
            <div className="panel-header">
              <div>
                <h2>02 / Findings</h2>
                <p>Click a finding to navigate to its source location.</p>
              </div>
            </div>

            {!result && !loading && !error && (
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

            {error && (
              <div className="error-box" role="alert">
                <strong>Analysis or navigation error</strong>
                <p>{error}</p>
              </div>
            )}

            {result && (
              <div className="results">
                <div
                  className={
                    findingCount ? "verdict danger" : "verdict safe"
                  }
                >
                  <strong>
                    {findingCount
                      ? `⚠ ${findingCount} potential finding${
                          findingCount === 1 ? "" : "s"
                        } detected`
                      : "✓ No findings reported"}
                  </strong>
                  <p>{result.message}</p>
                </div>

                {findings.length > 0 && (
                  <div className="findings-toolbar">
                    Click a finding to navigate to its reported source range.
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

                      {Number.isInteger(line) && line > 0 && (
                        <p>Line: {line}</p>
                      )}

                      {finding.expression && (
                        <div className="finding-expression">
                          <strong>Reported expression</strong>
                          <code>{finding.expression}</code>
                        </div>
                      )}

                      {finding.source && (
                        <p>Source: {String(finding.source)}</p>
                      )}

                      {finding.sink && (
                        <p>Sink: {String(finding.sink)}</p>
                      )}

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

                {findingCount > findings.length && (
                  <p className="disclaimer">
                    The API reported {findingCount} findings but returned only{" "}
                    {findings.length} finding details.
                  </p>
                )}

                {findingCount === 0 && (
                  <p className="disclaimer">
                    No findings were reported by the analyzer. This does not
                    prove the code is secure.
                  </p>
                )}

                {result.note && (
                  <p className="disclaimer">{result.note}</p>
                )}
              </div>
            )}
          </div>
        </section>

        <footer>
          SQLGuard-C · Compiler-based security analysis · Local development
        </footer>
      </main>
    </div>
  );
}
