# SQLGuard-C

**A Compiler-Based Tool to Detect, Explain, Repair and Verify SQL Injection in Python Code**

SQLGuard-C is an academic static-analysis project that uses compiler-design concepts to identify potential SQL injection vulnerabilities in Python programs. It combines AST-based analysis and taint tracking with source-to-sink explanations, remediation guidance, and a web-based dashboard for interactive analysis.

## Features

- **AST-based analysis:** Parses Python source code into an Abstract Syntax Tree.
- **Taint tracking:** Tracks potentially untrusted data as it flows through program variables.
- **SQL injection detection:** Identifies potentially unsafe SQL query construction, including string concatenation, f-strings, and common formatting patterns.
- **Source-to-sink explanation:** Shows how untrusted input may reach SQL execution.
- **Code highlighting:** Highlights reported source ranges in the editor and lets users navigate from findings to code.
- **Remediation guidance:** Recommends parameterized queries to help prevent SQL injection.
- **Repair and verification prototypes:** Includes separate modules for candidate repairs and verification experiments.
- **Interactive dashboard:** Provides a React frontend connected to a Python FastAPI backend.

> SQLGuard-C performs static analysis. It does not execute the submitted Python source code. Its findings are heuristic and should be reviewed; an absence of findings does not guarantee that a program is secure.

## Technology Stack

| Component | Technology |
|---|---|
| Core analyzer | Python, `ast` |
| Backend API | FastAPI, Uvicorn |
| Frontend | React, Vite |
| Code editor | CodeMirror 6 |
| Testing | pytest |
| Evaluation | Labeled benchmark dataset and evaluation scripts |

## Project Structure

```text
SQLGuard-C/
├── backend/
│   └── main.py                 # FastAPI application
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Dashboard and analysis interface
│   │   ├── App.css             # Dashboard styles
│   │   └── highlightExtension.js
│   ├── package.json
│   └── vite.config.js
├── sqlguard/
│   ├── analysis/
│   │   └── taint.py            # Taint analysis and detection
│   ├── explain/                # Source-to-sink explanations
│   ├── frontend/               # Python analysis components
│   ├── repair/                 # Repair prototype
│   ├── verification/           # Verification experiments
│   └── cli.py                  # Command-line interface
├── dataset/                    # Labeled examples
├── examples/                   # Demonstration programs
├── tests/                      # Automated tests
├── docs/                       # Project documentation
├── requirements.txt
├── evaluate_benchmarks.py
└── README.md
```

## Prerequisites

Install the following before running the application:

- Python 3.12
- Node.js and npm
- Git (to clone the repository)

## Setup and Installation

### 1. Clone the repository

```bash
git clone https://github.com/tejasdeshpande2005-star/SQLGuard-C.git
cd SQLGuard-C
```

### 2. Set up the Python backend

On Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
py -3.12 -m pip install -r requirements.txt
```

If PowerShell prevents activation, you can use the Python executable in the virtual environment directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 3. Set up the frontend

Open a terminal at the project root and run:

```powershell
cd frontend
npm install
```

Return to the root directory when needed:

```powershell
cd ..
```

## Running the Full Application

The frontend and backend run as two separate development processes. **Keep both terminals running while using the dashboard.**

### Terminal 1 — Start the FastAPI backend

From the project root, `SQLGuard-C/`:

```powershell
py -3.12 -m uvicorn backend.main:app --reload
```

The backend should be available at:

- API base URL: `http://127.0.0.1:8000`
- Interactive API documentation: `http://127.0.0.1:8000/docs`
- Health endpoint: `http://127.0.0.1:8000/api/health`

### Terminal 2 — Start the React frontend

Open a second terminal:

```powershell
cd D:\compiler\SQLGuard-C\frontend
npm run dev
```

Vite will display the local development URL, typically:

```text
http://localhost:5173
```

Open the URL displayed in your terminal in a browser.

### How the application works

1. The user enters Python code, selects a sample, or uploads a `.py` file.
2. The React frontend sends the code to the FastAPI analysis endpoint.
3. The backend validates the Python syntax and invokes the SQLGuard-C analyzer.
4. The analyzer examines the code for potential tainted data flows into SQL execution.
5. The backend returns findings, source locations, explanation paths, and remediation guidance.
6. The frontend displays the findings and highlights the reported source ranges.

```text
Python source code
        |
        v
React + CodeMirror frontend
        |
        | POST /api/analyze
        v
FastAPI backend
        |
        v
Python AST analysis
        |
        v
Taint tracking and SQL sink detection
        |
        v
Findings + source locations + explanations
        |
        v
Dashboard results and red code highlighting
```

## Demonstration Guide

Use this workflow to demonstrate the application during a faculty review.

### Demonstration 1 — Detect a vulnerable query

Paste the following code into the dashboard:

```python
def search_user(cursor):
    username = input("Enter username: ")

    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "'"
    )
    cursor.execute(query)
```

Click **Analyze code**.

Expected behavior:

- A potential SQL injection finding is reported.
- The finding identifies the untrusted input source and SQL execution sink.
- The source-to-sink path explains the detected flow.
- The editor highlights the reported unsafe expression in red.
- The findings panel provides remediation guidance.

### Demonstration 2 — Test an f-string query

```python
def get_user(cursor):
    user_id = input("Enter user ID: ")

    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
```

This tests whether the analyzer detects user-controlled data embedded directly in SQL through an f-string.

### Demonstration 3 — Compare with a parameterized query

```python
def search_user(cursor, username):
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
```

A parameterized query keeps the SQL template separate from the supplied value. For the tested example, SQLGuard-C is expected to report no SQL injection finding.

### Demonstration 4 — Test multiple findings

```python
def user_operations(cursor):
    username = input("Username: ")
    email = input("Email: ")

    query1 = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "'"
    )
    cursor.execute(query1)

    query2 = f"SELECT * FROM users WHERE email = '{email}'"
    cursor.execute(query2)
```

Analyze the code and inspect whether both unsafe query constructions are reported separately. Click each finding to navigate to its source range.

### Demonstration 5 — Upload a Python file

1. Save a Python example as `vulnerable_example.py`.
2. Click **Upload .py file** in the dashboard.
3. Select the saved file.
4. Click **Analyze code**.
5. Inspect the findings and highlighted source locations.

The dashboard accepts Python files and applies file-size validation.

## API Usage

The frontend communicates with the backend over HTTP.

### Health check

```http
GET /api/health
```

Use this endpoint to check whether the backend is reachable.

### Analyze Python source

```http
POST /api/analyze
Content-Type: application/json
```

Example request:

```json
{
  "code": "def search(cursor):\n    username = input('Username: ')\n    query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n    cursor.execute(query)\n"
}
```

Example using PowerShell:

```powershell
$body = @{
    code = @'
def search(cursor):
    username = input("Username: ")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
'@
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "http://127.0.0.1:8000/api/analyze" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
```

The response contains the analysis status, finding count, findings, and explanatory information. Individual findings can include severity, source, sink, source-to-sink path, remediation advice, and source-range metadata used by the editor.

For the exact response schema, start the backend and visit `http://127.0.0.1:8000/docs`.

## Running Tests

From the project root:

```powershell
py -3.12 -m pytest -q
```

To run the benchmark evaluation:

```powershell
py -3.12 evaluate_benchmarks.py
```

Review the evaluation scripts and generated files in `results/` for the benchmark configuration and reported metrics.

Benchmark results should be interpreted in the context of the dataset size, labeling process, and evaluation methodology. Results on a small or hand-labeled dataset do not establish general real-world detection accuracy.

## Troubleshooting

### Frontend cannot connect to the backend

- Confirm that the backend is running on port `8000`.
- Visit `http://127.0.0.1:8000/api/health`.
- Check the browser console and backend terminal for errors.
- Verify that the frontend's API URL matches the running backend.

### Python module or import errors

Run backend commands from the project root so that the `backend` and `sqlguard` packages are importable. Confirm that dependencies were installed into the Python environment you are using.

### Frontend dependency errors

From the frontend directory, run:

```powershell
npm install
npm run dev
```

Do not commit `node_modules/`; it is generated locally from the package manifest and lockfile.

### Python syntax errors in submitted code

Check the submitted code for valid Python syntax. The backend should report invalid source rather than analyze it as if it were valid.

## Limitations

- Static analysis may produce false positives or false negatives.
- Taint tracking and interprocedural analysis have implementation-specific limitations.
- Highlighting depends on the source ranges returned by the analyzer.
- Parameterized-query recognition depends on the supported query patterns.
- The repair and verification components are prototypes and should not be interpreted as proof that a repaired application is secure.
- SQLGuard-C is an academic project, not a replacement for security review, testing, or established security tools.

## Academic Purpose

SQLGuard-C demonstrates how compiler concepts—AST construction and traversal, data-flow tracking, source-to-sink analysis, and source-location mapping—can be applied to a practical software-security problem.

The project is intended for educational use and further experimentation.

## Repository

GitHub: https://github.com/tejasdeshpande2005-star/SQLGuard-C
