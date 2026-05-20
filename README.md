# IAM Sentinel

IAM Sentinel is a local cybersecurity portfolio project for identity risk and attack path analysis. This first milestone only creates the project foundation: a minimal Flask app, sample IAM data, a loader, simple typed structures, and starter tests.

## Local-only Design

This project is designed to run locally on your machine. It does not integrate with cloud providers, paid APIs, scanners, SIEM tools, or external monitoring systems.

## Windows Setup

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

## Run the App

```powershell
.\.venv\Scripts\python.exe app.py
```

Open:

```text
http://127.0.0.1:5000
```

Health check:

```text
http://127.0.0.1:5000/
```

Dashboard:

```text
http://127.0.0.1:5000/dashboard
```

## Run Analysis

With the Flask app running:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/analysis/run
```

## Run Tests

```powershell
.\.venv\Scripts\python.exe -m pytest
```

## Manual QA Checklist

Use this checklist before demos, screenshots, or portfolio recording.

- Route checks: open `/dashboard`, `/findings`, `/identities`, `/resources`, `/access-paths`, `/access-reviews`, and `/reports`.
- Detail route checks: open one valid finding, identity, and resource detail page from table actions.
- Loading state checks: refresh each workbench page and confirm one visible loading alert appears before data renders.
- Empty state checks: use filters/searches that return no rows and confirm the table shows a readable empty-state row.
- Export checks: use Reports export buttons for JSON and CSV, and confirm `/api/reports/governance-summary?format=csv` downloads CSV text.
- Cross-link navigation checks: use finding identity/resource links, access path identity/resource links, and report/review navigation links.
- Chart rendering checks: confirm dashboard charts and access review analytics charts render without layout overlap.
- Missing-detail-page checks: open `/findings/finding-missing`, `/identities/user-missing`, and `/resources/res-missing`.
- Access review workflow checks: create a review from Access Paths, update reviewer/status/decision/notes from Access Reviews, and verify stale/revoke metrics still render.
- Mobile overflow checks: narrow the browser width and confirm tables scroll horizontally, long IDs wrap safely, and action buttons remain usable.

## Current Scope

This milestone does not include risk detection rules, dashboards, cloud integrations, attack simulation, or monitoring. The goal is a clean base that is easy to extend.
