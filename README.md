# IAM Sentinel - IAM Governance & Access Risk Analysis Platform

IAM Sentinel is a local Flask and SQLite platform for analyzing IAM risk, access paths, governance reviews, remediation impact, audit evidence, and reporting using a coherent sample IAM dataset.

The project models identities, groups, roles, permissions, resources, findings, access reviews, remediation actions, and governance evidence in a repeatable local environment.

## Core Capabilities

- IAM graph modeling across identities, groups, roles, permissions, and resources
- Risk findings engine with severity, score, evidence, recommendations, and lifecycle status
- Identity and resource investigation pages with related findings and access context
- Access-path analysis for identity-to-resource reachability
- Attack graph exploration for visual access-path reasoning
- Access review workflow with reviewer, decision, notes, history, and remediation status
- Remediation impact preview before applying simulated changes
- Verified impact summary after remediation
- Remediation audit trail with before and after evidence
- Governance reports and exports in JSON, PDF, and evidence CSV formats

## Architecture

- `app.py` - Flask routes, API endpoints, remediation actions, and report generation
- `core/` - IAM loading, graph building, risk analysis, persistence helpers, and data models
- `data/` - sample IAM data and local SQLite state
- `templates/` - Jinja templates for the web interface
- `static/assets/js/` - page-specific JavaScript workbenches
- `tests/` - pytest regression tests for API behavior, graph logic, persistence, reports, and UI contracts
- `scripts/` - local reset and utility scripts

## Local Scope and Boundaries

IAM Sentinel is designed for local IAM governance analysis using sample data.

It does not include:

- Live IAM provider connections
- Cloud integration
- Authentication or RBAC
- Ticketing or email integration
- SIEM or log ingestion
- Real production IAM data
- Production authorization server behavior

The platform is not a replacement for a production IAM connector, SIEM, authorization server, or enterprise access governance product.

## Windows Setup

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Reset the sample state:

```powershell
.\scripts\reset_demo_state.ps1
```

Run the Flask app:

```powershell
.\.venv\Scripts\python.exe app.py
```

Open the dashboard:

```text
http://127.0.0.1:5000/dashboard
```

Health check:

```text
http://127.0.0.1:5000/
```

## Reset Sample State

The application uses `data/sample_iam.json` and local SQLite state in `data/findings.db`.

To reset the sample analysis state:

```powershell
.\scripts\reset_demo_state.ps1
```

The reset script removes only local SQLite state, including `data/findings.db` and SQLite sidecar files such as `findings.db-wal` and `findings.db-shm`. It then reseeds findings and access-review sample state from the sample IAM dataset. It does not delete source files or change `data/sample_iam.json`.

## Tests

Run the full test suite:

```powershell
.\.venv\Scripts\python.exe -m pytest
```

The suite covers API behavior, graph building, risk analysis, findings persistence, access reviews, remediation simulation, report exports, and UI contract checks.

## Application Map

- `/dashboard` - governance and risk summary dashboard
- `/findings` - findings workbench and quick investigation modal
- `/findings/<finding_id>` - full finding investigation workspace
- `/identities` - identity inventory
- `/identities/<identity_id>` - identity investigation and remediation workspace
- `/resources` - resource inventory
- `/resources/<resource_id>` - resource exposure investigation workspace
- `/access-paths` - identity-to-resource access path analysis
- `/attack-graph` - visual graph exploration of access relationships
- `/access-reviews` - access review workflow and review history
- `/remediation-audit` - remediation audit trail
- `/reports` - governance summary and evidence exports

## Suggested Walkthrough

1. Start at `/dashboard` to review the current IAM risk posture.
2. Open `/findings` and investigate a critical finding.
3. Follow the identity and resource context from the finding.
4. Review related access paths and the attack graph.
5. Create or update an access review for a risky identity/resource relationship.
6. Preview remediation impact from an identity detail page.
7. Apply the simulated remediation and review verified impact.
8. Open `/remediation-audit` to inspect the remediation evidence trail.
9. Export the governance summary or evidence file from `/reports`.

## Validation

Before sharing or recording the project, run:

```powershell
.\scripts\reset_demo_state.ps1
.\.venv\Scripts\python.exe -m pytest
```

Recommended smoke checks:

- Confirm `/dashboard`, `/findings`, `/identities`, `/resources`, `/access-paths`, `/attack-graph`, `/access-reviews`, `/remediation-audit`, and `/reports` return HTTP 200.
- Confirm report exports generate JSON, PDF, and evidence CSV files.
- Confirm the remediation preview and audit trail work from an identity detail page.

## Current Status

IAM Sentinel currently focuses on local IAM governance analysis, access-risk investigation, review workflow evidence, remediation simulation, and reporting. Future extensions could add production IAM connectors, authentication, approval routing, or external system integrations, but those are intentionally outside the current local scope.
