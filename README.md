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
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

The app returns:

```text
IAM Sentinel is running
```

## Run Tests

```powershell
pytest
```

## Current Scope

This milestone does not include risk detection rules, dashboards, cloud integrations, attack simulation, or monitoring. The goal is a clean base that is easy to extend.
