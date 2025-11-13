

https://github.com/user-attachments/assets/9895414b-8859-4bd1-8356-87f4cac5fdbd

# PySecCheck

PySecCheck is a Python/Tkinter utility for reviewing Microsoft 365 tenant security.  
It pulls data from Microsoft Graph, runs a rule-based assessment, and (optionally) uses an LLM to generate executive and technical reports.

## Features

- Enumerates tenant configuration (org, licenses, roles, Conditional Access, OAuth apps, Intune, Exchange).
- Rule-based scoring for MFA, legacy auth, break-glass accounts, OAuth risk, Intune baselines, etc.
- Separate **organizational** review and **per-user** review paths.
- Local caching of Graph data to avoid hammering the tenant.
- Tkinter UI with:
  - “Run All Checks” organizational report.
  - User review panel.
  - Export to **TXT**, **DOCX**, and **HTML** (with CSS themes).
- Optional AI integration for:
  - Executive JSON summary (score, headline risks, quick wins, roadmap, user table).
  - Technical Markdown remediation report.

## Requirements

- Python 3.11+ (tested with 3.13).
- A Microsoft Entra ID tenant with:
  - Delegated Graph permissions for basic org/user inventory.
  - App-only Graph permissions for audit/sign-in log access (e.g. `AuditLog.Read.All`).
- An app registration + client secret for the app-only flow.
- (Optional) OpenAI-compatible API key for AI reporting.

## Setup

```bash
git clone https://github.com/<your-org>/pyseccheck.git
cd pyseccheck
python -m venv .venv
. .venv/Scripts/activate  # Windows
pip install -r requirements.txt
