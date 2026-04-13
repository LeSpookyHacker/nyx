# Compliance Mapping

Nyx maps every finding to one or more control frameworks so auditors (and your CISO) can see coverage at a glance.

---

## Supported frameworks

Out of the box:

- **PCI DSS** 4.0
- **SOC 2** Trust Services Criteria (Common Criteria, Confidentiality, Availability)
- **NIST 800-53** Rev 5
- **CIS Controls** v8
- **OWASP Top 10** 2021

Plus any **custom framework** you define in the DB (`ENABLE_CUSTOM_COMPLIANCE=true`).

---

## How mapping works

Each finding carries:

- A **CWE** (Common Weakness Enumeration) ID, extracted from the scanner
- An **OWASP category** when the scanner provides one
- A **rule ID** and scanner name

Nyx maintains a mapping table between CWE / OWASP → control IDs. On ingest, every finding gets a `control_mappings` array. You can query findings by control, view coverage per framework, and track trend over time.

---

## Compliance page (`/compliance`)

Pick a framework from the selector and see:

| Element | What it shows |
|---|---|
| **Coverage percentage** | Controls with **no open findings mapped** ÷ total controls |
| **Controls grid** | Each control colored by state (green = clean, yellow = partial, red = at-risk) |
| **Drill-down** | Click a control to see all open findings mapped to it |
| **Trend** | 30 / 60 / 90 day coverage line |

<!-- IMAGE: Compliance page with PCI DSS selected, grid colored by state.
     File: wiki/images/compliance-grid.png -->
![Compliance page with PCI DSS](images/compliance-grid.png)
<!-- /IMAGE -->

---

## Custom frameworks

Define your own via the API:

```bash
curl -X POST "$NYX_URL/api/v1/compliance/frameworks" \
  -H "X-API-Key: $NYX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Internal Baseline",
    "version": "1.0",
    "controls": [
      {
        "id": "AIB-001",
        "title": "No hardcoded secrets",
        "cwe_mappings": [798, 259],
        "owasp_mappings": ["A07:2021"]
      },
      {
        "id": "AIB-002",
        "title": "All input validated",
        "cwe_mappings": [20, 78, 79, 89]
      }
    ]
  }'
```

Your custom framework now appears in the selector alongside built-ins and the executive report.

> Custom framework CRUD is also available from the UI under Settings → Custom Compliance.

---

## Executive report

The executive PDF includes a compliance summary: coverage per framework, top at-risk controls, and the 30-day trend. See [Reports & Analytics](Reports.md) for the full contents.

---

## Audit use case

During a PCI DSS audit, an auditor asks "show me evidence of coverage for requirement 6.2.4." Nyx answers in one click: filter by that control, show open and historical findings, show the audit trail of who fixed what and when. No spreadsheet archaeology.

---

## What next

- **Custom framework API →** [API Reference → compliance router](API-Reference.md#routers)
- **Generate a report for audit season →** [Reports & Analytics](Reports.md)
