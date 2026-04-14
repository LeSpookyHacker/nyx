#!/usr/bin/env python3
"""
Seed Nyx with rich demo data for three repositories.

Creates:
  - 3 repos under acme-corp (payments-api, web-frontend, infra-terraform)
  - 12 weeks of scan history per repo (multiple scanners, realistic cadence)
  - ~30 findings per repo (varied severities, statuses, first_seen spread over 90 days)
  - JIRA links on ~40% of CRITICAL/HIGH findings
  - Proper repo stat counts so dashboards render immediately

Run inside the backend container:
    docker compose cp scripts/seed_demo_data.py backend:/tmp/seed_demo_data.py
    docker compose exec -e PYTHONPATH=/app backend python3 /tmp/seed_demo_data.py
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from sqlalchemy import delete, select

from app.core.constants import FindingStatus, ScanStatus, ScanTrigger, Severity
from app.database import AsyncSessionLocal, init_db
from app.models.finding import Finding
from app.models.jira_link import JiraLink
from app.models.repository import Repository
from app.models.scan import Scan

random.seed(42)
NOW = datetime.now(timezone.utc)


# ─── Repositories ──────────────────────────────────────────────────────────────

REPOS = [
    {
        "github_full_name": "acme-corp/payments-api",
        "language": "Python",
        "description": "PCI-DSS compliant payment processing backend — handles card transactions, fraud detection, and settlement",
        "is_private": True,
        "scanners": "SEMGREP,BANDIT,TRIVY,GRYPE,SNYK",
    },
    {
        "github_full_name": "acme-corp/web-frontend",
        "language": "TypeScript",
        "description": "Customer-facing React SPA — checkout flow, account management, and order tracking",
        "is_private": False,
        "scanners": "SEMGREP,TRIVY,GRYPE,ZAP",
    },
    {
        "github_full_name": "acme-corp/infra-terraform",
        "language": "HCL",
        "description": "Terraform definitions for AWS infrastructure — VPCs, EKS clusters, RDS, S3, and IAM",
        "is_private": True,
        "scanners": "CHECKOV,TRIVY,SEMGREP",
    },
]


# ─── Finding templates per repo ────────────────────────────────────────────────
# Each entry: (title, description, rule_id, scanner, severity, category, extras)
# extras: file_path, line_start, code_snippet, cwe_ids, cve_id, cvss_score, url,
#         remediation_guidance, is_exploitable, owasp_category

FINDINGS_PAYMENTS_API = [
    # CRITICAL
    {
        "title": "Hardcoded Stripe Secret Key",
        "description": "A Stripe live secret key is hardcoded in the configuration module. Anyone with repository access can use this key to process or refund payments.",
        "rule_id": "semgrep.python.stripe-secret-key",
        "scanner": "SEMGREP",
        "severity": "CRITICAL",
        "category": "SECRETS",
        "file_path": "payments/config.py",
        "line_start": 14,
        "code_snippet": 'STRIPE_SECRET_KEY = "sk_test_DEMO_PLACEHOLDER_NOT_REAL_4eC39H"',
        "cwe_ids": '["CWE-798"]',
        "remediation_guidance": "Move to environment variable or AWS Secrets Manager. Rotate the exposed key immediately.",
        "owasp_category": "A02:2021",
    },
    {
        "title": "CVE-2024-1135 — Gunicorn HTTP Request Smuggling",
        "description": "Gunicorn versions prior to 22.0.0 are vulnerable to HTTP request smuggling. An attacker can bypass security controls or poison caches.",
        "rule_id": "grype.CVE-2024-1135",
        "scanner": "GRYPE",
        "severity": "CRITICAL",
        "category": "SCA",
        "cve_id": "CVE-2024-1135",
        "cvss_score": 9.1,
        "cwe_ids": '["CWE-444"]',
        "is_exploitable": True,
        "remediation_guidance": "Upgrade gunicorn to >= 22.0.0.",
    },
    {
        "title": "SQL Injection in payment search endpoint",
        "description": "User-supplied order_id is concatenated directly into a raw SQL query, enabling full database read/write by an authenticated user.",
        "rule_id": "bandit.B608",
        "scanner": "BANDIT",
        "severity": "CRITICAL",
        "category": "SAST",
        "file_path": "payments/api/orders.py",
        "line_start": 83,
        "code_snippet": '    query = f"SELECT * FROM orders WHERE id = \'{order_id}\'"',
        "cwe_ids": '["CWE-89"]',
        "remediation_guidance": "Use SQLAlchemy parameterized queries: db.execute(text('SELECT * FROM orders WHERE id = :id'), {'id': order_id})",
        "owasp_category": "A03:2021",
    },
    # HIGH
    {
        "title": "Insecure deserialization — pickle used on user data",
        "description": "Pickle is used to deserialize data that originates from an HTTP request body. Pickle deserialization of untrusted data can lead to arbitrary code execution.",
        "rule_id": "bandit.B301",
        "scanner": "BANDIT",
        "severity": "HIGH",
        "category": "SAST",
        "file_path": "payments/cache/session.py",
        "line_start": 41,
        "code_snippet": "    session_data = pickle.loads(request.body)",
        "cwe_ids": '["CWE-502"]',
        "remediation_guidance": "Replace pickle with JSON. For complex objects use marshmallow or pydantic.",
        "owasp_category": "A08:2021",
    },
    {
        "title": "JWT secret is a weak static string",
        "description": "The JWT signing secret is a short, guessable string defined inline. Tokens can be forged by brute-forcing the secret.",
        "rule_id": "semgrep.python.jwt-hardcoded-secret",
        "scanner": "SEMGREP",
        "severity": "HIGH",
        "category": "SAST",
        "file_path": "payments/auth/tokens.py",
        "line_start": 7,
        "code_snippet": 'JWT_SECRET = "secret123"',
        "cwe_ids": '["CWE-321", "CWE-798"]',
        "remediation_guidance": "Generate a cryptographically random secret of at least 256 bits. Load from environment variable.",
        "owasp_category": "A02:2021",
    },
    {
        "title": "Server-Side Request Forgery in webhook handler",
        "description": "The webhook callback URL is fetched without allowlisting, allowing requests to internal metadata endpoints (e.g. 169.254.169.254).",
        "rule_id": "semgrep.python.ssrf-requests",
        "scanner": "SEMGREP",
        "severity": "HIGH",
        "category": "SAST",
        "file_path": "payments/webhooks/handler.py",
        "line_start": 58,
        "code_snippet": "    resp = requests.post(event.callback_url, json=payload)",
        "cwe_ids": '["CWE-918"]',
        "remediation_guidance": "Validate callback URLs against an allowlist. Block private IP ranges before making the request.",
        "owasp_category": "A10:2021",
    },
    {
        "title": "CVE-2023-44487 — HTTP/2 Rapid Reset (h2)",
        "description": "The h2 library version in use is vulnerable to the HTTP/2 Rapid Reset attack which can exhaust server resources.",
        "rule_id": "trivy.CVE-2023-44487",
        "scanner": "TRIVY",
        "severity": "HIGH",
        "category": "SCA",
        "cve_id": "CVE-2023-44487",
        "cvss_score": 7.5,
        "cwe_ids": '["CWE-400"]',
        "is_exploitable": True,
        "remediation_guidance": "Upgrade h2 to >= 4.1.0.",
    },
    {
        "title": "Password hashed with MD5",
        "description": "MD5 is used to hash passwords in the legacy admin portal. MD5 is trivially reversed using rainbow tables.",
        "rule_id": "bandit.B324",
        "scanner": "BANDIT",
        "severity": "HIGH",
        "category": "SAST",
        "file_path": "payments/auth/legacy_admin.py",
        "line_start": 29,
        "code_snippet": "    pw_hash = hashlib.md5(password.encode()).hexdigest()",
        "cwe_ids": '["CWE-327", "CWE-916"]',
        "remediation_guidance": "Use bcrypt, argon2-cffi, or scrypt for password hashing.",
        "owasp_category": "A02:2021",
    },
    # MEDIUM
    {
        "title": "Sensitive PII logged at INFO level",
        "description": "The payment processing function logs the full card object including masked PAN and cardholder name. Log aggregation systems may store this data insecurely.",
        "rule_id": "semgrep.python.logging-sensitive-data",
        "scanner": "SEMGREP",
        "severity": "MEDIUM",
        "category": "SAST",
        "file_path": "payments/processing/charge.py",
        "line_start": 112,
        "code_snippet": '    logger.info(f"Processing charge for {card}")',
        "cwe_ids": '["CWE-532"]',
        "remediation_guidance": "Log only non-sensitive identifiers (e.g. last 4 digits, charge ID). Never log full card data.",
    },
    {
        "title": "Missing CSRF protection on payment form",
        "description": "The payment initiation endpoint does not validate CSRF tokens, allowing cross-site request forgery attacks from malicious pages.",
        "rule_id": "semgrep.python.django-no-csrf",
        "scanner": "SEMGREP",
        "severity": "MEDIUM",
        "category": "SAST",
        "file_path": "payments/views/checkout.py",
        "line_start": 67,
        "cwe_ids": '["CWE-352"]',
        "remediation_guidance": "Use Django's @csrf_protect decorator or DRF's SessionAuthentication which enforces CSRF automatically.",
        "owasp_category": "A01:2021",
    },
    {
        "title": "Cryptographically weak token generation",
        "description": "random.choices() is used to generate API tokens. The standard library random module is not cryptographically secure.",
        "rule_id": "bandit.B311",
        "scanner": "BANDIT",
        "severity": "MEDIUM",
        "category": "SAST",
        "file_path": "payments/auth/api_keys.py",
        "line_start": 18,
        "code_snippet": "    token = ''.join(random.choices(string.ascii_letters + string.digits, k=48))",
        "cwe_ids": '["CWE-330"]',
        "remediation_guidance": "Replace with secrets.token_urlsafe(32).",
    },
    {
        "title": "subprocess call with shell=True",
        "description": "Shell injection risk — a subprocess call passes user-controlled input with shell=True, allowing command injection.",
        "rule_id": "bandit.B602",
        "scanner": "BANDIT",
        "severity": "MEDIUM",
        "category": "SAST",
        "file_path": "payments/reporting/exporter.py",
        "line_start": 44,
        "code_snippet": '    subprocess.call(f"convert {filename} output.pdf", shell=True)',
        "cwe_ids": '["CWE-78"]',
        "remediation_guidance": "Pass arguments as a list and set shell=False: subprocess.call(['convert', filename, 'output.pdf'])",
    },
    {
        "title": "CVE-2024-22195 — Jinja2 XSS in HTML attribute injection",
        "description": "Jinja2 < 3.1.3 is vulnerable to XSS when rendering user input inside HTML attributes without explicit escaping.",
        "rule_id": "snyk.SNYK-PYTHON-JINJA2-6228509",
        "scanner": "SNYK",
        "severity": "MEDIUM",
        "category": "SCA",
        "cve_id": "CVE-2024-22195",
        "cvss_score": 5.4,
        "cwe_ids": '["CWE-79"]',
        "remediation_guidance": "Upgrade Jinja2 to >= 3.1.3.",
    },
    {
        "title": "Refund amount not validated server-side",
        "description": "The refund amount is taken from client request without server-side validation against the original charge, allowing arbitrary refund amounts.",
        "rule_id": "semgrep.python.business-logic-refund",
        "scanner": "SEMGREP",
        "severity": "MEDIUM",
        "category": "SAST",
        "file_path": "payments/api/refunds.py",
        "line_start": 35,
        "cwe_ids": '["CWE-20"]',
        "remediation_guidance": "Look up the original charge amount from the database and cap refunds at that value.",
    },
    # LOW
    {
        "title": "HTTP timeout not set on external API calls",
        "description": "Requests to the fraud detection API do not specify a timeout, which can cause thread exhaustion under slow or unresponsive upstream services.",
        "rule_id": "bandit.B113",
        "scanner": "BANDIT",
        "severity": "LOW",
        "category": "SAST",
        "file_path": "payments/fraud/detector.py",
        "line_start": 77,
        "code_snippet": "    resp = requests.post(FRAUD_API_URL, json=payload)",
        "cwe_ids": '["CWE-400"]',
        "remediation_guidance": "Add timeout parameter: requests.post(..., timeout=(3.05, 10))",
    },
    {
        "title": "Debug mode enabled in production config",
        "description": "DEBUG=True is set in the production settings file, which exposes stack traces and internal configuration to users on errors.",
        "rule_id": "semgrep.python.django-debug-enabled",
        "scanner": "SEMGREP",
        "severity": "LOW",
        "category": "SAST",
        "file_path": "payments/settings/production.py",
        "line_start": 5,
        "code_snippet": "DEBUG = True  # TODO: remove before deploy",
        "cwe_ids": '["CWE-489"]',
        "remediation_guidance": "Set DEBUG = False in production. Use environment variable: DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'",
    },
    {
        "title": "Missing security response headers",
        "description": "The API does not set Strict-Transport-Security, X-Content-Type-Options, or X-Frame-Options headers.",
        "rule_id": "zap.10035",
        "scanner": "ZAP",
        "severity": "LOW",
        "category": "DAST",
        "url": "https://payments.acme-corp.example.com/api/v1/",
        "cwe_ids": '["CWE-693"]',
        "remediation_guidance": "Add security headers middleware. In Django: use django-csp and SecurityMiddleware.",
    },
    {
        "title": "Overly verbose error messages in API responses",
        "description": "Internal Python exceptions and stack traces are returned in API error responses, leaking implementation details.",
        "rule_id": "semgrep.python.verbose-error-response",
        "scanner": "SEMGREP",
        "severity": "LOW",
        "category": "SAST",
        "file_path": "payments/middleware/error_handler.py",
        "line_start": 23,
        "cwe_ids": '["CWE-209"]',
        "remediation_guidance": "Return generic error messages to clients. Log full exceptions server-side only.",
    },
]

FINDINGS_WEB_FRONTEND = [
    # CRITICAL
    {
        "title": "CVE-2024-45590 — body-parser ReDoS",
        "description": "body-parser < 1.20.3 is vulnerable to a regular expression denial of service when parsing deeply nested JSON.",
        "rule_id": "grype.CVE-2024-45590",
        "scanner": "GRYPE",
        "severity": "CRITICAL",
        "category": "SCA",
        "cve_id": "CVE-2024-45590",
        "cvss_score": 9.8,
        "cwe_ids": '["CWE-1333"]',
        "is_exploitable": True,
        "remediation_guidance": "Upgrade body-parser to >= 1.20.3.",
    },
    {
        "title": "Hardcoded Stripe publishable key committed with secret key",
        "description": "Both Stripe publishable and secret keys are committed together. The secret key in this bundle enables server-side payment operations.",
        "rule_id": "semgrep.js.stripe-secret-committed",
        "scanner": "SEMGREP",
        "severity": "CRITICAL",
        "category": "SECRETS",
        "file_path": "src/lib/stripe.ts",
        "line_start": 3,
        "code_snippet": 'export const STRIPE_SECRET = "sk_test_DEMO_PLACEHOLDER_NOT_REAL_abc123"',
        "cwe_ids": '["CWE-798"]',
        "remediation_guidance": "Remove from source code immediately and rotate the key. Use VITE_STRIPE_PUBLISHABLE_KEY for the publishable key only.",
    },
    # HIGH
    {
        "title": "Reflected XSS via URL search parameter",
        "description": "The ?q= query parameter is rendered into the page DOM without sanitization, enabling reflected XSS attacks via crafted links.",
        "rule_id": "zap.40012",
        "scanner": "ZAP",
        "severity": "HIGH",
        "category": "DAST",
        "url": "https://shop.acme-corp.example.com/search?q=<script>alert(1)</script>",
        "cwe_ids": '["CWE-79"]',
        "remediation_guidance": "Use DOMPurify or React's built-in escaping. Never use dangerouslySetInnerHTML with user data.",
        "owasp_category": "A03:2021",
    },
    {
        "title": "Missing Content-Security-Policy header",
        "description": "No CSP header is returned by the application. Without CSP, the browser cannot restrict sources for scripts, styles, and other resources.",
        "rule_id": "zap.10038",
        "scanner": "ZAP",
        "severity": "HIGH",
        "category": "DAST",
        "url": "https://shop.acme-corp.example.com/",
        "cwe_ids": '["CWE-693"]',
        "remediation_guidance": "Add a CSP header via Nginx or Cloudflare. Start with: Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...'",
        "owasp_category": "A05:2021",
    },
    {
        "title": "CVE-2024-4068 — braces prototype pollution",
        "description": "The braces npm package < 3.0.3 is vulnerable to prototype pollution and can cause uncontrolled resource consumption.",
        "rule_id": "trivy.CVE-2024-4068",
        "scanner": "TRIVY",
        "severity": "HIGH",
        "category": "SCA",
        "cve_id": "CVE-2024-4068",
        "cvss_score": 7.5,
        "cwe_ids": '["CWE-400"]',
        "remediation_guidance": "Run: npm update braces",
    },
    {
        "title": "Access token stored in localStorage",
        "description": "The OAuth access token is persisted in localStorage, making it accessible to any JavaScript on the page including third-party scripts.",
        "rule_id": "semgrep.js.localstorage-token",
        "scanner": "SEMGREP",
        "severity": "HIGH",
        "category": "SAST",
        "file_path": "src/auth/session.ts",
        "line_start": 22,
        "code_snippet": "localStorage.setItem('access_token', token)",
        "cwe_ids": '["CWE-312", "CWE-922"]',
        "remediation_guidance": "Use httpOnly cookies for token storage. If localStorage is required, evaluate the XSS risk surface.",
        "owasp_category": "A02:2021",
    },
    {
        "title": "Insecure cross-origin postMessage listener",
        "description": "A window.addEventListener('message') handler accepts messages from any origin ('*'), allowing malicious pages to inject data.",
        "rule_id": "semgrep.js.postmessage-no-origin-check",
        "scanner": "SEMGREP",
        "severity": "HIGH",
        "category": "SAST",
        "file_path": "src/components/PaymentIframe.tsx",
        "line_start": 45,
        "code_snippet": "window.addEventListener('message', (event) => {\n  processPayment(event.data)\n})",
        "cwe_ids": '["CWE-346"]',
        "remediation_guidance": "Always validate event.origin against your expected domain before processing message data.",
        "owasp_category": "A01:2021",
    },
    # MEDIUM
    {
        "title": "React dangerouslySetInnerHTML without sanitization",
        "description": "HTML is rendered using dangerouslySetInnerHTML with user-supplied content from the product description API, enabling stored XSS.",
        "rule_id": "semgrep.js.react-dangerously-set-inner-html",
        "scanner": "SEMGREP",
        "severity": "MEDIUM",
        "category": "SAST",
        "file_path": "src/components/ProductDescription.tsx",
        "line_start": 31,
        "code_snippet": "<div dangerouslySetInnerHTML={{ __html: product.description }} />",
        "cwe_ids": '["CWE-79"]',
        "remediation_guidance": "Pass content through DOMPurify.sanitize() before setting. Install: npm install dompurify @types/dompurify",
        "owasp_category": "A03:2021",
    },
    {
        "title": "Unvalidated redirect after login",
        "description": "The ?next= parameter after OAuth login is not validated against an allowlist, enabling open redirect attacks.",
        "rule_id": "semgrep.js.open-redirect",
        "scanner": "SEMGREP",
        "severity": "MEDIUM",
        "category": "SAST",
        "file_path": "src/auth/callback.ts",
        "line_start": 14,
        "code_snippet": "const next = new URLSearchParams(location.search).get('next')\nwindow.location.href = next || '/'",
        "cwe_ids": '["CWE-601"]',
        "remediation_guidance": "Validate that the next URL is a relative path or matches your domain. Reject absolute URLs to other origins.",
        "owasp_category": "A01:2021",
    },
    {
        "title": "Sensitive data in console.log statements",
        "description": "Multiple console.log statements output user email, session tokens, and API responses in production builds.",
        "rule_id": "semgrep.js.console-log-sensitive",
        "scanner": "SEMGREP",
        "severity": "MEDIUM",
        "category": "SAST",
        "file_path": "src/api/client.ts",
        "line_start": 56,
        "code_snippet": "console.log('Response:', response.data) // includes auth tokens",
        "cwe_ids": '["CWE-532"]',
        "remediation_guidance": "Remove console.log from production code. Use structured logging with redaction filters.",
    },
    {
        "title": "CVE-2024-39338 — axios SSRF",
        "description": "axios < 1.7.4 allows SSRF through request forwarding when baseURL is user-controlled.",
        "rule_id": "snyk.SNYK-JS-AXIOS-7361793",
        "scanner": "SNYK",
        "severity": "MEDIUM",
        "category": "SCA",
        "cve_id": "CVE-2024-39338",
        "cvss_score": 6.5,
        "cwe_ids": '["CWE-918"]',
        "remediation_guidance": "Upgrade axios to >= 1.7.4.",
    },
    {
        "title": "Missing Subresource Integrity on CDN scripts",
        "description": "External scripts loaded from CDN do not use integrity attributes. A compromised CDN could inject malicious code.",
        "rule_id": "semgrep.js.missing-sri",
        "scanner": "SEMGREP",
        "severity": "MEDIUM",
        "category": "SAST",
        "file_path": "index.html",
        "line_start": 12,
        "code_snippet": '<script src="https://cdn.example.com/analytics.js"></script>',
        "cwe_ids": '["CWE-353"]',
        "remediation_guidance": "Add integrity and crossorigin attributes. Generate hash with: openssl dgst -sha384 -binary script.js | openssl base64 -A",
    },
    # LOW
    {
        "title": "Cookie without Secure flag",
        "description": "Session cookies are set without the Secure attribute, allowing them to be transmitted over plaintext HTTP connections.",
        "rule_id": "zap.10011",
        "scanner": "ZAP",
        "severity": "LOW",
        "category": "DAST",
        "url": "https://shop.acme-corp.example.com/login",
        "cwe_ids": '["CWE-614"]',
        "remediation_guidance": "Set Secure flag on all cookies: Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict",
    },
    {
        "title": "Deprecated TLS 1.0/1.1 accepted by server",
        "description": "The web server accepts TLS 1.0 and 1.1 connections which have known vulnerabilities (BEAST, POODLE).",
        "rule_id": "zap.10070",
        "scanner": "ZAP",
        "severity": "LOW",
        "category": "DAST",
        "url": "https://shop.acme-corp.example.com/",
        "cwe_ids": '["CWE-326"]',
        "remediation_guidance": "Configure Nginx/ALB to accept TLS 1.2 and 1.3 only.",
    },
    {
        "title": "X-Frame-Options header absent",
        "description": "The application does not set X-Frame-Options or CSP frame-ancestors, leaving it vulnerable to clickjacking.",
        "rule_id": "zap.10020",
        "scanner": "ZAP",
        "severity": "LOW",
        "category": "DAST",
        "url": "https://shop.acme-corp.example.com/checkout",
        "cwe_ids": '["CWE-1021"]',
        "remediation_guidance": "Add: X-Frame-Options: DENY or use CSP: frame-ancestors 'none'",
    },
    {
        "title": "Source maps exposed in production",
        "description": "JavaScript source maps (.map files) are publicly accessible, exposing the full TypeScript source code to external parties.",
        "rule_id": "semgrep.js.source-maps-exposed",
        "scanner": "SEMGREP",
        "severity": "LOW",
        "category": "SAST",
        "file_path": "vite.config.ts",
        "line_start": 8,
        "code_snippet": "sourcemap: true, // should be false in prod",
        "cwe_ids": '["CWE-540"]',
        "remediation_guidance": "Set sourcemap: false in Vite production build config, or restrict access to .map files in Nginx.",
    },
]

FINDINGS_INFRA_TERRAFORM = [
    # CRITICAL
    {
        "title": "S3 bucket with public ACL — customer-data",
        "description": "The customer-data S3 bucket has ACL set to 'public-read', making all objects publicly downloadable. This bucket contains PII and payment records.",
        "rule_id": "checkov.CKV_AWS_20",
        "scanner": "CHECKOV",
        "severity": "CRITICAL",
        "category": "IAC",
        "file_path": "modules/storage/s3.tf",
        "line_start": 12,
        "code_snippet": '  acl = "public-read"',
        "cwe_ids": '["CWE-732"]',
        "remediation_guidance": "Set acl = 'private' and enable aws_s3_bucket_public_access_block with block_public_acls = true.",
    },
    {
        "title": "RDS instance publicly accessible",
        "description": "The production PostgreSQL RDS instance has publicly_accessible = true, exposing the database endpoint to the internet.",
        "rule_id": "checkov.CKV_AWS_17",
        "scanner": "CHECKOV",
        "severity": "CRITICAL",
        "category": "IAC",
        "file_path": "modules/database/rds.tf",
        "line_start": 28,
        "code_snippet": "  publicly_accessible = true",
        "cwe_ids": '["CWE-668"]',
        "remediation_guidance": "Set publicly_accessible = false. Access RDS via VPC and private subnets only. Use a bastion host or VPN for admin access.",
    },
    # HIGH
    {
        "title": "IAM role with wildcard action on all resources",
        "description": "An IAM role used by EKS pods grants Action: '*' on Resource: '*', violating least privilege. Any compromised pod gains full AWS account access.",
        "rule_id": "checkov.CKV_AWS_40",
        "scanner": "CHECKOV",
        "severity": "HIGH",
        "category": "IAC",
        "file_path": "modules/iam/eks-pod-role.tf",
        "line_start": 18,
        "code_snippet": '  actions   = ["*"]\n  resources = ["*"]',
        "cwe_ids": '["CWE-269"]',
        "remediation_guidance": "Enumerate only the specific IAM actions required. Use resource-specific ARNs.",
    },
    {
        "title": "Security group allows unrestricted inbound SSH (0.0.0.0/0)",
        "description": "An EC2 security group allows SSH (port 22) from any IP address, exposing the instance to brute-force and exploitation attempts.",
        "rule_id": "checkov.CKV_AWS_24",
        "scanner": "CHECKOV",
        "severity": "HIGH",
        "category": "IAC",
        "file_path": "modules/network/security_groups.tf",
        "line_start": 35,
        "code_snippet": '  cidr_blocks = ["0.0.0.0/0"]  # SSH open to world',
        "cwe_ids": '["CWE-284"]',
        "remediation_guidance": "Restrict SSH to bastion host IPs or use AWS Systems Manager Session Manager instead of SSH.",
    },
    {
        "title": "EKS cluster with public endpoint and no CIDR restrictions",
        "description": "The EKS API server endpoint is public and has no CIDR block restrictions, allowing anyone to query the Kubernetes API.",
        "rule_id": "checkov.CKV_AWS_58",
        "scanner": "CHECKOV",
        "severity": "HIGH",
        "category": "IAC",
        "file_path": "modules/compute/eks.tf",
        "line_start": 44,
        "code_snippet": '  endpoint_public_access       = true\n  public_access_cidrs          = ["0.0.0.0/0"]',
        "cwe_ids": '["CWE-284"]',
        "remediation_guidance": "Set endpoint_public_access = false for production. Use private endpoint with VPN access.",
    },
    {
        "title": "S3 bucket versioning disabled on backup bucket",
        "description": "Versioning is disabled on the database backup S3 bucket. Accidental or malicious deletion of objects cannot be recovered.",
        "rule_id": "checkov.CKV_AWS_21",
        "scanner": "CHECKOV",
        "severity": "HIGH",
        "category": "IAC",
        "file_path": "modules/storage/backups.tf",
        "line_start": 9,
        "code_snippet": "# versioning block absent",
        "cwe_ids": '["CWE-693"]',
        "remediation_guidance": "Add a versioning block with enabled = true. Also enable MFA delete for the backup bucket.",
    },
    {
        "title": "CloudTrail logging disabled in us-west-2",
        "description": "CloudTrail is not enabled in the us-west-2 region where production workloads run, creating a blind spot in audit logging.",
        "rule_id": "checkov.CKV_AWS_67",
        "scanner": "CHECKOV",
        "severity": "HIGH",
        "category": "IAC",
        "file_path": "modules/logging/cloudtrail.tf",
        "line_start": 5,
        "cwe_ids": '["CWE-778"]',
        "remediation_guidance": "Enable CloudTrail in all regions with multi-region trail and log file validation enabled.",
    },
    # MEDIUM
    {
        "title": "EBS volumes not encrypted at rest",
        "description": "EBS volumes attached to EC2 instances are not encrypted. Data at rest on these volumes could be accessed if volumes are mishandled.",
        "rule_id": "checkov.CKV_AWS_8",
        "scanner": "CHECKOV",
        "severity": "MEDIUM",
        "category": "IAC",
        "file_path": "modules/compute/ec2.tf",
        "line_start": 22,
        "code_snippet": "  encrypted = false",
        "cwe_ids": '["CWE-312"]',
        "remediation_guidance": "Set encrypted = true and specify a KMS key ARN in the root_block_device block.",
    },
    {
        "title": "RDS automated backups disabled",
        "description": "The RDS instance has backup_retention_period = 0, disabling automated backups. Data loss in a failure scenario cannot be recovered via point-in-time restore.",
        "rule_id": "checkov.CKV_AWS_133",
        "scanner": "CHECKOV",
        "severity": "MEDIUM",
        "category": "IAC",
        "file_path": "modules/database/rds.tf",
        "line_start": 34,
        "code_snippet": "  backup_retention_period = 0",
        "cwe_ids": '["CWE-693"]',
        "remediation_guidance": "Set backup_retention_period to at least 7 (days). For production, 30 days is recommended.",
    },
    {
        "title": "Secrets Manager rotation not enabled",
        "description": "Database credentials stored in AWS Secrets Manager do not have automatic rotation configured, leaving long-lived static secrets in use.",
        "rule_id": "checkov.CKV_AWS_149",
        "scanner": "CHECKOV",
        "severity": "MEDIUM",
        "category": "IAC",
        "file_path": "modules/secrets/db_credentials.tf",
        "line_start": 14,
        "cwe_ids": '["CWE-798"]',
        "remediation_guidance": "Enable rotation with a Lambda rotation function. Use the aws_secretsmanager_secret_rotation resource.",
    },
    {
        "title": "VPC Flow Logs not enabled",
        "description": "VPC Flow Logs are disabled for the production VPC. Network-level anomaly detection and forensics are not possible without this data.",
        "rule_id": "checkov.CKV2_AWS_11",
        "scanner": "CHECKOV",
        "severity": "MEDIUM",
        "category": "IAC",
        "file_path": "modules/network/vpc.tf",
        "line_start": 8,
        "cwe_ids": '["CWE-778"]',
        "remediation_guidance": "Add aws_flow_log resource pointing to a CloudWatch log group or S3 bucket.",
    },
    {
        "title": "Terraform state stored in unencrypted S3 bucket",
        "description": "The Terraform remote state backend uses an S3 bucket without server-side encryption. State files often contain sensitive values.",
        "rule_id": "semgrep.tf.s3-state-unencrypted",
        "scanner": "SEMGREP",
        "severity": "MEDIUM",
        "category": "IAC",
        "file_path": "backend.tf",
        "line_start": 6,
        "code_snippet": '  bucket = "acme-terraform-state"  # no encrypt = true',
        "cwe_ids": '["CWE-312"]',
        "remediation_guidance": "Add encrypt = true and specify a KMS key in the backend configuration.",
    },
    # LOW
    {
        "title": "S3 bucket access logging not enabled",
        "description": "Server access logging is disabled for S3 buckets, reducing auditability of object access patterns.",
        "rule_id": "checkov.CKV_AWS_18",
        "scanner": "CHECKOV",
        "severity": "LOW",
        "category": "IAC",
        "file_path": "modules/storage/s3.tf",
        "line_start": 18,
        "cwe_ids": '["CWE-778"]',
        "remediation_guidance": "Add a logging block to each bucket resource pointing to a central logging bucket.",
    },
    {
        "title": "RDS deletion protection disabled",
        "description": "Deletion protection is not enabled on the production RDS instance. The database could be accidentally destroyed with a terraform destroy.",
        "rule_id": "checkov.CKV_AWS_293",
        "scanner": "CHECKOV",
        "severity": "LOW",
        "category": "IAC",
        "file_path": "modules/database/rds.tf",
        "line_start": 38,
        "code_snippet": "  deletion_protection = false",
        "cwe_ids": '["CWE-693"]',
        "remediation_guidance": "Set deletion_protection = true on all production RDS instances.",
    },
    {
        "title": "EC2 instance uses outdated AMI",
        "description": "The AMI specified is more than 6 months old. Recent security patches and OS updates may not be included.",
        "rule_id": "checkov.CKV_AWS_8_AMI",
        "scanner": "CHECKOV",
        "severity": "LOW",
        "category": "IAC",
        "file_path": "modules/compute/ec2.tf",
        "line_start": 8,
        "code_snippet": '  ami = "ami-0c55b159cbfafe1f0"  # Amazon Linux 2, 2022',
        "cwe_ids": '["CWE-1104"]',
        "remediation_guidance": "Use data source to fetch the latest AMI: data 'aws_ami' 'amazon_linux_2' { most_recent = true }",
    },
]

ALL_REPO_FINDINGS = [
    FINDINGS_PAYMENTS_API,
    FINDINGS_WEB_FRONTEND,
    FINDINGS_INFRA_TERRAFORM,
]

# Scanners used in historical scans per repo
REPO_SCANNERS = [
    ["SEMGREP", "BANDIT", "TRIVY", "GRYPE", "SNYK"],
    ["SEMGREP", "TRIVY", "GRYPE", "ZAP"],
    ["CHECKOV", "TRIVY", "SEMGREP"],
]

# ─── Helpers ───────────────────────────────────────────────────────────────────

def fp(repo_name: str, rule_id: str, file_path: str | None, line: int | None) -> str:
    raw = f"{repo_name}:{rule_id}:{file_path or ''}:{line or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()[:40]


def days_ago(n: float) -> datetime:
    return NOW - timedelta(days=n)


def jira_key(project: str, n: int) -> str:
    return f"{project}-{100 + n}"


# ─── Seed ─────────────────────────────────────────────────────────────────────

async def seed():
    await init_db()

    async with AsyncSessionLocal() as db:
        print("🌑 Seeding Nyx demo data...")

        # ── Wipe existing demo repos (idempotent re-runs) ──────────────────────
        demo_names = [r["github_full_name"] for r in REPOS]
        existing = await db.execute(
            select(Repository).where(Repository.github_full_name.in_(demo_names))
        )
        for old_repo in existing.scalars().all():
            # cascade-delete scans, findings, jira_links
            scans_q = await db.execute(select(Scan).where(Scan.repository_id == old_repo.id))
            for s in scans_q.scalars().all():
                findings_q = await db.execute(select(Finding).where(Finding.scan_id == s.id))
                for f in findings_q.scalars().all():
                    await db.execute(delete(JiraLink).where(JiraLink.finding_id == f.id))
                    await db.delete(f)
                await db.delete(s)
            # also delete findings directly linked to repo (no scan_id)
            all_findings = await db.execute(
                select(Finding).where(Finding.repository_id == old_repo.id)
            )
            for f in all_findings.scalars().all():
                await db.execute(delete(JiraLink).where(JiraLink.finding_id == f.id))
                await db.delete(f)
            await db.delete(old_repo)

        await db.flush()

        # ── Create repositories ────────────────────────────────────────────────
        repo_objects = []
        for r in REPOS:
            repo = Repository(
                github_full_name=r["github_full_name"],
                default_branch="main",
                description=r["description"],
                language=r["language"],
                is_private=r["is_private"],
                webhook_active=True,
                enabled_scanners=r["scanners"],
            )
            db.add(repo)
            repo_objects.append(repo)

        await db.flush()
        print(f"  ✓ Created {len(repo_objects)} repositories")

        # ── Create 12 weeks of scan history ───────────────────────────────────
        # Each repo gets 2-3 scans per week across its scanners
        all_scans: list[Scan] = []
        for repo_idx, repo in enumerate(repo_objects):
            scanners = REPO_SCANNERS[repo_idx]
            week_count = 12
            for week in range(week_count, 0, -1):
                # pick 2-3 scanners randomly for this week
                week_scanners = random.sample(scanners, k=min(random.randint(2, 3), len(scanners)))
                for scanner in week_scanners:
                    age_days = week * 7 - random.uniform(0, 4)
                    started = days_ago(age_days)
                    new_ct = random.randint(1, 6) if week > 8 else random.randint(0, 3)
                    fixed_ct = random.randint(0, 2)
                    total_ct = random.randint(new_ct + fixed_ct, new_ct + fixed_ct + 12)
                    scan = Scan(
                        repository_id=repo.id,
                        scanner=scanner,
                        trigger=ScanTrigger.WEBHOOK.value,
                        status=ScanStatus.COMPLETED.value,
                        git_ref="main",
                        finding_count=total_ct,
                        new_finding_count=new_ct,
                        fixed_finding_count=fixed_ct,
                        started_at=started,
                        completed_at=started + timedelta(minutes=random.randint(3, 12)),
                    )
                    db.add(scan)
                    all_scans.append(scan)

        await db.flush()
        print(f"  ✓ Created {len(all_scans)} scan records (12 weeks × 3 repos)")

        # ── Create findings ────────────────────────────────────────────────────
        jira_ticket_counter = 0
        total_findings = 0

        # Status weight distribution: 65% OPEN, 15% FIXED, 10% IN_REMEDIATION, 10% SUPPRESSED
        def pick_status(severity: str) -> str:
            r = random.random()
            # CRITICAL/HIGH findings are more likely to be acted on
            if severity in ("CRITICAL", "HIGH"):
                if r < 0.60:
                    return FindingStatus.OPEN.value
                elif r < 0.80:
                    return FindingStatus.IN_REMEDIATION.value
                elif r < 0.95:
                    return FindingStatus.FIXED.value
                else:
                    return FindingStatus.SUPPRESSED.value
            else:
                if r < 0.70:
                    return FindingStatus.OPEN.value
                elif r < 0.82:
                    return FindingStatus.FIXED.value
                elif r < 0.90:
                    return FindingStatus.ACCEPTED_RISK.value
                else:
                    return FindingStatus.SUPPRESSED.value

        def mttr_days(severity: str) -> int:
            """Realistic mean time to remediate based on severity."""
            base = {"CRITICAL": 5, "HIGH": 18, "MEDIUM": 45, "LOW": 90, "INFO": 150}
            b = base.get(severity, 30)
            return max(1, int(random.gauss(b, b * 0.3)))

        for repo_idx, (repo, findings_list) in enumerate(zip(repo_objects, ALL_REPO_FINDINGS)):
            repo_scans = [s for s in all_scans if s.repository_id == repo.id]
            open_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            finding_objects: list[Finding] = []

            for f_idx, f_data in enumerate(findings_list):
                # Spread first_seen_at across last 90 days — older findings first
                age_days = random.uniform(5, 85)
                first_seen = days_ago(age_days)
                status = pick_status(f_data["severity"])

                # Assign to a matching scan (same scanner, closest in time)
                matching_scans = [s for s in repo_scans if s.scanner == f_data["scanner"]]
                scan = matching_scans[f_idx % len(matching_scans)] if matching_scans else repo_scans[0]

                # Resolved at
                if status in (FindingStatus.FIXED.value, FindingStatus.ACCEPTED_RISK.value):
                    days_to_fix = mttr_days(f_data["severity"])
                    resolved_at = min(first_seen + timedelta(days=days_to_fix), NOW)
                elif status == FindingStatus.SUPPRESSED.value:
                    resolved_at = first_seen + timedelta(days=random.randint(1, 7))
                else:
                    resolved_at = None

                sev_enum = Severity(f_data["severity"])

                finding = Finding(
                    fingerprint=fp(repo.github_full_name, f_data["rule_id"], f_data.get("file_path"), f_data.get("line_start")),
                    repository_id=repo.id,
                    scan_id=scan.id,
                    title=f_data["title"],
                    description=f_data["description"],
                    rule_id=f_data["rule_id"],
                    scanner=f_data["scanner"],
                    scanner_sources=f_data["scanner"],
                    category=f_data["category"],
                    severity=f_data["severity"],
                    file_path=f_data.get("file_path"),
                    line_start=f_data.get("line_start"),
                    line_end=f_data.get("line_end"),
                    code_snippet=f_data.get("code_snippet"),
                    url=f_data.get("url"),
                    cwe_ids=f_data.get("cwe_ids", "[]"),
                    cve_id=f_data.get("cve_id"),
                    owasp_category=f_data.get("owasp_category"),
                    remediation_guidance=f_data.get("remediation_guidance"),
                    cvss_score=f_data.get("cvss_score"),
                    is_exploitable=f_data.get("is_exploitable", False),
                    status=status,
                    first_seen_at=first_seen,
                    last_seen_at=NOW - timedelta(hours=random.randint(0, 48)),
                    resolved_at=resolved_at,
                    priority_score=round(
                        sev_enum.weight * 65
                        + (f_data.get("cvss_score") or 0) * 2
                        + (10 if f_data.get("is_exploitable") else 0)
                        + random.uniform(0, 15),
                        2
                    ),
                    sla_breach_at=first_seen + timedelta(days=sev_enum.sla_days),
                )
                db.add(finding)
                finding_objects.append(finding)

                if status == FindingStatus.OPEN.value:
                    open_counts[f_data["severity"]] += 1

            await db.flush()
            total_findings += len(finding_objects)

            # ── Create JIRA links for ~40% of CRITICAL/HIGH open findings ──────
            jira_project = repo.github_full_name.split("/")[1].upper().replace("-", "")[:4]
            jira_statuses = ["To Do", "In Progress", "In Progress", "Done", "In Progress"]
            jira_priorities = ["Highest", "High", "High", "Medium", "High"]
            jira_assignees = ["alice@acme-corp.com", "bob@acme-corp.com", None, "carol@acme-corp.com", None]

            for f in finding_objects:
                sev = f.severity
                if sev in ("CRITICAL", "HIGH") and f.status == FindingStatus.OPEN.value:
                    if random.random() < 0.45:
                        await db.flush()  # ensure f.id is set
                        jira_ticket_counter += 1
                        ticket_key = jira_key(jira_project, jira_ticket_counter)
                        pick = jira_ticket_counter % len(jira_statuses)
                        link = JiraLink(
                            finding_id=f.id,
                            jira_issue_key=ticket_key,
                            jira_issue_url=f"https://acme-corp.atlassian.net/browse/{ticket_key}",
                            jira_project_key=jira_project,
                            jira_status=jira_statuses[pick],
                            jira_priority=jira_priorities[pick],
                            jira_assignee=jira_assignees[pick],
                            synced_at=NOW - timedelta(hours=random.randint(1, 72)),
                        )
                        db.add(link)

            # ── Update repo aggregate stats ────────────────────────────────────
            risk = (
                open_counts["CRITICAL"] * 25
                + open_counts["HIGH"] * 10
                + open_counts["MEDIUM"] * 3
                + open_counts["LOW"] * 0.5
            )
            repo.open_critical = open_counts["CRITICAL"]
            repo.open_high = open_counts["HIGH"]
            repo.open_medium = open_counts["MEDIUM"]
            repo.open_low = open_counts["LOW"]
            repo.open_info = open_counts.get("INFO", 0)
            repo.risk_score = min(round(risk, 1), 100)
            repo.last_scan_at = NOW - timedelta(hours=random.randint(1, 6))

        await db.commit()

        print(f"  ✓ Created {total_findings} findings across {len(repo_objects)} repos")
        print(f"  ✓ Created {jira_ticket_counter} JIRA ticket links")
        print()
        print("🌑 Demo data seeded successfully!")
        print()
        for repo in repo_objects:
            print(f"   {repo.github_full_name}  risk={repo.risk_score}  "
                  f"C={repo.open_critical} H={repo.open_high} M={repo.open_medium} L={repo.open_low}")
        print()
        print("   Open http://localhost:3000 to explore the dashboard.")


async def wipe():
    """Delete all demo repos and their associated data, then exit."""
    await init_db()
    demo_names = [r["github_full_name"] for r in REPOS]
    async with AsyncSessionLocal() as db:
        print("🌑 Wiping Nyx demo data...")
        existing = await db.execute(
            select(Repository).where(Repository.github_full_name.in_(demo_names))
        )
        removed = 0
        for old_repo in existing.scalars().all():
            scans_q = await db.execute(select(Scan).where(Scan.repository_id == old_repo.id))
            for s in scans_q.scalars().all():
                findings_q = await db.execute(select(Finding).where(Finding.scan_id == s.id))
                for f in findings_q.scalars().all():
                    await db.execute(delete(JiraLink).where(JiraLink.finding_id == f.id))
                    await db.delete(f)
                await db.delete(s)
            all_findings = await db.execute(
                select(Finding).where(Finding.repository_id == old_repo.id)
            )
            for f in all_findings.scalars().all():
                await db.execute(delete(JiraLink).where(JiraLink.finding_id == f.id))
                await db.delete(f)
            await db.delete(old_repo)
            removed += 1
        await db.commit()
        if removed:
            print(f"  ✓ Removed {removed} demo repo(s) and all associated data.")
        else:
            print("  Nothing to remove — no demo repos found.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Nyx demo data tool")
    parser.add_argument("--wipe", action="store_true", help="Delete demo data and exit without re-seeding")
    args = parser.parse_args()

    if args.wipe:
        asyncio.run(wipe())
    else:
        asyncio.run(seed())
