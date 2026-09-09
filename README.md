# SEER — Secure Exposure Elimination & Redaction

Local-first data-loss prevention for generative-AI interactions. SEER scans text locally before it is submitted to supported AI sites, shows an explainable warning, and produces a safe redacted preview. It is designed to support privacy-by-design and data-minimization practices; it is not legal advice, a compliance certification, or an Aadhaar/UIDAI verification product.

## Included MVP

- Spring Boot 3.4 / Java 17 loopback API at `127.0.0.1:8080`.
- Deterministic detectors for Aadhaar-like identifiers, PAN-like identifiers, Indian phones, email, IFSC, UPI, payment cards (Luhn), contextual bank accounts, secrets, passwords, and address postal codes.
- No raw prompt or sensitive value is persisted or returned. Audit metadata contains category, severity, confidence, safe preview, domain, and timestamp only.
- Security console at `/`, OpenAPI at `/swagger-ui.html`, health at `/api/v1/health`.
- Manifest V3 extension for ChatGPT, Gemini, Claude, and Copilot. It uses localhost only and shows Mask/Edit/Cancel/Allow Once controls.

## Run on Windows

```powershell
cd seer-aii
.\mvnw.cmd clean verify
.\mvnw.cmd spring-boot:run
```

Open `http://127.0.0.1:8080/`. Load `seer-extension` with Chrome/Edge → Extensions → Developer mode → Load unpacked. Use synthetic test values only. The wrapper requires a supported JDK (17 or newer); if PowerShell cannot launch it, install a JDK and ensure `JAVA_HOME` is set.

Example API call:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/api/v1/scan -Method Post -ContentType 'application/json' -Body (@{text='Synthetic PAN ABCDE1234F and email demo@example.com';sourceDomain='chatgpt.com';inputMode='PASTE';policyProfile='PERSONAL'} | ConvertTo-Json)
```

## Production checklist

Before deployment, add authenticated users and organization policy storage, PostgreSQL/Flyway migrations, TLS termination, pairing-token authentication, CSP review, code signing, penetration testing, dependency scanning, retention/deletion controls, monitoring/SIEM, key rotation, incident response, and browser-store review. Do not bind the service to `0.0.0.0` without a reviewed production security boundary.

See `seer-aii/src/main/java` for the detector implementation and `seer-extension` for the browser client.

## What changed in this release

### Backend

- Replaced the incompatible Spring Initializr dependency set with Spring Boot 3.4.5, Java 17, Spring Web, validation, Security, Actuator, OpenAPI, H2 runtime support, and test dependencies.
- Added `POST /api/v1/scan`, with request validation, request IDs, severity summaries, safe previews, redacted text, and an explicit `rawTextStored: false` response field.
- Added `/api/v1/health`, `/api/v1/metrics-summary`, `/api/v1/audit-events`, and `/api/v1/policies`.
- Configured the server to bind to `127.0.0.1` by default and added restricted CORS and security headers.
- Added centralized deterministic detection for API secrets, passwords in context, payment cards with Luhn validation, PAN-like identifiers, IFSC, UPI handles, email, Indian phone numbers, Aadhaar-like numbers, contextual bank accounts, and address postal codes.
- Added overlap resolution so higher-risk detections take precedence and card candidates that fail Luhn are discarded.
- Raw values are used only during the in-memory scan and are not returned in detection objects or audit metadata.

### Dashboard

- Added a dark security-console dashboard at `/`.
- Added privacy posture, scan count, metadata event count, and raw-storage status cards.
- Added a local live-scan console with redacted preview and explanations.

### Browser extension

- Added Manifest V3 configuration for ChatGPT, ChatGPT legacy, Gemini, Claude, and Copilot only.
- Added localhost communication through the background service worker.
- Added paste interception and an accessible in-page warning with Mask and Continue, Edit Text, Cancel, and Allow Once choices.
- Added popup connection status, protection toggle, and dashboard link.

### Repository and delivery

- Added `.env.example` containing no secrets.
- Added root and module `.gitignore` rules that ignore `.env`, `.env.*`, credentials, build output, IDE files, and logs while allowing `.env.example`.
- Added GitHub Actions workflow at `.github/workflows/build.yml` to run Maven verification on pushes and pull requests.
- Pushed commit `7632d35` to the `main` branch.

## Secret-file safety

Never create or commit `.env` in this repository. Copy `.env.example` to a local, untracked `.env` only when environment configuration is needed. Verify before pushing:

```powershell
git status --short
git ls-files '*env*' '*secret*' '*credential*'
```

The only environment file currently tracked is `.env.example`, which contains no credentials.

## Verification status

JavaScript syntax checks and `git diff --check` passed before the push. The local environment did not have a runnable Java/Maven installation, so the Java test suite could not be executed here; the GitHub Actions workflow performs the Maven build in CI. Install JDK 17+ locally and run `.\mvnw.cmd clean verify` before deployment.
