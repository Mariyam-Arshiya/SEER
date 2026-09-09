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
