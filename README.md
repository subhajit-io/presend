# Presend - Zero-AI Local Privacy Shield

A 100% deterministic, zero-AI, client-side pre-processor that strips personal identifiable information (PII) before text is shared with any cloud AI service or third-party platform.

---

## Why Zero-AI?

If an AI model (like an LLM or cloud API) inspects raw text to redact it, the privacy shield has already failed — the AI provider has already received your unredacted personal data. 

**Presend guarantees zero data leakage**:
- **0 external network requests**
- **0 AI models or LLM dependencies**
- **100% local, deterministic linguistic algorithms**
- **Runs entirely offline in Python CLI or through your browser**

---

## Architecture

### 1. Presentation Frontend (`index.html`)
- Pure presentation layer: zero regex patterns, zero linguistic dictionaries, zero cloud connections.
- Interactive token badges, bidirectional token highlighter, label switcher dropdowns, and conversion audit log.
- Communicates directly with the local Python server via loopback API (`POST /api/redact`).
- If the server is not reachable, the UI indicates "Server Down" and performs zero redaction.

### 2. Core Engine & Server (`presend.py`)
- **Names & Self-Introductions**: Masked as `[Name]` rendered in bold green text (e.g. `I am Krish` -> `I am [Name]`, `Please call Subhajit` -> `Please call [Name]`).
- **Addresses & Locations**: Detected via address suffixes (`MG Road`, `Greenfield Apts`) as well as location/residence context (`I live in Arambagh` -> `I live in [ADDRESS]`).
- **Software & Technical Terms Protected**: Technical common nouns and artifacts (`PII Redactor`, `React App`, `Node Server`, `Mask`) are preserved and not falsely flagged as personal names.
- **Universal Digit Encoding**: Every digit `0-9` is encoded with `X` (phone numbers `XXXXXXXXXX`, prices `XXXXXrs`, PINs `XXXXXX`, Aadhaar `XXXX XXXX XXXX`).
- **Emails & Credentials**: Replaced with `[EMAIL]`, `[PASSWORD]`, `[API_KEY]`, `[DB_URI]`.
- **National IDs & Payment Handles**: Indian PAN cards (`[PAN]`), Aadhaar (`[AADHAAR]`), Passports (`[PASSPORT]`), and UPI handles (`[UPI_ID]`).

---

## Running Presend

### Web Application (HTML Frontend + Local Server)
Start the Python backend server:
```bash
python presend.py
```
Open `http://127.0.0.1:8000/` in your browser. All PII detection, tokenization, tracking, and live stats calculation run under the hood in Python.

### Python CLI
```bash
python presend.py "Hello my name is Krish. I live in Arambagh. My phone number is +91 7001023356. I made this PII Redactor named Mask." --track
```

---

## License

Copyright (c) 2026 Subhajit Das (subhajit-io). All rights reserved.

This project is licensed under the **Presend Non-Commercial, No-Derivatives License (NC-ND)**:
- **Commercial Use Prohibited**: You may not use this software or any part thereof for commercial purposes, business operations, or monetization.
- **Modifications Prohibited**: You may not alter, adapt, fork, or create derivative works based on this codebase.
- **Personal and Educational Use Only**: You are permitted to view, inspect, test, and run unmodified verbatim copies solely for personal and educational purposes.

See the [`LICENSE`](LICENSE) file for the full legal text.
