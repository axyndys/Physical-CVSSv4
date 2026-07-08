# PhysVuln_Evaluator (Physical Vulnerability Evaluator)

PhysVuln Evaluator

A Web-Based Scoring Tool for Physical Security Vulnerabilities in Converged Vulnerability Management. The PhysVuln Evaluator is available via: https://physical-cvssv4.onrender.com/

The web application, formerly known as Physical-CVSS and tailored to the needs of physical security, is part of the work:
STECKEROVÁ, Andrea. Propojení fyzické a kybernetické bezpečnosti při správě zranitelností v podnikovém prostředí. Online. Bakalářská práce. Ostrava: Vysoká škola báňská - Technická univerzita Ostrava, Fakulta bezpečnostního inženýrství. 2026. Available from: https://theses.cz/id/hn44ov/.

---
**Autor:** Andrea Steckerová

---
## Statement on the use of AI tools
The following artificial intelligence tools were used during the development of this project:
- Google Gemini – to assist with debugging the "Physical-CVSSv4" calculator script,
- Claude Code – to further assist with debugging the script and creating the index.html (HTML, CSS) design for the “Physical-CVSSv4” calculator’s web interface, which was subsequently modified by the author.


---
## Table of Contents

1. [Abstract](#abstract)
2. [Theoretical Background](#theoretical-background)
3. [Metric Taxonomy](#metric-taxonomy)
4. [Vector and Score Computation](#vector-and-score-computation)
5. [Severity Classification](#severity-classification)
6. [System Architecture](#system-architecture)
7. [Project Structure](#project-structure)
8. [Installation and Setup](#installation-and-setup)
9. [Usage Guide](#usage-guide)
10. [API Reference](#api-reference)
11. [Internationalization (i18n)](#internationalization-i18n)
12. [Limitations and Future Work](#limitations-and-future-work)
13. [References](#references)
14. [License](#license)

---

## Abstract

PhysVuln Evaluator is a web-based decision-support tool designed to provide a systematic, quantifiable, and repeatable methodology for assessing the severity of physical security vulnerabilities within organizations that adopt a converged approach to security risk management, i.e., the unified governance of both cyber and physical threat domains. The application addresses a long-standing methodological asymmetry between the highly standardized vulnerability scoring practices established in the information security domain and the comparatively fragmented, often qualitative and subjective, approaches historically applied to the evaluation of physical security deficiencies such as inadequately protected access zones, weak perimeter barriers, or insufficient technical surveillance measures.

The core contribution of this tool is the adaptation of the **Common Vulnerability Scoring System version 4.0 (CVSS v4.0)** — the de facto industry standard for scoring software vulnerabilities — into a structurally analogous framework applicable to physical security contexts. This adapted methodology is internally referred to as **P-CVSS (Physical CVSS)**. It preserves the hierarchical metric-group structure and machine-readable vector notation of CVSS v4.0 while redefining the semantic content of individual metrics to reflect physical, rather than digital, attack surfaces and consequences.

---

## Theoretical Background

CVSS v4.0, maintained by the **Forum of Incident Response and Security Teams (FIRST.org)**, decomposes a vulnerability's severity into a structured set of metrics describing, on one hand, the conditions required for successful exploitation, and on the other, the scope and nature of the resulting impact. The output of this decomposition is twofold: a normalized numerical score in the range of 0.0–10.0, and a compact, machine-readable vector string that unambiguously encodes the specific combination of metric values used in the calculation.

The theoretical premise underlying PhysVuln Evaluator is that this same structural logic — separating *exploitability* from *impact*, and further separating impact on the *directly affected asset* from impact *propagated to subsequent, dependent assets* — is fully transferable to the physical security domain. In both domains, the severity of a vulnerability is a function of comparable underlying factors: the attacker's positional or logical proximity to the target, the complexity of the countermeasures that must be circumvented, the level of pre-existing privilege or access required, and the degree of dependency on interaction with another human actor (e.g., social engineering or tailgating in the physical context).

A key domain-specific extension introduced by P-CVSS is the explicit treatment of **human health and life safety** as a first-class supplemental metric, reflecting the fact that, unlike purely informational vulnerabilities, the exploitation of physical security weaknesses may directly endanger human life. This is operationalized through a scoring rule in which a high or medium safety impact automatically escalates the confidentiality, integrity, and availability impact on subsequent systems to their maximum value, in accordance with a precautionary principle that prioritizes the protection of persons over purely material or informational considerations.

---

## Metric Taxonomy

The evaluation model is organized into four hierarchical metric groups, collectively comprising sixteen individual metrics. Each metric is presented to the assessor as a closed set of mutually exclusive options, rather than free-text input, in order to minimize recording error and enforce terminological consistency across assessors.

### 1. Base Metrics — Exploitability

| Code | Metric | Description |
|------|--------|-------------|
| `AV` | Attack Vector | The security zone in which the vulnerability is located (Public, Controlled, Protected, Secured). |
| `AC` | Attack Complexity | The degree of complexity of the security mechanisms the attacker must bypass. |
| `AT` | Attack Requirements | Whether exploitation is contingent upon additional specific preconditions. |
| `PR` | Privileges Required | The level of legitimate access or authorization the attacker must possess prior to the attack. |
| `UI` | User Interaction | The degree to which successful exploitation depends on the (conscious or unconscious) cooperation of another person. |

### 2. Base Metrics — Vulnerable System Impact

| Code | Metric | Description |
|------|--------|-------------|
| `VC` | Confidentiality | Impact on the confidentiality of the directly affected security measure. |
| `VI` | Integrity | Impact on the integrity of the directly affected security measure. |
| `VA` | Availability | Impact on the availability of the directly affected security measure. |

### 3. Base Metrics — Subsequent System Impact

| Code | Metric | Description |
|------|--------|-------------|
| `SC` | Confidentiality | Impact on the confidentiality of the asset(s) protected by the compromised measure. |
| `SI` | Integrity | Impact on the integrity of the asset(s) protected by the compromised measure. |
| `SA` | Availability | Impact on the availability of the asset(s) protected by the compromised measure. |

This distinction between the *vulnerable system* (the security measure itself) and the *subsequent system* (the asset it protects) allows the model to capture the cascading nature of physical security incidents, in which the breach of a single protective layer typically exposes far more valuable assets in its immediate vicinity.

### 4. Supplemental Metric — Safety

| Code | Metric | Description |
|------|--------|-------------|
| `S` | Safety | The extent to which exploitation of the vulnerability may endanger human health or life. |

If `S = P` (High/Medium safety impact), the application automatically overrides `SC`, `SI`, and `SA` to `H` (High) prior to score computation, regardless of the assessor's original selection for those metrics. This business rule is implemented in the `/calculate` endpoint in `app.py`.

### 5. Environmental Metrics — Security Requirements

| Code | Metric | Description |
|------|--------|-------------|
| `CR` | Confidentiality Requirement | The criticality of confidentiality for the affected asset within the specific organizational context. |
| `IR` | Integrity Requirement | The criticality of integrity for the affected asset within the specific organizational context. |
| `AR` | Availability Requirement | The criticality of availability for the affected asset within the specific organizational context. |

These metrics allow the base score to be contextually recalibrated to reflect the actual value and significance of the protected asset at a specific site, acknowledging that an identical vulnerability may carry a substantially different level of criticality across different facilities or operational contexts.

### 6. Threat Metric

| Code | Metric | Description |
|------|--------|-------------|
| `E` | Exploit Maturity | The current prevalence and maturity of known methods of exploiting the vulnerability (Actively exploited / Proof-of-concept / Rarely exploited). |

---

## Vector and Score Computation

All selected metric values are assembled, in the fixed order mandated by the CVSS v4.0 specification, into a single vector string prefixed with `CVSS:4.0/`, e.g.:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:P/CR:H/IR:H/AR:H/E:A
```

This vector construction is handled by the `sestavit_vektor()` function in `p_cvss.py`. The resulting string is passed to the `CVSS4` class of the third-party [`cvss`](https://pypi.org/project/cvss/) Python package, which validates the vector against the official CVSS v4.0 grammar and computes the corresponding base score (0.0–10.0).

> **Note:** Although the numerical scoring algorithm itself is delegated to the standards-compliant `cvss` library (ensuring mathematical correctness and specification conformance), the *semantic meaning* assigned to each metric option is redefined for the physical security domain, as described in the [Metric Taxonomy](#metric-taxonomy) section above.

---

## Severity Classification

In addition to the numerical score, the application derives a qualitative severity rating using the `urcit_kritickost()` function in `p_cvss.py`. This mirrors the standard CVSS qualitative severity scale:

| Score range (s) | Severity |
|---|---|
| `s = 0` | None |
| `0 < s < 4` | Low |
| `4 ≤ s < 7` | Medium |
| `7 ≤ s < 9` | High |
| `9 ≤ s ≤ 10` | Critical |

The function returns a language-agnostic key (e.g., `severity_high`) rather than a localized string; the corresponding human-readable label is resolved at render time via the active translation dictionary (see [Internationalization](#internationalization-i18n)).

---

## System Architecture

The application follows a conventional server-rendered web architecture with a lightweight, dependency-free JavaScript frontend:

- **Backend:** [Flask](https://flask.palletsprojects.com/) (Python), responsible for routing, session-based language state, translation dictionary loading, vector assembly, and score/severity computation via the `cvss` library.
- **Templating:** Jinja2, used to render the metric selection interface dynamically from the `METRIKY` data structure and to inject localized strings into the markup.
- **Frontend:** Vanilla HTML5, CSS3 (custom properties for theming), and unobfuscated JavaScript (`fetch` API) — no build step or frontend framework is required.
- **Computation engine:** The third-party `cvss` package, providing a specification-compliant implementation of the CVSS v4.0 scoring algorithm.

Score computation occurs **asynchronously and in real time**: every change to any metric selection triggers a `fetch` request to the `/calculate` endpoint, which returns the updated score, severity, and vector without requiring a full page reload or explicit form submission.

---

## Project Structure

```
.
├── app.py                 # Flask application: routing, i18n resolution, /calculate endpoint
├── p_cvss.py               # Metric definitions, vector assembly, severity classification
├── templates/
│   └── index.html          # Jinja2 template — UI, client-side logic, theming, i18n rendering
└── lang/
    ├── cs.json              # Czech translation dictionary
    └── en.json              # English translation dictionary
```

---

## Installation and Setup

### Prerequisites

- Python 3.9 or higher
- `pip` package manager

### Steps

```bash
# 1. Clone or download the project
git clone <repository-url>
cd physvuln-evaluator

# 2. (Recommended) Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate      # on Windows: venv\Scripts\activate

# 3. Install dependencies
pip install flask cvss

# 4. (Optional, recommended for production) Set a persistent secret key
export SECRET_KEY="your-own-random-secret-key"    # on Windows: set SECRET_KEY=...

# 5. Run the development server
python app.py
```

By default, the application is served at `http://127.0.0.1:5000/`.

> **Security note:** The `SECRET_KEY` used to sign the Flask session cookie has a hard-coded development fallback in `app.py`. This fallback **must** be overridden via the `SECRET_KEY` environment variable in any production or externally accessible deployment.

---

## Usage Guide

### Interface Overview

The application interface is fully responsive: on desktop viewports, the language switch, application title, and theme toggle are distributed horizontally across the header; on mobile viewports (≤768px), these elements are automatically restacked vertically and centered to preserve usability on constrained screens. A persistent language switch (`CZ` / `EN`) allows the assessor to change the interface language at any point; the selected language is retained for the duration of the browser session via server-side session state. A dark/light mode toggle, persisted in the browser's `localStorage`, allows the interface to be adapted to varying ambient lighting conditions typical of both field audits and monitoring-center environments.

### Conducting an Assessment

The assessment process consists of sixteen sequential steps, visually grouped according to the six metric categories described in [Metric Taxonomy](#metric-taxonomy). For each step, the assessor selects the single option that best corresponds to the actual state of the audited object or protective measure, using the provided button controls rather than free-text entry.

As each selection is made, the application immediately recalculates and displays:

1. **Score** — the numerical base score (0.0–10.0).
2. **Severity** — the corresponding qualitative rating (None / Low / Medium / High / Critical).
3. **Vector** — the complete, machine-readable CVSS-compatible string encoding all currently selected metric values.

This real-time feedback loop allows the assessor to perform interactive sensitivity analysis, exploring how the overall severity rating would change under alternative assumptions before finalizing the assessment.

### Exporting the Result

A single click on the copy icon within the results panel copies a formatted summary string — containing the severity, score, and vector — to the system clipboard, for direct insertion into a vulnerability register, audit report, or converged risk-management platform.

---

## API Reference

### `GET /`

Renders the main assessment interface. Resolves the active language (see [Internationalization](#internationalization-i18n)) and injects the translated metric definitions into the template.

### `POST /calculate`

Accepts the current set of metric selections and returns the computed score, severity, and vector.

**Request body:**

```json
{
  "selections": {
    "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
    "VC": "H", "VI": "H", "VA": "H",
    "SC": "H", "SI": "H", "SA": "H",
    "S": "P",
    "CR": "H", "IR": "H", "AR": "H",
    "E": "A"
  }
}
```

**Successful response (`200 OK`):**

```json
{
  "status": "success",
  "score": 9.3,
  "severity_key": "severity_critical",
  "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:P/CR:H/IR:H/AR:H/E:A"
}
```

**Error response (`400 Bad Request`):**

```json
{
  "status": "error",
  "message": "error_no_selections"
}
```

Error messages are returned as language-agnostic keys rather than localized text, consistent with the application's overall separation of computation logic from presentation.

---

## Internationalization (i18n)

The application implements a key-based internationalization scheme in which no user-facing text is hard-coded in either the backend (`p_cvss.py`, `app.py`) or the template's logic layer. Instead, all backend components operate exclusively on language-agnostic string keys (e.g., `metric_av_label`, `severity_high`, `error_no_selections`), which are resolved to human-readable text only at render time, via one of two JSON translation dictionaries (`lang/cs.json`, `lang/en.json`).

**Language resolution** (implemented in `zjisti_jazyk()` in `app.py`) follows this precedence:

1. An explicit `?lang=cs` or `?lang=en` URL query parameter, if present, is applied and persisted to the session.
2. Otherwise, the language previously stored in the session is used.
3. Otherwise, the application defaults to Czech (`cs`).

Both translation dictionaries are loaded once into memory at application startup and are made available to the template both server-side (as the Jinja2 variable `t`) and client-side (serialized into a JavaScript constant `T` for use in dynamically generated alerts and UI text).

---

## Limitations and Future Work

As an academic prototype, PhysVuln Evaluator is subject to several limitations that warrant disclosure:

- **Unofficial adaptation.** P-CVSS is an independent, unofficial adaptation of the CVSS v4.0 methodology. It is not endorsed, certified, or maintained by FIRST.org, and the redefinition of metric semantics for the physical domain has not undergone the same degree of multi-stakeholder consensus validation as the original CVSS specification.
- **Absence of empirical calibration.** The mapping between physical security conditions and individual metric values, as well as the severity thresholds themselves, are inherited directly from the CVSS v4.0 model without independent empirical validation against real-world physical incident data.
- **Session-based, non-persistent state.** The current implementation does not persist assessment results to a database; each evaluation exists only within the browser session unless manually exported via the copy function.
- **Single-user, non-collaborative design.** The tool does not currently support multi-assessor workflows, audit trails of who selected which values, or historical comparison between successive assessments of the same asset.

Potential directions for future development include persistent storage of assessment records, integration with existing GRC (Governance, Risk, and Compliance) platforms via a REST or webhook interface, extension of the environmental metric group to support asset-specific weighting profiles, and empirical validation of the physical metric definitions through structured expert elicitation.

---

## References

- FIRST.org, Inc. — *Common Vulnerability Scoring System version 4.0: Specification Document*. Forum of Incident Response and Security Teams.
- Python `cvss` package — CVSS vector parsing and score computation library.
- Flask — *The Python micro web framework*, Pallets Projects.

---

## License

This application is an independent adaptation inspired by the globally recognized CVSS (Common Vulnerability Scoring System) version 4.0 standard for assessing software vulnerabilities, maintained by FIRST (Forum of Incident Response and Security Teams). The CVSS acronym and standard are the intellectual property of FIRST. This web application for assessing physical security vulnerabilities in the context of converged vulnerability management is not created, maintained, supported, or officially endorsed by FIRST. This project is provided for academic and educational purposes. Refer to the  thesis, or institutional documentation for the applicable usage terms.