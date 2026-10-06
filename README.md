# Threat Intelligence Aggregator (Non-AI)

A web-based cybersecurity threat intelligence aggregation, normalization, and Indicator of Compromise (IOC) correlation platform. Designed for high-stakes Security Operations Centers (SOC), this platform enables analysts to ingest local or remote intelligence feeds, detect and validate indicators, remove duplicates, compute deterministic risk scores, and compile blocklists or reports.

---

## 1. Project Description
The Threat Intelligence Aggregator is a rule-based, deterministic defense platform built using Django. It acts as a centralized repository for collecting cyber threat indicators, identifying feed intersections, calculating threat severity without using black-box machine learning models, and generating export lists for network protection systems.

## 2. Features
- **Feed Import Pipeline:** Standardized parsing of CSV, JSON (including STIX objects), and TXT formats. Handles remote URL feeds or manual file uploads.
- **Auto-Extraction & Validation:** Automatically identifies IPv4 addresses, domain names, URLs, file hashes (MD5, SHA-1, SHA-256), and email addresses using standard Python libraries.
- **Normalization Engine:** Canonicalizes strings (whitespace trimming, case normalization, URL scheme/host pruning) to match and aggregate duplicates.
- **Cross-Feed Correlation:** Tracks indicator overlaps across multiple discrete intel feeds to identify high-confidence threats.
- **Deterministic Risk Engine:** Purely rule-based scoring (0-100) and severity assignment (Low, Medium, High, Critical) based on configuration heuristics.
- **Blocklist Generator:** Targeted search and query utility exporting IP, domain, URL, or hash blocklists in CSV, JSON, or plain TXT format.
- **Operational Reports:** Compiles operational and executive threat statistics, top threats list, and export reviews.
- **Activity Logging:** Session login/logout tracking, feed configurations, rejections, processing history, and correlation actions recorded to the database.
- **Secure Authentication:** User registration, password hashing, and session management using Django's built-in authentication system.

---

## 3. Technology Stack
- **Backend Framework:** Python, Django, Django REST Framework
- **Data Manipulation:** pandas
- **HTTP client:** requests
- **Database Engine:** SQLite (configured for seamless migration to PostgreSQL)
- **Frontend Layer:** Tailwind CSS (Sentinel Modern Theme configuration), Google Fonts (Inter, JetBrains Mono), Material Symbols, Chart.js

---

## 4. Project Structure
```
stitch_threatshield_intelligence_aggregator/
│
├── manage.py
├── requirements.txt
├── README.md
│
├── threatintel/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   ├── wsgi.py
│   └── asgi.py
│
└── aggregator/
    ├── __init__.py
    ├── admin.py
    ├── apps.py
    ├── models.py
    ├── views.py
    ├── urls.py
    ├── serializers.py
    ├── forms.py
    ├── tests.py
    │
    ├── services/
    │   ├── __init__.py
    │   ├── validator.py
    │   ├── normalizer.py
    │   ├── ioc_parser.py
    │   ├── feed_parser.py
    │   ├── feed_fetcher.py
    │   ├── risk_engine.py
    │   ├── correlation.py
    │   ├── blocklist.py
    │   └── reporting.py
    │
    ├── templates/
    │   └── aggregator/
    │       ├── base.html
    │       ├── login.html
    │       ├── register.html
    │       ├── dashboard.html
    │       ├── feed_management.html
    │       ├── ioc_explorer.html
    │       ├── correlation.html
    │       ├── blocklists.html
    │       ├── reports.html
    │       └── activity_logs.html
    │
    └── management/
        ├── __init__.py
        └── commands/
            ├── __init__.py
            └── seed_demo_data.py
```

---

## 5. Installation & Setup

### Prerequisites
- Python 3.10 or higher
- pip (Python package installer)

### Step 1: Virtual Environment Setup
Clone the repository, open a terminal in the project directory, and initialize a virtual environment:
```bash
# Create virtual environment
python -m venv venv

# Activate on Windows (PowerShell/CMD)
.\venv\Scripts\activate

# Activate on Linux/Mac
source venv/bin/activate
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Database Migrations
Initialize the SQLite database schema:
```bash
python manage.py makemigrations aggregator
python manage.py migrate
```

### Step 4: Load Demo Data
Run the custom seed command to populate the database with 5 feeds, 55+ indicators, and activity logs:
```bash
python manage.py seed_demo_data
```
*Note: This command will print the created superuser credentials. Default Username: `analyst`, Password: `ThreatShield2026!`.*

### Step 5: Start Server
Launch the development server:
```bash
python manage.py runserver
```
Navigate to `http://127.0.0.1:8000/` in your web browser.

---

## 6. Algorithms & Processing Workflows

### A. IOC Ingestion Workflow
```
[Ingest Trigger (URL/Upload)]
             │
             ▼
      [Feed Parser] ──────────► [Validation Service]
             │                          │
             │ (Parsed Items)           ├─► (Invalid) ──► [Log Rejections]
             ▼                          │
    [Normalizer Service] ◄──────────────┴─► (Valid)
             │
             ▼
    [Deduplication check] ──► [Insert / Update IOC Source]
```

### B. Correlation Engine
For each active indicator:
1. Queries the `IOCSource` link records.
2. Counts the unique source feeds contributing the indicator.
3. Sums total occurrences.
4. Gathers threat categories associated with those feeds.
5. Invokes the Risk Scoring Engine to compute an updated risk score and severity value.
6. Saves updates and writes a `CorrelationResult` audit log.

### C. Risk Scoring Rules
Risk score is calculated deterministically on a scale of `0 - 100` using the following parameters:
- **Base Overlap Score:**
  - 1 feed = 20 points
  - 2 feeds = 40 points
  - 3 feeds = 60 points
  - 4 feeds = 80 points
  - 5+ feeds = 100 points
- **Modifiers:**
  - *Occurrences:* +2 points per occurrence (up to +15 pts).
  - *Specificity:* +5 points for highly specific types (Hashes, URLs, Emails); +2 points for IPs and Domains.
  - *Threat Categories:* +10 points if feed description/category contains critical terms (malware, phishing, botnet, ransomware).
  - *Recency:* +10 points if observed within the last 24 hours.
- **Score Cap:** Final score is capped at `100`.
- **Severity Mapping:**
  - `0 - 24`: Low
  - `25 - 49`: Medium
  - `50 - 74`: High
  - `75 - 100`: Critical

---

## 7. API Documentation

All API endpoints are protected and require session authentication.

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/feeds/` | `GET`, `POST` | List and register threat intelligence feeds. |
| `/api/iocs/` | `GET` | List unique active indicators. Supports query filtering: `?type=IPv4&severity=High&min_risk=50`. |
| `/api/iocs/{id}/` | `GET` | Retrieve detail metrics and full feed overlap mapping for a specific indicator. |
| `/api/correlation/` | `GET` | Retrieve calculated correlation result statistics. |
| `/api/correlation/run/` | `POST` | Execute a manual correlation scoring pass. |
| `/api/blocklists/generate/` | `POST` | Compile blocklist file contents. Parameters: `ioc_type`, `min_severity`, `min_risk_score`, `file_format`. |
| `/api/reports/` | `GET` | Retrieve compiled statistics report for the dashboard. |
| `/api/dashboard/stats/` | `GET` | Retrieve aggregated counters for SOC display panels. |

---

## 8. Testing
To run the automated tests verifying validators, normalizers, STIX parsers, and API responses:
```bash
python manage.py test
```

## 9. Security Considerations
- **No Upload Executions:** Uploaded files are decoded strictly as UTF-8 textual streams and parsed via `csv.reader` or `json.loads` within standard Python memory space. No subprocesses are executed.
- **CSRF Protection:** Integrated on all form templates to prevent cross-site request forgery.
- **Input Validation:** Strict validation of IP boundaries, domain string limits, and hex pattern sizes rejects raw injections.
- **ORM Boundaries:** All searches and filters utilize Django's DB ORM structure, preventing SQL injection vulnerabilities.

## 10. Future Enhancements
- Integration of Taxi/Stix client for remote STIX-over-TAXII server ingestion.
- Live webhook alerts for firewall rule automations.
- IPv6 detection support.

---

## 11. License
This project is licensed under the MIT License - see the LICENSE file for details.
