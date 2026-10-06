# 🛡️ ThreatShield Intelligence Aggregator

## Cyber Threat Intelligence, IOC Aggregation & Correlation Platform

ThreatShield Intelligence Aggregator is a **Django-based Cyber Threat Intelligence (CTI) platform** designed to collect, normalize, store, analyze, and correlate **Indicators of Compromise (IOCs)** from external threat intelligence sources.

The platform provides a centralized dashboard where security analysts can manage threat intelligence feeds, process IOC data, identify repeated indicators across multiple sources, synchronize vulnerability intelligence, and review security-related activity.

---

# 🔎 Project Overview

ThreatShield is a centralized **Cyber Threat Intelligence Aggregation and Correlation Platform**.

Security teams receive threat intelligence from many different sources. These sources may contain:

* Malicious IP addresses
* Malicious domains
* Suspicious URLs
* File hashes
* Email indicators
* Other indicators associated with malicious activity

Handling these feeds manually can be difficult.

ThreatShield provides a centralized system that can:

1. Register threat intelligence feeds.
2. Retrieve feed data.
3. Parse different feed formats.
4. Detect IOC types.
5. Normalize IOC values.
6. Store indicators in a database.
7. Link indicators to their sources.
8. Identify indicators appearing in multiple feeds.
9. Calculate and maintain threat-related metadata.
10. Display intelligence through a security dashboard.
11. Synchronize CISA Known Exploited Vulnerabilities.
12. Maintain activity logs for important system operations.

---

# 🎯 Why This Project Was Developed

Traditional threat intelligence collection can become fragmented when analysts manually check multiple websites, files, and feeds.

ThreatShield was developed to provide a **single centralized location** for collecting and analyzing threat intelligence.

Instead of:

```text
Feed 1 → Manual checking
Feed 2 → Manual checking
Feed 3 → Manual checking
CISA  → Manual checking
        ↓
     Analyst
```

ThreatShield provides:

```text
       Threat Intelligence Sources
          ↓       ↓       ↓
       Feed 1   Feed 2   Feed 3
          \       |       /
           \      |      /
            ↓     ↓     ↓
       ThreatShield
            ↓
       Feed Parser
            ↓
       IOC Detection
            ↓
       IOC Database
            ↓
    Correlation Engine
            ↓
        Dashboard
            ↓
      Security Analyst
```



# 🏗️ System Architecture

```text
                    ┌─────────────────────────┐
                    │ External CTI Sources    │
                    │                         │
                    │ TXT / CSV / JSON / STIX│
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │    Feed Management      │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      Feed Fetcher       │
                    │                         │
                    │ URL validation          │
                    │ HTTPS/HTTP retrieval    │
                    │ Size validation         │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      Feed Parser        │
                    │                         │
                    │ TXT / CSV / JSON        │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      IOC Detection      │
                    │                         │
                    │ IPv4 / IPv6             │
                    │ Domain / URL            │
                    │ MD5 / SHA1 / SHA256     │
                    │ Email                   │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      IOC Database       │
                    └────────────┬────────────┘
                                 │
                       ┌─────────┴─────────┐
                       ▼                   ▼
             ┌─────────────────┐  ┌──────────────────┐
             │ IOC Correlation │  │ CISA KEV Catalog │
             └────────┬────────┘  └────────┬─────────┘
                      │                    │
                      └─────────┬──────────┘
                                ▼
                    ┌─────────────────────────┐
                    │ Security Dashboard      │
                    │                         │
                    │ Feeds                   │
                    │ IOCs                    │
                    │ Correlation              │
                    │ Vulnerabilities         │
                    │ Activity Logs           │
                    │ Reports                 │
                    └─────────────────────────┘
```

---


# 🔢 Supported IOC Types

ThreatShield currently supports the following IOC types:

| IOC Type | Description          |
| -------- | -------------------- |
| IPv4     | IPv4 network address |
| IPv6     | IPv6 network address |
| Domain   | Domain name          |
| URL      | Web URL              |
| MD5      | MD5 file hash        |
| SHA1     | SHA-1 file hash      |
| SHA256   | SHA-256 file hash    |
| Email    | Email address        |

The system detects the IOC type automatically when the feed does not explicitly provide the type.

---


# ⚠️ Severity and Risk Information

IOC records contain metadata such as:

* Severity
* Risk score
* Status
* First seen
* Last seen

The current prototype uses rule-based/default classification for imported IOC data.

Typical severity levels include:

```text
Low
Medium
High
Critical
```

The severity model is intended to help analysts prioritize investigation.

---



# 🗂️ Project Structure

The main project follows a Django application structure.

```text
stitch_threatshield_intelligence_aggregator/
│
├── manage.py
│
├── aggregator/
│   │
│   ├── models.py
│   ├── forms.py
│   ├── views.py
│   ├── urls.py
│   ├── admin.py
│   │
│   ├── services/
│   │   ├── feed_fetcher.py
│   │   └── feed_parser.py
│   │
│   ├── management/
│   │   └── commands/
│   │       └── process_active_feed.py
│   │
│   ├── migrations/
│   │
│   └── templates/
│
├── static/
│
├── templates/
│
├── requirements.txt
│
├── .gitignore
│
├── .env.example
│
└── README.md
```

---

# 🧠 Important Backend Components

## `aggregator/models.py`

Defines the primary database models.

Important models include:

### Feed

Stores threat intelligence feed information.

### IOC

Stores normalized indicators.

### IOCSource

Connects IOCs to their source feeds.

### CorrelationResult

Stores correlation-related information.

### Vulnerability

Stores CISA KEV vulnerability information.

### ActivityLog

Stores important system activity.

---

## `aggregator/forms.py`

Contains forms used by the web interface.

The `FeedForm` handles:

* Feed name
* Source
* Feed type
* Category
* Description
* URL
* File upload

---

## `aggregator/services/feed_fetcher.py`

Responsible for secure retrieval of remote feeds.

Responsibilities include:

* URL validation
* HTTP/HTTPS validation
* Private/local destination protection
* Redirect handling
* Response validation
* Maximum feed size validation
* Empty response validation

---

## `aggregator/services/feed_parser.py`

Responsible for parsing feed content.

Supported:

```text
TXT
CSV
JSON
STIX-style JSON
```

It also performs IOC type detection and normalization.

---

## `aggregator/management/commands/process_active_feed.py`

This Django management command processes active remote feeds.

The workflow is:

```text
Find active URL feeds
       ↓
Fetch each feed
       ↓
Parse feed
       ↓
Process IOC records
       ↓
Update database
       ↓
Run correlation
```

---

# 💻 Technology Stack

## Backend

* Python
* Django

## Database

* SQLite for development/prototype use

## Frontend

* HTML
* CSS
* JavaScript
* Django Templates

## Threat Intelligence

* External IOC feeds
* CISA KEV

## Data Formats

* TXT
* CSV
* JSON
* STIX-style JSON

---

# 🛠️ Installation

## 1. Clone the repository

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
```

Example:

```bash
git clone https://github.com/YOUR_USERNAME/ThreatShield-Intelligence-Aggregator.git
```

Enter the project:

```bash
cd ThreatShield-Intelligence-Aggregator
```

---

# 🐍 2. Create Virtual Environment

Windows:

```powershell
python -m venv venv
```

Activate:

```powershell
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution, use the appropriate local PowerShell execution-policy configuration for your development environment.

---

# 📦 3. Install Dependencies

```powershell
pip install -r requirements.txt
```

---

# 🔍 4. Check Django Configuration

```powershell
python manage.py check
```

The command should complete without critical configuration errors.

---

# 🗄️ Database Setup

Apply migrations:

```powershell
python manage.py migrate
```

If model changes need migrations:

```powershell
python manage.py makemigrations
python manage.py migrate
```

---

# 👤 Create Administrator

```powershell
python manage.py createsuperuser
```

Enter:

```text
Username
Email
Password
```

---

# ▶️ Running the Project

Start the Django development server:

```powershell
python manage.py runserver 127.0.0.1:5000
```

Open:

```text
http://127.0.0.1:5000/
```

---


# 🔐 Security Considerations

Security is an important part of a threat intelligence platform.

The project includes protections around remote feed retrieval.

The feed fetcher:

* Accepts HTTP/HTTPS URLs.
* Validates destination addresses.
* Blocks unsafe local/private destinations.
* Does not automatically follow redirects.
* Limits maximum response size.
* Rejects empty feed responses.

---

# 🔑 Secrets and Credentials

Never commit sensitive values to GitHub.

Do not upload:

```text
.env
API keys
Passwords
SMTP passwords
Database credentials
Private tokens
Authentication secrets
```

Use environment variables instead.

Example:

```env
SECRET_KEY=your-secret-key
DEBUG=True

OPENAI_API_KEY=your-api-key

EMAIL_HOST_USER=your-email
EMAIL_HOST_PASSWORD=your-password
```

Only placeholder values should be included in `.env.example`.

---

# 🚫 Files That Should Not Be Uploaded

The following should normally be excluded using `.gitignore`:

```text
venv/
.env
db.sqlite3
__pycache__/
*.pyc
staticfiles/
media/
```

---

# 🧪 Basic Testing

Run Django checks:

```powershell
python manage.py check
```

Check migrations:

```powershell
python manage.py makemigrations --check
```

Compile Python code:

```powershell
python -m compileall .
```

Run the server:

```powershell
python manage.py runserver 127.0.0.1:5000
```

Process feeds:

```powershell
python manage.py process_active_feed
```



# 🔄 Complete Project Workflow

The complete ThreatShield workflow can be represented as:

```text
                  ┌──────────────────┐
                  │ Threat Sources   │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Feed Management  │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Feed Fetcher     │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Feed Parser      │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ IOC Detection    │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Normalization    │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ IOC Database     │
                  └────────┬─────────┘
                           │
                  ┌────────┴─────────┐
                  ▼                  ▼
          ┌───────────────┐   ┌──────────────┐
          │ IOC Correlation│   │ CISA KEV     │
          └───────┬───────┘   └──────┬───────┘
                  │                  │
                  └────────┬─────────┘
                           ▼
                  ┌──────────────────┐
                  │ Threat Dashboard │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Security Analyst │
                  └──────────────────┘


# ⚠️ Disclaimer

This project is intended for:

* Educational purposes
* Cybersecurity research
* Controlled laboratory environments
* Threat intelligence analysis
* Defensive security operations

The platform should not be used to perform unauthorized access, attack systems, or conduct malicious activity.

Threat intelligence indicators should be treated as security data and should be validated before being used for blocking or automated response.

---

