# AlertANSSI - ANSSI Vulnerability Monitor


## Features

- **Automated Monitoring**: Fetches the latest alerts from the ANSSI RSS feed.
- **Data Enrichment**:
  - Retrieves **CVE** metadata from MITRE (description, CVSS score, affected versions).
  - Fetches **EPSS** scores to estimate exploitation probability.
- **Targeted Alerting**: Filters vulnerabilities based on user subscriptions (Vendor/Product).
- **Reporting**: Generates PDF reports and CSV exports of relevant vulnerabilities.
- **Notifications**: Sends daily email summaries with attached reports.

## Installation

### Prerequisites

- Python 3.12+
- `pip`

### Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Azelout/AlertANSSI.git
   cd AlertANSSI
   ```

2. **Install dependencies**:
   ```bash
   pip install .
   ```

## Configuration

The application requires two configuration files: `config.yaml` for general settings and `.env` for credentials.

### 1. General Configuration (`src/anssi_monitor/config/config.yaml`)

Create a `config.yaml` file in `src/anssi_monitor/config/`:

```yaml
load_csv: false          # Set to true to load existing DB.csv instead of fetching new data
debug: true              # Enable debug prints
multithread: true        # Enable multithreading for faster API requests

api:
  anssi: "https://www.cert.ssi.gouv.fr/feed/"
  epss: "https://api.first.org/data/v1/epss?cve="
  mitre: "https://cveawg.mitre.org/api/cve/"

mail:
  send_mail: true
  SMTP: "smtp.gmail.com" # If you use Gmail
  SMTP_PORT: 587
```

### 2. Credentials (`.env`)

Create a `.env` file in the project root to store email credentials:

```bash
MAIL_USER=your_email@example.com
MAIL_PASSWORD=your_app_password
```

### 3. User Subscriptions (`data/users.json`)

Define users and their subscriptions in `data/users.json`:

```json
{
    "users": [
        {
            "email": "user@example.com",
            "subscriptions": {
                "companies": ["Microsoft", "Adobe"],
                "products": ["Chrome", "Apache HTTP Server"]
            }
        }
    ]
}
```

## Usage

Run the main script to start the scan and alerting process:

```bash
python main.py
```

The script will:
1. Fetch latest alerts from ANSSI.
2. Enrich them with CVE/EPSS data.
3. Match against `data/users.json`.
4. Generate PDF/CSV reports in the current directory (temp).
5. Send emails to affected users.
