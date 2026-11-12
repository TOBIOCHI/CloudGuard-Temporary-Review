
# CloudGuard
### Cloud Misconfiguration Detection Tool

CloudGuard is a Python-based AWS cloud security auditing tool designed to identify common cloud configuration weaknesses through read-only AWS API calls.

It provides modular security scanners, risk classification, SQLite result storage, a Flask web dashboard and downloadable PDF reports.

## 1. Features

CloudGuard currently includes six AWS security scanners:

| AWS Service | Security Checks |
|---|---|
| Amazon S3 | Public bucket policies, public ACLs and Block Public Access configuration |
| AWS IAM | Users without MFA and potentially over-permissive policies |
| Amazon EC2 | Security groups exposing SSH, RDP and other unrestricted inbound traffic |
| Amazon EBS | Unencrypted EBS volumes |
| Amazon RDS | Publicly accessible database configuration |
| AWS CloudTrail | Trail existence, logging status, multi-region configuration and log-file validation |

Other features:

- Sequential execution of security scanners.
- Severity classification: CRITICAL, HIGH, MEDIUM, LOW and INFO.
- SQLite database for scan history and findings.
- Flask web dashboard.
- Individual scan details pages.
- PDF security assessment reports.
- Application health endpoint.
- Automated tests using pytest.

CloudGuard is designed for detection and reporting. It does not automatically modify AWS resources or perform remediation.

## 2. Technology Stack

- Python
- Boto3
- AWS CLI
- Flask
- SQLite
- ReportLab
- HTML, CSS, JavaScript and Bootstrap
- pytest

## 3. Project Structure

```text
CloudGuard/
│
├── app.py
├── config.py
├── run_cloudguard.py
├── run_s3_scan.py
├── test_aws.py
├── test_permissions.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
│
├── cloudguard/
│   ├── run_s3_scan.py
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   └── scan_manager.py
│   │
│   ├── database/
│   │   ├── __init__.py
│   │   └── db_manager.py
│   │
│   ├── reports/
│   │   ├── __init__.py
│   │   └── pdf_generator.py
│   │
│   └── scanners/
│       ├── __init__.py
│       ├── s3_scanner.py
│       ├── iam_scanner.py
│       ├── ec2_scanner.py
│       ├── ebs_scanner.py
│       ├── rds_scanner.py
│       ├── cloudtrail_scanner.py
│       └── iam_scanner_backup.py
│
├── data/
│   ├── cloudguard.db
│   └── reports/
│       └── (generated PDF reports)
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── dashboard.js
│
├── templates/
│   ├── 404.html
│   ├── base.html
│   ├── index.html
│   └── scan_details.html
│
└── tests/
    ├── test_app.py
    ├── test_database.py
    ├── test_s3_scanner.py
    ├── test_iam_scanner.py
    ├── test_ec2_scanner.py
    ├── test_ebs_scanner.py
    ├── test_rds_scanner.py
    └── test_cloudtrail_scanner.py
```

**Note:** The project tree shows the expected local database and report-output locations. These are generated runtime files and should not be committed to source control. The IAM backup is retained for reference and is not an active scanner.

## 4. Requirements

- Python 3
- pip
- AWS CLI v2
- An AWS account with permission to perform read-only security audits.

The project was tested using Python 3.14.

## 5. Installation

Clone or download the project and open PowerShell in the project directory.

Create a virtual environment:

```powershell
py -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
```

## 6. Environment Configuration

Create a private environment file:

```powershell
Copy-Item .env.example .env
```

Generate a secure Flask secret:

```powershell
py -c "import secrets; print(secrets.token_hex(32))"
```

Open `.env` and set:

```text
FLASK_SECRET_KEY=your_generated_secret_key
```

Keep `.env` private. Never upload it to GitHub or share its contents.

## 7. AWS Configuration

Install AWS CLI v2 and configure a dedicated IAM audit profile.

The recommended setup uses an IAM identity with the AWS-managed `SecurityAudit` policy, subject to the permissions required by the scanners.

Configure the profile:

```powershell
aws configure --profile cloudguard-audit
```

Enter the access key, secret key, default region and output format locally when prompted.

The tested region is:

```text
eu-north-1
```

Verify the AWS identity:

```powershell
aws sts get-caller-identity --profile cloudguard-audit
```

Never use root account credentials for routine scanning. Do not commit AWS credentials, access-key CSV files or private environment files.

## 8. Running CloudGuard

Run the complete AWS scan:

```powershell
py run_cloudguard.py
```

The program runs the six scanners, gathers findings, calculates severity summaries and saves the results.

Scan results are stored locally in:

```text
cloudguard_scan_results.json
data/cloudguard.db
```

The JSON report and SQLite database are local generated data and are excluded from version control by `.gitignore`.

## 9. Running the Web Dashboard

Start the Flask application:

```powershell
py app.py
```

Open:

```text
http://127.0.0.1:5000
```

The dashboard provides access to:

- Latest scan overview.
- Severity summaries.
- AWS service results.
- Security findings.
- Scan history.
- Individual scan details.
- PDF report downloads.

Health endpoint:

```text
http://127.0.0.1:5000/health
```

Stop the application with `CTRL+C`.

## 10. Running Automated Tests

Run all tests:

```powershell
py -m pytest -v
```

The current test suite contains 45 passing tests covering:

- Six AWS scanner modules.
- Scanner pagination and detection logic.
- SQLite database operations.
- Flask dashboard routes.
- Scan details and missing scan handling.
- PDF download responses.
- Application health endpoint.

The tests use simulated AWS responses and temporary databases where appropriate. They do not require a live AWS scan.

## 11. Risk Severity

CloudGuard uses five severity categories:

| Severity | Meaning |
|---|---|
| CRITICAL | A potentially severe security exposure |
| HIGH | A significant security weakness |
| MEDIUM | A configuration weakness requiring attention |
| LOW | A lower-impact security improvement |
| INFO | Informational observation |

Severity indicates the scanner's assessment of a detected configuration. It is not a guarantee of exploitability or actual compromise.

## 12. Security and Technical Limitations

CloudGuard is a prototype security auditing tool. Its results should be reviewed and validated before operational decisions are made.

Important limitations:

- IAM policy analysis uses simplified wildcard and administrator-policy checks. It is not a complete AWS effective-permissions evaluator.
- IAM users without MFA may be programmatic identities that do not use console sign-in.
- EC2 security-group rules alone do not prove that a resource is reachable from the internet.
- An RDS `PubliclyAccessible` setting does not independently prove internet reachability.
- EBS checks currently focus on encryption status of existing volumes.
- CloudTrail findings are based on the trails returned in the selected region. They do not establish that AWS Event History is unavailable.
- Some AWS resources and services are region-specific.
- A scan with zero findings does not prove that an AWS account is completely secure.
- CloudGuard performs read-only checks and does not automatically remediate detected issues.

Always confirm the selected AWS account, region and IAM permissions before running a scan.

## 13. Project Status

Current implementation:

- Six modular AWS security scanners.
- Central scan manager.
- SQLite persistence.
- Flask dashboard.
- PDF report generation.
- Health monitoring endpoint.
- Environment-based Flask secret configuration.
- Automated test suite: 45 passing tests.

## 14. Disclaimer

CloudGuard is an educational and research-oriented cloud security auditing project.

Only scan AWS accounts and resources for which you have explicit authorization. The project is provided for security assessment, learning and demonstration purposes.
