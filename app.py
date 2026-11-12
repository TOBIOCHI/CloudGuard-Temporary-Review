import os
import secrets

from dotenv import load_dotenv

from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    abort,
    send_file
)

from cloudguard.database.db_manager import DatabaseManager
from cloudguard.core.scan_manager import ScanManager
from cloudguard.reports.pdf_generator import PDFReportGenerator


# --------------------------------------------------
# PROJECT CONFIGURATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "templates"),
    static_folder=str(PROJECT_ROOT / "static")
)

app.secret_key = (
    os.getenv("FLASK_SECRET_KEY")
    or secrets.token_hex(32)
)

database = DatabaseManager()


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/")
def index():
    """Display the latest scan and dashboard overview."""

    scan_history = database.get_scan_history(limit=20)

    latest_scan = scan_history[0] if scan_history else None

    latest_details = None
    findings = []
    services = {}

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    if latest_scan:

        latest_details = database.get_scan_details(
            latest_scan["id"]
        )

        if latest_details:
            findings = latest_details.get("findings", [])
            services = latest_details.get("services", {})

        severity_counts.update(
            latest_scan.get("severity_counts", {})
        )

    # --------------------------------------------------
    # OPTIONAL FINDING FILTERS
    # --------------------------------------------------

    selected_severity = request.args.get(
        "severity", ""
    ).upper()

    selected_service = request.args.get(
        "service", ""
    ).upper()

    if selected_severity in severity_counts:

        findings = [
            finding for finding in findings
            if finding.get("severity", "").upper()
            == selected_severity
        ]

    else:
        selected_severity = ""

    if selected_service:

        findings = [
            finding for finding in findings
            if finding.get("service", "").upper()
            == selected_service
        ]

    # --------------------------------------------------
    # RENDER DASHBOARD
    # --------------------------------------------------

    return render_template(
        "index.html",
        latest_scan=latest_scan,
        latest_details=latest_details,
        scan_history=scan_history,
        findings=findings,
        services=services,
        severity_counts=severity_counts,
        selected_severity=selected_severity,
        selected_service=selected_service
    )


# --------------------------------------------------
# INDIVIDUAL SCAN DETAILS
# --------------------------------------------------

@app.route("/scans/<int:scan_id>")
def scan_details(scan_id):
    """Display the complete details of one saved scan."""

    details = database.get_scan_details(scan_id)

    if details is None:
        abort(404)

    return render_template(
        "scan_details.html",
        details=details,
        scan=details["scan"]
    )


# --------------------------------------------------
# DOWNLOAD PDF REPORT
# --------------------------------------------------

@app.route("/scans/<int:scan_id>/report")
def download_scan_report(scan_id):
    """Generate and download a PDF for a saved scan."""

    details = database.get_scan_details(scan_id)

    if details is None:
        abort(404)

    scan = details["scan"]

    # Reconstruct the structure expected by PDFReportGenerator.
    results = {
        "tool": "CloudGuard",
        "scan_started_at": scan.get("scan_started_at"),
        "scan_completed_at": scan.get("scan_completed_at"),
        "duration_seconds": scan.get("duration_seconds", 0),

        "summary": {
            "total_scanners": scan.get("total_scanners", 0),
            "completed_scanners": scan.get("completed_scanners", 0),
            "total_findings": scan.get("total_findings", 0),
            "total_errors": scan.get("total_errors", 0),
            "severity_counts": scan.get("severity_counts", {})
        },

        "services": details.get("services", {}),
        "findings": details.get("findings", []),
        "errors": details.get("errors", [])
    }

    try:

        generator = PDFReportGenerator()

        report_path = generator.generate_report(
            results,
            scan_id=scan_id
        )

        report_path = Path(report_path)

        if not report_path.is_file():
            raise FileNotFoundError(
                "The PDF generator did not create the report file."
            )

        return send_file(
            report_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=report_path.name
        )

    except Exception:

        app.logger.exception(
            "Failed to generate PDF report for scan %s",
            scan_id
        )

        flash(
            "The PDF report could not be generated. "
            "Check the application console for details.",
            "danger"
        )

        return redirect(
            url_for("scan_details", scan_id=scan_id)
        )


# --------------------------------------------------
# RUN NEW AWS SCAN
# --------------------------------------------------

@app.route("/run-scan", methods=["POST"])
def run_scan():
    """Run all read-only AWS scanners and save results."""

    try:

        manager = ScanManager()

        results = manager.run_all()

        scan_id = database.save_scan(results)

        flash(
            f"Scan #{scan_id} completed and saved successfully.",
            "success"
        )

    except Exception as error:

        app.logger.exception(
            "CloudGuard scan failed"
        )

        flash(
            f"Scan failed: {error}",
            "danger"
        )

    return redirect(url_for("index"))


# --------------------------------------------------
# APPLICATION HEALTH CHECK
# --------------------------------------------------

@app.route("/health")
def health():
    """Check whether the application and database are available."""

    try:

        history = database.get_scan_history(limit=1)

        return {
            "application": "CloudGuard",
            "status": "running",
            "database": "connected",
            "saved_scans": len(history)
        }

    except Exception:

        app.logger.exception(
            "Database health check failed"
        )

        return {
            "application": "CloudGuard",
            "status": "error",
            "database": "disconnected"
        }, 500


# --------------------------------------------------
# 404 ERROR HANDLER
# --------------------------------------------------

@app.errorhandler(404)
def not_found(error):

    return render_template("404.html"), 404


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    print("\n========== CLOUDGUARD DASHBOARD ==========")

    print("Dashboard: http://127.0.0.1:5000")

    print("Press CTRL+C to stop the server.\n")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
