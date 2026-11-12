
import pytest

import app as app_module
from cloudguard.database.db_manager import DatabaseManager


def sample_scan():
    """Return a small simulated scan for application route tests."""

    return {
        "tool": "CloudGuard",
        "scan_started_at": "2026-11-11T10:00:00+00:00",
        "scan_completed_at": "2026-11-11T10:00:05+00:00",
        "duration_seconds": 5.0,
        "summary": {
            "total_scanners": 6,
            "completed_scanners": 6,
            "total_findings": 1,
            "total_errors": 0,
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 1,
                "LOW": 0,
                "INFO": 0
            }
        },
        "services": {
            "IAM": {
                "service": "IAM",
                "findings": [],
                "errors": []
            }
        },
        "findings": [
            {
                "service": "IAM",
                "resource": "test-user",
                "check": "IAM_USER_WITHOUT_MFA",
                "severity": "MEDIUM",
                "title": "IAM user has no MFA",
                "description": "Test finding for route testing.",
                "recommendation": "Enable MFA.",
                "evidence": {
                    "registered_mfa_devices": 0
                }
            }
        ],
        "errors": []
    }


@pytest.fixture
def test_client(tmp_path, monkeypatch):
    """Create a Flask test client using an isolated temporary database."""

    test_database = DatabaseManager(
        db_path=tmp_path / "cloudguard_test.db"
    )

    monkeypatch.setattr(
        app_module,
        "database",
        test_database
    )

    app_module.app.config.update(TESTING=True)

    client = app_module.app.test_client()

    return client, test_database


def test_dashboard_loads_without_scans(test_client):
    client, database = test_client

    response = client.get("/")

    assert response.status_code == 200


def test_dashboard_loads_with_saved_scan(test_client):
    client, database = test_client

    database.save_scan(sample_scan())

    response = client.get("/")

    assert response.status_code == 200


def test_scan_details_page_loads(test_client):
    client, database = test_client

    scan_id = database.save_scan(sample_scan())

    response = client.get(f"/scans/{scan_id}")

    assert response.status_code == 200


def test_missing_scan_pages_return_404(test_client):
    client, database = test_client

    details_response = client.get("/scans/999999")
    report_response = client.get("/scans/999999/report")

    assert details_response.status_code == 404
    assert report_response.status_code == 404


def test_pdf_report_download(test_client, tmp_path, monkeypatch):
    client, database = test_client

    scan_id = database.save_scan(sample_scan())

    class FakePDFReportGenerator:
        """Create a small test PDF without using the real report generator."""

        def generate_report(self, results, scan_id=None):
            assert results["tool"] == "CloudGuard"
            assert results["summary"]["total_findings"] == 1
            assert scan_id is not None

            report_path = tmp_path / "test_report.pdf"

            report_path.write_bytes(
                b"%PDF-1.4\n% CloudGuard test report\n%%EOF\n"
            )

            return report_path

    monkeypatch.setattr(
        app_module,
        "PDFReportGenerator",
        FakePDFReportGenerator
    )

    response = client.get(f"/scans/{scan_id}/report")

    assert response.status_code == 200
    assert response.content_type == "application/pdf"
    assert response.data.startswith(b"%PDF-1.4")
    assert "attachment" in response.headers.get(
        "Content-Disposition", ""
    )


def test_health_endpoint(test_client):
    client, database = test_client

    database.save_scan(sample_scan())

    response = client.get("/health")

    assert response.status_code == 200

    data = response.get_json()

    assert data["application"] == "CloudGuard"
    assert data["status"] == "running"
    assert data["database"] == "connected"
    assert data["saved_scans"] == 1
