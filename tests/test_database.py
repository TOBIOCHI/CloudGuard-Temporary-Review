
import json

from cloudguard.database.db_manager import DatabaseManager


def sample_scan():
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
                "description": "Test description",
                "recommendation": "Enable MFA",
                "evidence": {
                    "registered_mfa_devices": 0
                }
            }
        ],
        "errors": []
    }


def test_initializes_database(tmp_path):
    db_path = tmp_path / "test.db"

    DatabaseManager(db_path=db_path)

    assert db_path.exists()


def test_saves_scan_and_returns_id(tmp_path):
    manager = DatabaseManager(
        db_path=tmp_path / "test.db"
    )

    scan_id = manager.save_scan(sample_scan())

    assert scan_id == 1


def test_retrieves_scan_history(tmp_path):
    manager = DatabaseManager(
        db_path=tmp_path / "test.db"
    )

    manager.save_scan(sample_scan())

    history = manager.get_scan_history()

    assert len(history) == 1
    assert history[0]["total_findings"] == 1


def test_retrieves_scan_details(tmp_path):
    manager = DatabaseManager(
        db_path=tmp_path / "test.db"
    )

    scan_id = manager.save_scan(sample_scan())

    details = manager.get_scan_details(scan_id)

    assert details is not None
    assert len(details["services"]) == 1
    assert len(details["findings"]) == 1
    assert details["findings"][0]["check_name"] == (
        "IAM_USER_WITHOUT_MFA"
    )


def test_filters_findings_by_severity(tmp_path):
    manager = DatabaseManager(
        db_path=tmp_path / "test.db"
    )

    scan_id = manager.save_scan(sample_scan())

    findings = manager.get_findings(
        scan_id=scan_id,
        severity="medium"
    )

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_missing_scan_returns_none(tmp_path):
    manager = DatabaseManager(
        db_path=tmp_path / "test.db"
    )

    assert manager.get_scan_details(999) is None
