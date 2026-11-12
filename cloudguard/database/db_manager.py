
import json
import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "cloudguard.db"


class DatabaseManager:
    """Stores CloudGuard scan results in a local SQLite database."""

    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize_database()

    def get_connection(self):
        """Create a database connection with dictionary-like rows."""
        connection = sqlite3.connect(str(self.db_path))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _json(value):
        return json.dumps(value if value is not None else {}, default=str)

    @staticmethod
    def _decode(value, default=None):
        if value is None:
            return default
        try:
            return json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return default

    def initialize_database(self):
        """Create database tables and indexes."""
        connection = self.get_connection()

        try:
            with connection:
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_started_at TEXT,
                        scan_completed_at TEXT,
                        duration_seconds REAL DEFAULT 0,
                        total_scanners INTEGER DEFAULT 0,
                        completed_scanners INTEGER DEFAULT 0,
                        total_findings INTEGER DEFAULT 0,
                        total_errors INTEGER DEFAULT 0,
                        severity_counts TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE TABLE IF NOT EXISTS service_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        service TEXT NOT NULL,
                        result_json TEXT NOT NULL,
                        FOREIGN KEY (scan_id)
                            REFERENCES scans(id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        service TEXT,
                        resource TEXT,
                        check_name TEXT,
                        severity TEXT,
                        title TEXT,
                        description TEXT,
                        recommendation TEXT,
                        evidence TEXT,
                        FOREIGN KEY (scan_id)
                            REFERENCES scans(id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS scan_errors (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        service TEXT,
                        operation TEXT,
                        error TEXT,
                        FOREIGN KEY (scan_id)
                            REFERENCES scans(id) ON DELETE CASCADE
                    );

                    CREATE INDEX IF NOT EXISTS idx_findings_scan_id
                    ON findings(scan_id);

                    CREATE INDEX IF NOT EXISTS idx_findings_severity
                    ON findings(severity);

                    CREATE INDEX IF NOT EXISTS idx_scans_completed_at
                    ON scans(scan_completed_at);
                """)
        finally:
            connection.close()

    def save_scan(self, results):
        """Save a complete scan and return its database ID."""
        summary = results.get("summary", {})
        connection = self.get_connection()

        try:
            with connection:
                cursor = connection.execute("""
                    INSERT INTO scans (
                        scan_started_at,
                        scan_completed_at,
                        duration_seconds,
                        total_scanners,
                        completed_scanners,
                        total_findings,
                        total_errors,
                        severity_counts
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    results.get("scan_started_at"),
                    results.get("scan_completed_at"),
                    results.get("duration_seconds", 0),
                    summary.get("total_scanners", 0),
                    summary.get("completed_scanners", 0),
                    summary.get(
                        "total_findings",
                        len(results.get("findings", []))
                    ),
                    summary.get(
                        "total_errors",
                        len(results.get("errors", []))
                    ),
                    self._json(summary.get("severity_counts", {}))
                ))

                scan_id = cursor.lastrowid

                for service, service_result in results.get(
                    "services", {}
                ).items():
                    connection.execute("""
                        INSERT INTO service_results (
                            scan_id, service, result_json
                        )
                        VALUES (?, ?, ?)
                    """, (
                        scan_id,
                        service,
                        self._json(service_result)
                    ))

                for finding in results.get("findings", []):
                    connection.execute("""
                        INSERT INTO findings (
                            scan_id,
                            service,
                            resource,
                            check_name,
                            severity,
                            title,
                            description,
                            recommendation,
                            evidence
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        finding.get("service"),
                        finding.get("resource"),
                        finding.get("check_name") or finding.get("check"),
                        finding.get("severity"),
                        finding.get("title"),
                        finding.get("description"),
                        finding.get("recommendation"),
                        self._json(finding.get("evidence", {}))
                    ))

                for error in results.get("errors", []):
                    connection.execute("""
                        INSERT INTO scan_errors (
                            scan_id, service, operation, error
                        )
                        VALUES (?, ?, ?, ?)
                    """, (
                        scan_id,
                        error.get("service"),
                        error.get("operation"),
                        error.get(
                            "error",
                            error.get("message", str(error))
                        )
                    ))

            return scan_id

        finally:
            connection.close()

    def get_scan_history(self, limit=50):
        """Return recent scans, newest first."""
        connection = self.get_connection()

        try:
            rows = connection.execute("""
                SELECT *
                FROM scans
                ORDER BY id DESC
                LIMIT ?
            """, (max(1, int(limit)),)).fetchall()

            history = []

            for row in rows:
                item = dict(row)
                item["severity_counts"] = self._decode(
                    item.get("severity_counts"), {}
                )
                history.append(item)

            return history

        finally:
            connection.close()

    def get_scan_details(self, scan_id):
        """Return scan details, services, findings and errors."""
        connection = self.get_connection()

        try:
            scan_row = connection.execute("""
                SELECT *
                FROM scans
                WHERE id = ?
            """, (scan_id,)).fetchone()

            if scan_row is None:
                return None

            scan = dict(scan_row)
            scan["severity_counts"] = self._decode(
                scan.get("severity_counts"), {}
            )

            service_rows = connection.execute("""
                SELECT service, result_json
                FROM service_results
                WHERE scan_id = ?
                ORDER BY service
            """, (scan_id,)).fetchall()

            services = {
                row["service"]: self._decode(row["result_json"], {})
                for row in service_rows
            }

            finding_rows = connection.execute("""
                SELECT *
                FROM findings
                WHERE scan_id = ?
                ORDER BY id
            """, (scan_id,)).fetchall()

            findings = []

            for row in finding_rows:
                finding = dict(row)
                finding["evidence"] = self._decode(
                    finding.get("evidence"), {}
                )
                findings.append(finding)

            error_rows = connection.execute("""
                SELECT *
                FROM scan_errors
                WHERE scan_id = ?
                ORDER BY id
            """, (scan_id,)).fetchall()

            errors = [dict(row) for row in error_rows]

            return {
                "scan": scan,
                "services": services,
                "findings": findings,
                "errors": errors
            }

        finally:
            connection.close()

    def get_findings(self, scan_id=None, severity=None):
        """Retrieve findings with optional scan and severity filters."""
        connection = self.get_connection()

        try:
            query = "SELECT * FROM findings WHERE 1=1"
            parameters = []

            if scan_id is not None:
                query += " AND scan_id = ?"
                parameters.append(scan_id)

            if severity:
                query += " AND UPPER(severity) = UPPER(?)"
                parameters.append(severity)

            query += " ORDER BY id DESC"

            rows = connection.execute(query, parameters).fetchall()
            findings = []

            for row in rows:
                finding = dict(row)
                finding["evidence"] = self._decode(
                    finding.get("evidence"), {}
                )
                findings.append(finding)

            return findings

        finally:
            connection.close()
