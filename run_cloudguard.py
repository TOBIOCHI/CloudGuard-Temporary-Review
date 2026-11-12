
import json
from pathlib import Path

from cloudguard.core.scan_manager import ScanManager
from cloudguard.database.db_manager import DatabaseManager


PROJECT_ROOT = Path(__file__).resolve().parent

JSON_REPORT_PATH = PROJECT_ROOT / "cloudguard_scan_results.json"
DATABASE_PATH = PROJECT_ROOT / "data" / "cloudguard.db"


def main():
    print("\n========== CLOUDGUARD ==========")
    print("Starting AWS security assessment...\n")

    # Run all configured AWS security scanners.
    manager = ScanManager()
    results = manager.run_all()

    # Display scan summary.
    print("\n========== CLOUDGUARD SCAN SUMMARY ==========")
    print(json.dumps(results["summary"], indent=4))

    # Display complete scan results.
    print("\n========== COMPLETE SCAN RESULTS ==========")
    print(json.dumps(results, indent=4, default=str))

    # Save JSON report first so results remain available
    # even if SQLite persistence encounters an error.
    try:
        with open(JSON_REPORT_PATH, "w", encoding="utf-8") as report_file:
            json.dump(results, report_file, indent=4, default=str)

        print(f"\nJSON report saved to: {JSON_REPORT_PATH}")

    except OSError as error:
        print(f"\nWARNING: Could not save JSON report: {error}")

    # Save the same scan results to SQLite.
    try:
        db_manager = DatabaseManager()
        scan_id = db_manager.save_scan(results)

        print("\n========== DATABASE STORAGE ==========")
        print(f"Scan ID: {scan_id}")
        print(f"Database: {DATABASE_PATH}")
        print("Scan results successfully saved to SQLite.")

    except Exception as error:
        print("\nWARNING: Could not save scan to SQLite.")
        print(f"Database error: {error}")


if __name__ == "__main__":
    main()
