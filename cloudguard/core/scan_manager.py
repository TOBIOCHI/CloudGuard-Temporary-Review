
from datetime import datetime, timezone

from cloudguard.scanners.s3_scanner import S3Scanner
from cloudguard.scanners.iam_scanner import IAMScanner
from cloudguard.scanners.ec2_scanner import EC2Scanner
from cloudguard.scanners.ebs_scanner import EBSScanner
from cloudguard.scanners.rds_scanner import RDSScanner
from cloudguard.scanners.cloudtrail_scanner import CloudTrailScanner


class ScanManager:
    """
    Runs all CloudGuard scanners and combines their results.

    All scanners are read-only. This manager does not create,
    modify, or delete AWS resources.
    """

    def __init__(self):
        self.scanners = [
            ("S3", S3Scanner),
            ("IAM", IAMScanner),
            ("EC2", EC2Scanner),
            ("EBS", EBSScanner),
            ("RDS", RDSScanner),
            ("CloudTrail", CloudTrailScanner),
        ]

    def run_all(self):
        started_at = datetime.now(timezone.utc)

        service_results = {}
        all_findings = []
        all_errors = []

        for service_name, scanner_class in self.scanners:
            print(f"[CloudGuard] Scanning {service_name}...")

            try:
                scanner = scanner_class()
                result = scanner.scan()

                service_results[service_name] = result

                findings = result.get("findings", [])
                errors = result.get("errors", [])

                all_findings.extend(findings)

                for error in errors:
                    all_errors.append({
                        "service": service_name,
                        **error
                    })

                print(
                    f"[CloudGuard] {service_name}: "
                    f"{len(findings)} finding(s), "
                    f"{len(errors)} error(s)"
                )

            except Exception as error:
                error_result = {
                    "service": service_name,
                    "operation": "scanner_execution",
                    "message": str(error)
                }

                all_errors.append(error_result)

                service_results[service_name] = {
                    "service": service_name,
                    "findings": [],
                    "errors": [error_result]
                }

                print(
                    f"[CloudGuard] {service_name} failed: {error}"
                )

        completed_at = datetime.now(timezone.utc)

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }

        for finding in all_findings:
            severity = str(
                finding.get("severity", "INFO")
            ).upper()

            severity_counts[severity] = (
                severity_counts.get(severity, 0) + 1
            )

        return {
            "tool": "CloudGuard",
            "scan_started_at": started_at.isoformat(),
            "scan_completed_at": completed_at.isoformat(),
            "duration_seconds": round(
                (completed_at - started_at).total_seconds(),
                2
            ),
            "summary": {
                "total_scanners": len(self.scanners),
                "completed_scanners": len(service_results)
                    - sum(
                        1 for result in service_results.values()
                        if result.get("errors")
                        and result.get("errors")[0].get("operation")
                        == "scanner_execution"
                    ),
                "total_findings": len(all_findings),
                "total_errors": len(all_errors),
                "severity_counts": severity_counts
            },
            "services": service_results,
            "findings": all_findings,
            "errors": all_errors
        }
