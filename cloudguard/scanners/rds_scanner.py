
"""
CloudGuard - RDS Security Scanner

Read-only checks:
1. Detect RDS instances configured for public accessibility.
2. Record database configuration as evidence.
3. Retrieve all DB instances using RDS Marker pagination.

Important:
PubliclyAccessible=True does not prove that a database
is reachable from the internet. Network security groups,
subnet routing, and other controls must also be reviewed.

No database settings are modified.
"""

import boto3

from botocore.exceptions import ClientError


class RDSScanner:

    def __init__(self, session=None):

        self.session = session or boto3.Session(
            profile_name="cloudguard-audit",
            region_name="eu-north-1"
        )

        self.rds = self.session.client("rds")

        self.findings = []
        self.errors = []

    @staticmethod
    def error_code(error):
        return error.response.get("Error", {}).get(
            "Code", "UnknownError"
        )

    def add_finding(self, instance):

        security_groups = [
            group.get("VpcSecurityGroupId")
            for group in instance.get("VpcSecurityGroups", [])
        ]

        self.findings.append({
            "service": "RDS",
            "resource": instance.get(
                "DBInstanceIdentifier", "Unknown"
            ),
            "check": "RDS_PUBLICLY_ACCESSIBLE",
            "severity": "MEDIUM",
            "title": "RDS instance configured for public accessibility",
            "description": (
                "This RDS instance has PubliclyAccessible set to True. "
                "This indicates that AWS may assign it a public address, "
                "but does not by itself prove internet reachability. "
                "Network controls must also be examined."
            ),
            "recommendation": (
                "Confirm whether public accessibility is required. "
                "Prefer private database access where possible. "
                "Review attached security groups, inbound rules, "
                "subnet routing, and database access requirements."
            ),
            "evidence": {
                "db_instance_identifier": instance.get(
                    "DBInstanceIdentifier"
                ),
                "engine": instance.get("Engine"),
                "engine_version": instance.get("EngineVersion"),
                "publicly_accessible": instance.get(
                    "PubliclyAccessible"
                ),
                "endpoint": instance.get("Endpoint", {}).get(
                    "Address"
                ),
                "port": instance.get("Endpoint", {}).get("Port"),
                "vpc_id": instance.get("DBSubnetGroup", {}).get(
                    "VpcId"
                ),
                "security_groups": security_groups,
                "status": instance.get("DBInstanceStatus")
            }
        })

    def inspect_instance(self, instance):

        if instance.get("PubliclyAccessible") is True:
            self.add_finding(instance)

    def scan(self):

        self.findings = []
        self.errors = []

        instances = []
        marker = None

        # RDS DescribeDBInstances uses Marker pagination.
        while True:

            params = {}

            if marker:
                params["Marker"] = marker

            try:
                response = self.rds.describe_db_instances(
                    **params
                )

            except ClientError as error:

                self.errors.append({
                    "resource": "AWS Account",
                    "operation": "DescribeDBInstances",
                    "error": self.error_code(error)
                })

                break

            instances.extend(
                response.get("DBInstances", [])
            )

            new_marker = response.get("Marker")

            if not new_marker:
                break

            if new_marker == marker:
                self.errors.append({
                    "resource": "AWS Account",
                    "operation": "DescribeDBInstances",
                    "error": "PaginationMarkerDidNotAdvance"
                })
                break

            marker = new_marker

        for instance in instances:
            self.inspect_instance(instance)

        return {
            "service": "RDS",
            "scanned_instances": len(instances),
            "findings": self.findings,
            "errors": self.errors
        }


if __name__ == "__main__":

    scanner = RDSScanner()
    results = scanner.scan()

    print("\n========== CLOUDGUARD RDS SCAN ==========")
    print("DB instances scanned:", results["scanned_instances"])
    print("Findings:", len(results["findings"]))
    print("Errors:", len(results["errors"]))

    for finding in results["findings"]:
        print("\n----------------------------------------")
        print("Database:", finding["resource"])
        print("Issue:", finding["title"])
        print("Severity:", finding["severity"])
        print("Evidence:", finding["evidence"])
        print("Recommendation:", finding["recommendation"])

    for error in results["errors"]:
        print("\n[SCAN ERROR]", error)

    print("\n========== SCAN COMPLETE ==========")
