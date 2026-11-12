
"""
CloudGuard - EBS Encryption Scanner

Read-only checks:
1. Detect EBS volumes without encryption.
2. Record volume details as evidence.
3. Retrieve all volumes using pagination.

No volume is modified, encrypted, detached, or deleted.
"""

import boto3

from botocore.exceptions import ClientError


class EBSScanner:

    def __init__(self, session=None):

        self.session = session or boto3.Session(
            profile_name="cloudguard-audit",
            region_name="eu-north-1"
        )

        self.ec2 = self.session.client("ec2")

        self.findings = []
        self.errors = []

    @staticmethod
    def error_code(error):
        return error.response.get("Error", {}).get(
            "Code", "UnknownError"
        )

    def add_finding(self, volume):

        self.findings.append({
            "service": "EBS",
            "resource": volume.get("VolumeId", "Unknown"),
            "check": "EBS_VOLUME_UNENCRYPTED",
            "severity": "MEDIUM",
            "title": "EBS volume is not encrypted",
            "description": (
                "This EBS volume is not encrypted. "
                "Data stored on the volume does not have "
                "EBS encryption protection."
            ),
            "recommendation": (
                "Review the volume's data sensitivity and "
                "encryption requirements. Plan a safe migration "
                "to an encrypted volume using an encrypted "
                "snapshot. Do not attempt to encrypt an existing "
                "volume directly."
            ),
            "evidence": {
                "volume_id": volume.get("VolumeId"),
                "encrypted": volume.get("Encrypted"),
                "state": volume.get("State"),
                "size_gib": volume.get("Size"),
                "availability_zone": volume.get("AvailabilityZone"),
                "volume_type": volume.get("VolumeType")
            }
        })

    def inspect_volume(self, volume):

        if volume.get("Encrypted") is False:
            self.add_finding(volume)

    def scan(self):

        self.findings = []
        self.errors = []

        volumes = []
        next_token = None

        # Retrieve every page of EBS volumes.
        while True:

            params = {}

            if next_token:
                params["NextToken"] = next_token

            try:
                response = self.ec2.describe_volumes(
                    **params
                )

            except ClientError as error:

                self.errors.append({
                    "resource": "AWS Account",
                    "operation": "DescribeVolumes",
                    "error": self.error_code(error)
                })

                break

            volumes.extend(response.get("Volumes", []))

            new_token = response.get("NextToken")

            if not new_token:
                break

            if new_token == next_token:
                self.errors.append({
                    "resource": "AWS Account",
                    "operation": "DescribeVolumes",
                    "error": "PaginationTokenDidNotAdvance"
                })
                break

            next_token = new_token

        for volume in volumes:
            self.inspect_volume(volume)

        return {
            "service": "EBS",
            "scanned_volumes": len(volumes),
            "findings": self.findings,
            "errors": self.errors
        }


if __name__ == "__main__":

    scanner = EBSScanner()
    results = scanner.scan()

    print("\n========== CLOUDGUARD EBS SCAN ==========")
    print("Volumes scanned:", results["scanned_volumes"])
    print("Findings:", len(results["findings"]))
    print("Errors:", len(results["errors"]))

    for finding in results["findings"]:
        print("\n----------------------------------------")
        print("Volume:", finding["resource"])
        print("Issue:", finding["title"])
        print("Severity:", finding["severity"])
        print("Evidence:", finding["evidence"])
        print("Recommendation:", finding["recommendation"])

    for error in results["errors"]:
        print("\n[SCAN ERROR]", error)

    print("\n========== SCAN COMPLETE ==========")
   