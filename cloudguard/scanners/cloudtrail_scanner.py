
import boto3
from botocore.exceptions import ClientError


class CloudTrailScanner:
    """
    Read-only CloudTrail security scanner.

    Checks:
    - Whether a customer-managed trail exists.
    - Whether each trail is actively logging.
    - Whether a trail covers multiple AWS regions.
    - Whether log-file integrity validation is enabled.
    """

    def __init__(self, session=None):
        if session is None:
            session = boto3.Session(
                profile_name="cloudguard-audit",
                region_name="eu-north-1"
            )

        self.client = session.client("cloudtrail")
        self.findings = []
        self.errors = []
        self.scanned_trails = 0

    def add_finding(
        self,
        resource,
        check,
        severity,
        title,
        description,
        recommendation,
        evidence=None
    ):
        self.findings.append({
            "service": "CloudTrail",
            "resource": resource,
            "check": check,
            "severity": severity,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "evidence": evidence or {}
        })

    def scan(self):
        self.findings = []
        self.errors = []
        self.scanned_trails = 0

        try:
            response = self.client.describe_trails(
                includeShadowTrails=False
            )
            trails = response.get("trailList", [])

        except ClientError as error:
            self.errors.append({
                "operation": "describe_trails",
                "message": error.response.get(
                    "Error", {}
                ).get("Message", str(error))
            })

            return self.get_results()

        if not trails:
            self.add_finding(
                resource="AWS account",
                check="NO_CUSTOM_TRAIL",
                severity="MEDIUM",
                title="No customer-managed CloudTrail trail found",
                description=(
                    "No customer-managed CloudTrail trail was returned "
                    "in the selected AWS region. CloudTrail Event History "
                    "may still be available, but this scanner did not "
                    "find a trail configured for ongoing delivery to "
                    "a destination such as Amazon S3."
                ),
                recommendation=(
                    "Ask the account owner to review CloudTrail coverage "
                    "and configure an appropriately protected, preferably "
                    "multi-region trail if ongoing audit logging is required."
                )
            )

            return self.get_results()

        for trail in trails:
            self.scanned_trails += 1

            trail_name = trail.get("Name", "Unknown trail")
            trail_arn = trail.get("TrailARN")
            trail_id = trail_arn or trail_name

            evidence = {
                "trail_name": trail_name,
                "trail_arn": trail_arn,
                "home_region": trail.get("HomeRegion"),
                "is_multi_region": trail.get(
                    "IsMultiRegionTrail", False
                ),
                "is_organization_trail": trail.get(
                    "IsOrganizationTrail", False
                ),
                "log_file_validation_enabled": trail.get(
                    "LogFileValidationEnabled", False
                ),
                "s3_bucket_name": trail.get("S3BucketName")
            }

            # Check whether the trail is actively logging.
            try:
                status = self.client.get_trail_status(
                    Name=trail_id
                )

                is_logging = status.get("IsLogging", False)
                evidence["is_logging"] = is_logging

            except ClientError as error:
                self.errors.append({
                    "operation": "get_trail_status",
                    "resource": trail_id,
                    "message": error.response.get(
                        "Error", {}
                    ).get("Message", str(error))
                })
                continue

            if not is_logging:
                self.add_finding(
                    resource=trail_name,
                    check="CLOUDTRAIL_NOT_LOGGING",
                    severity="HIGH",
                    title="CloudTrail trail is not actively logging",
                    description=(
                        "The trail exists, but AWS reports that it is "
                        "not currently logging events."
                    ),
                    recommendation=(
                        "Ask the account owner to investigate and enable "
                        "logging after confirming the intended trail "
                        "configuration."
                    ),
                    evidence=evidence
                )

            # A regional trail does not provide account-wide
            # multi-region coverage by itself.
            if not evidence["is_multi_region"]:
                self.add_finding(
                    resource=trail_name,
                    check="CLOUDTRAIL_NOT_MULTI_REGION",
                    severity="MEDIUM",
                    title="CloudTrail trail is not multi-region",
                    description=(
                        "This trail is not configured as a multi-region "
                        "trail. It may not capture management events "
                        "from other AWS regions."
                    ),
                    recommendation=(
                        "Review regional logging requirements and consider "
                        "a multi-region trail for broader account coverage."
                    ),
                    evidence=evidence
                )

            # Log-file validation helps detect modification or deletion
            # of delivered CloudTrail log files.
            if not evidence["log_file_validation_enabled"]:
                self.add_finding(
                    resource=trail_name,
                    check="CLOUDTRAIL_LOG_FILE_VALIDATION_DISABLED",
                    severity="LOW",
                    title="CloudTrail log-file validation is disabled",
                    description=(
                        "Log-file integrity validation is not enabled "
                        "for this trail."
                    ),
                    recommendation=(
                        "Enable log-file validation if integrity "
                        "verification is required for audit records."
                    ),
                    evidence=evidence
                )

        return self.get_results()

    def get_results(self):
        return {
            "service": "CloudTrail",
            "scanned_trails": self.scanned_trails,
            "findings": self.findings,
            "errors": self.errors
        }
