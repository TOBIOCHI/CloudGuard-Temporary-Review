
"""
CloudGuard - S3 Security Scanner

Read-only checks:
1. Public bucket policies
2. Public bucket ACLs
3. Bucket-level Block Public Access
4. Account-level Block Public Access

A missing protection setting is not automatically
treated as proof of public exposure.
"""

import boto3

from botocore.exceptions import ClientError


PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


class S3Scanner:

    def __init__(self, session=None):
        self.session = session or boto3.Session(
            profile_name="cloudguard-audit",
            region_name="eu-north-1"
        )

        self.s3 = self.session.client("s3")
        self.s3control = self.session.client("s3control")
        self.sts = self.session.client("sts")

        self.findings = []
        self.errors = []

    def add_finding(
        self, bucket, check, severity,
        title, description, recommendation, evidence=None
    ):
        self.findings.append({
            "service": "S3",
            "resource": bucket,
            "check": check,
            "severity": severity,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "evidence": evidence or {}
        })

    @staticmethod
    def error_code(error):
        return error.response.get("Error", {}).get(
            "Code", "UnknownError"
        )

    def get_account_public_access_block(self, account_id):
        try:
            response = self.s3control.get_public_access_block(
                AccountId=account_id
            )
            return response.get("PublicAccessBlockConfiguration", {})

        except ClientError as error:
            code = self.error_code(error)

            if code == "NoSuchPublicAccessBlockConfiguration":
                return {}

            self.errors.append({
                "resource": "AWS Account",
                "operation": "GetAccountPublicAccessBlock",
                "error": code
            })
            return None

    def get_bucket_public_access_block(self, bucket):
        try:
            response = self.s3.get_public_access_block(
                Bucket=bucket
            )
            return response.get("PublicAccessBlockConfiguration", {})

        except ClientError as error:
            code = self.error_code(error)

            if code == "NoSuchPublicAccessBlockConfiguration":
                return {}

            self.errors.append({
                "resource": bucket,
                "operation": "GetPublicAccessBlock",
                "error": code
            })
            return None

    def check_bucket_policy(self, bucket, account_block, bucket_block):

        try:
            response = self.s3.get_bucket_policy_status(
                Bucket=bucket
            )
            is_public = response.get("PolicyStatus", {}).get(
                "IsPublic", False
            )

        except ClientError as error:
            code = self.error_code(error)

            if code == "NoSuchBucketPolicy":
                return

            self.errors.append({
                "resource": bucket,
                "operation": "GetBucketPolicyStatus",
                "error": code
            })
            return

        if not is_public:
            return

        # RestrictPublicBuckets can restrict access to
        # buckets with public policies.
        restricted = (
            (account_block or {}).get("RestrictPublicBuckets", False)
            or
            (bucket_block or {}).get("RestrictPublicBuckets", False)
        )

        if restricted:
            severity = "MEDIUM"
            title = "Public policy detected with access restriction"
            description = (
                "AWS identifies the bucket policy as public, "
                "but RestrictPublicBuckets is enabled at the "
                "bucket or account level."
            )
            recommendation = (
                "Review the policy and remove unnecessary public "
                "access. Verify effective access restrictions."
            )
        else:
            severity = "HIGH"
            title = "Public bucket policy detected"
            description = (
                "AWS identifies this bucket policy as public, "
                "and no applicable RestrictPublicBuckets setting "
                "was detected."
            )
            recommendation = (
                "Review the bucket policy and remove unintended "
                "public access. Enable appropriate Block Public "
                "Access protections."
            )

        self.add_finding(
            bucket,
            "PUBLIC_BUCKET_POLICY",
            severity,
            title,
            description,
            recommendation,
            {"is_public": True, "restricted": restricted}
        )

    def check_bucket_acl(self, bucket, account_block, bucket_block):

        try:
            response = self.s3.get_bucket_acl(Bucket=bucket)

        except ClientError as error:
            self.errors.append({
                "resource": bucket,
                "operation": "GetBucketAcl",
                "error": self.error_code(error)
            })
            return

        public_grants = []

        for grant in response.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI")

            if uri in PUBLIC_GROUPS:
                public_grants.append({
                    "permission": grant.get("Permission"),
                    "group": uri
                })

        if not public_grants:
            return

        # IgnorePublicAcls prevents public ACL grants
        # from granting access.
        ignored = (
            (account_block or {}).get("IgnorePublicAcls", False)
            or
            (bucket_block or {}).get("IgnorePublicAcls", False)
        )

        if ignored:
            severity = "LOW"
            title = "Public ACL grants detected but ignored"
            description = (
                "The bucket ACL contains public grants, "
                "but IgnorePublicAcls is enabled."
            )
            recommendation = (
                "Remove unnecessary public ACL grants and "
                "prefer bucket policies with Block Public Access."
            )
        else:
            severity = "HIGH"
            title = "Public bucket ACL detected"
            description = (
                "The bucket ACL grants permissions to a public "
                "or broadly authenticated AWS group."
            )
            recommendation = (
                "Remove unintended public ACL grants and enable "
                "IgnorePublicAcls or appropriate Block Public Access."
            )

        self.add_finding(
            bucket,
            "PUBLIC_BUCKET_ACL",
            severity,
            title,
            description,
            recommendation,
            {"public_grants": public_grants, "ignored": ignored}
        )

    def check_block_public_access(self, bucket, account_block, bucket_block):

        if account_block is None or bucket_block is None:
            return

        account_flags = account_block or {}
        bucket_flags = bucket_block or {}

        flags = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets"
        ]

        enabled = {
            flag: (
                account_flags.get(flag, False)
                or bucket_flags.get(flag, False)
            )
            for flag in flags
        }

        if not any(enabled.values()):
            self.add_finding(
                bucket,
                "BLOCK_PUBLIC_ACCESS_DISABLED",
                "MEDIUM",
                "No Block Public Access protections detected",
                (
                    "No enabled account-level or bucket-level "
                    "Block Public Access settings were detected."
                ),
                (
                    "Review the bucket's access requirements and "
                    "enable all four Block Public Access settings "
                    "unless a documented exception is required."
                ),
                {"effective_protection_flags": enabled}
            )

    def scan(self):

        self.findings = []
        self.errors = []

        identity = self.sts.get_caller_identity()
        account_id = identity["Account"]

        account_block = self.get_account_public_access_block(
            account_id
        )

        try:
            buckets = self.s3.list_buckets().get("Buckets", [])

        except ClientError as error:
            return {
                "service": "S3",
                "scanned_buckets": 0,
                "findings": [],
                "errors": [{
                    "resource": "AWS Account",
                    "operation": "ListBuckets",
                    "error": self.error_code(error)
                }]
            }

        for item in buckets:
            bucket = item["Name"]

            bucket_block = self.get_bucket_public_access_block(
                bucket
            )

            self.check_bucket_policy(
                bucket, account_block, bucket_block
            )

            self.check_bucket_acl(
                bucket, account_block, bucket_block
            )

            self.check_block_public_access(
                bucket, account_block, bucket_block
            )

        return {
            "service": "S3",
            "scanned_buckets": len(buckets),
            "findings": self.findings,
            "errors": self.errors
        }


if __name__ == "__main__":

    scanner = S3Scanner()
    results = scanner.scan()

    print("\n========== CLOUDGUARD S3 SCAN ==========")
    print("Buckets scanned:", results["scanned_buckets"])
    print("Findings:", len(results["findings"]))
    print("Errors:", len(results["errors"]))

    for finding in results["findings"]:
        print("\n----------------------------------------")
        print("Bucket:", finding["resource"])
        print("Severity:", finding["severity"])
        print("Issue:", finding["title"])
        print("Recommendation:", finding["recommendation"])

    for error in results["errors"]:
        print("\n[SCAN ERROR]", error)

    print("\n========== SCAN COMPLETE ==========")
