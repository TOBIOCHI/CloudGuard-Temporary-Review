
"""
CloudGuard - IAM Security Scanner

Read-only checks:
1. IAM users without registered MFA devices.
2. Users with directly attached AdministratorAccess policies.
3. Administrator-level permissions inherited through groups.
4. User and group policies allowing Action "*" on Resource "*".

No AWS resources or policies are modified.
"""

import boto3
from botocore.exceptions import ClientError


class IAMScanner:

    def __init__(self, session=None):
        self.session = session or boto3.Session(
            profile_name="cloudguard-audit",
            region_name="eu-north-1"
        )

        self.iam = self.session.client("iam")
        self.findings = []
        self.errors = []

    def add_finding(
        self, user, check, severity,
        title, description, recommendation, evidence=None
    ):
        self.findings.append({
            "service": "IAM",
            "resource": user,
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

    def api_call(self, operation, **kwargs):
        """Call an IAM API operation and record AWS errors."""
        try:
            method = getattr(self.iam, operation)
            return method(**kwargs)

        except ClientError as error:
            self.errors.append({
                "resource": kwargs.get("UserName", "AWS Account"),
                "operation": operation,
                "error": self.error_code(error)
            })
            return None

    @staticmethod
    def policy_is_admin(document):
        """
        Detect an Allow statement with wildcard Action
        and wildcard Resource.

        This is not a complete IAM policy evaluator.
        """
        if not isinstance(document, dict):
            return False

        statements = document.get("Statement", [])

        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if not isinstance(statement, dict):
                continue

            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])

            if isinstance(actions, str):
                actions = [actions]

            if isinstance(resources, str):
                resources = [resources]

            if "*" in actions and "*" in resources:
                return True

        return False

    def inspect_managed_policy(self, policy, username, source):
        """Inspect an attached managed policy."""
        policy_name = policy.get("PolicyName", "")
        policy_arn = policy.get("PolicyArn", "")

        if policy_name == "AdministratorAccess":
            self.add_finding(
                username,
                "IAM_ADMINISTRATOR_ACCESS",
                "HIGH",
                "AdministratorAccess policy assigned",
                (
                    f"AdministratorAccess is assigned through "
                    f"{source}."
                ),
                (
                    "Review whether full administrator privileges "
                    "are necessary. Apply least-privilege permissions."
                ),
                {
                    "policy_name": policy_name,
                    "policy_arn": policy_arn,
                    "source": source
                }
            )
            return

        if not policy_arn:
            return

        details = self.api_call(
            "get_policy",
            PolicyArn=policy_arn
        )

        if not details:
            return

        default_version = details.get(
            "Policy", {}
        ).get("DefaultVersionId")

        if not default_version:
            return

        version = self.api_call(
            "get_policy_version",
            PolicyArn=policy_arn,
            VersionId=default_version
        )

        if not version:
            return

        document = version.get(
            "PolicyVersion", {}
        ).get("Document", {})

        if self.policy_is_admin(document):
            self.add_finding(
                username,
                "IAM_OVERLY_PERMISSIVE_POLICY",
                "HIGH",
                "Wildcard administrator permissions detected",
                (
                    f"A policy assigned through {source} contains "
                    "an Allow statement with Action '*' and "
                    "Resource '*'."
                ),
                (
                    "Review the policy and replace wildcard "
                    "permissions with the minimum required actions "
                    "and resources."
                ),
                {
                    "policy_name": policy_name,
                    "policy_arn": policy_arn,
                    "source": source
                }
            )

    def inspect_inline_policy(
        self, username, policy_name, document, source
    ):
        if self.policy_is_admin(document):
            self.add_finding(
                username,
                "IAM_OVERLY_PERMISSIVE_POLICY",
                "HIGH",
                "Wildcard inline permissions detected",
                (
                    f"Inline policy '{policy_name}' assigned through "
                    f"{source} allows Action '*' on Resource '*'."
                ),
                (
                    "Replace wildcard permissions with specific "
                    "actions and resources."
                ),
                {
                    "policy_name": policy_name,
                    "source": source
                }
            )

    def check_user_mfa(self, username):
        response = self.api_call(
            "list_mfa_devices",
            UserName=username
        )

        if response is None:
            return

        devices = response.get("MFADevices", [])

        if not devices:
            self.add_finding(
                username,
                "IAM_USER_WITHOUT_MFA",
                "MEDIUM",
                "IAM user has no registered MFA device",
                (
                    "No MFA device is registered for this IAM user. "
                    "Confirm whether the account has console access "
                    "or uses programmatic credentials only."
                ),
                (
                    "Enable MFA for console users and review the "
                    "authentication controls for programmatic access."
                ),
                {"registered_mfa_devices": 0}
            )

    def check_user_policies(self, username):
        # Directly attached managed policies
        response = self.api_call(
            "list_attached_user_policies",
            UserName=username
        )

        if response:
            for policy in response.get("AttachedPolicies", []):
                self.inspect_managed_policy(
                    policy, username, "user"
                )

        # Inline user policies
        response = self.api_call(
            "list_user_policies",
            UserName=username
        )

        if response:
            for policy_name in response.get("PolicyNames", []):
                policy = self.api_call(
                    "get_user_policy",
                    UserName=username,
                    PolicyName=policy_name
                )

                if policy:
                    self.inspect_inline_policy(
                        username,
                        policy_name,
                        policy.get("PolicyDocument", {}),
                        "user"
                    )

    def check_group_policies(self, username):
        response = self.api_call(
            "list_groups_for_user",
            UserName=username
        )

        if not response:
            return

        for group in response.get("Groups", []):
            group_name = group["GroupName"]

            # Attached managed policies
            attached = self.api_call(
                "list_attached_group_policies",
                GroupName=group_name
            )

            if attached:
                for policy in attached.get("AttachedPolicies", []):
                    self.inspect_managed_policy(
                        policy,
                        username,
                        f"group:{group_name}"
                    )

            # Inline group policies
            inline = self.api_call(
                "list_group_policies",
                GroupName=group_name
            )

            if inline:
                for policy_name in inline.get("PolicyNames", []):
                    policy = self.api_call(
                        "get_group_policy",
                        GroupName=group_name,
                        PolicyName=policy_name
                    )

                    if policy:
                        self.inspect_inline_policy(
                            username,
                            policy_name,
                            policy.get("PolicyDocument", {}),
                            f"group:{group_name}"
                        )

    def scan(self):
        """Scan all IAM users, handling user-list pagination."""

        self.findings = []
        self.errors = []

        users = []
        marker = None

        # Retrieve every page of IAM users.
        while True:
            params = {}

            if marker:
                params["Marker"] = marker

            response = self.api_call(
                "list_users",
                **params
            )

            if response is None:
                # Preserve any users already retrieved.
                break

            users.extend(response.get("Users", []))

            if not response.get("IsTruncated", False):
                break

            next_marker = response.get("Marker")

            if not next_marker:
                self.errors.append({
                    "resource": "AWS Account",
                    "operation": "ListUsers",
                    "error": "PaginationMarkerMissing"
                })
                break

            if next_marker == marker:
                self.errors.append({
                    "resource": "AWS Account",
                    "operation": "ListUsers",
                    "error": "PaginationMarkerDidNotAdvance"
                })
                break

            marker = next_marker

        # Scan every user successfully retrieved.
        for user in users:
            username = user["UserName"]

            self.check_user_mfa(username)
            self.check_user_policies(username)
            self.check_group_policies(username)

        return {
            "service": "IAM",
            "scanned_users": len(users),
            "findings": self.findings,
            "errors": self.errors
        }


if __name__ == "__main__":

    scanner = IAMScanner()
    results = scanner.scan()

    print("\n========== CLOUDGUARD IAM SCAN ==========")
    print("Users scanned:", results["scanned_users"])
    print("Findings:", len(results["findings"]))
    print("Errors:", len(results["errors"]))

    for finding in results["findings"]:
        print("\n----------------------------------------")
        print("User:", finding["resource"])
        print("Severity:", finding["severity"])
        print("Issue:", finding["title"])
        print("Recommendation:", finding["recommendation"])

    for error in results["errors"]:
        print("\n[SCAN ERROR]", error)

    print("\n========== SCAN COMPLETE ==========")
