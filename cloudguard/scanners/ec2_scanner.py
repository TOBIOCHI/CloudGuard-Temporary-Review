
"""
CloudGuard - EC2 Security Group Scanner

Read-only checks:
1. SSH (TCP 22) exposed to the internet
2. RDP (TCP 3389) exposed to the internet
3. Other unrestricted inbound ports
4. All-protocol inbound rules exposed to the internet

Supports IPv4, IPv6, and DescribeSecurityGroups pagination.

This scanner inspects security-group rules. It does not claim
that a group is attached to a running EC2 instance.
"""

import boto3
import ipaddress

from botocore.exceptions import ClientError


class EC2Scanner:

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

    @staticmethod
    def is_public_cidr(cidr):
        """Return True when a CIDR represents the entire address space."""

        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return network.prefixlen == 0

        except ValueError:
            return False

    def add_finding(
        self,
        group,
        check,
        severity,
        title,
        description,
        recommendation,
        evidence=None
    ):
        self.findings.append({
            "service": "EC2",
            "resource": group.get("GroupId", "Unknown"),
            "check": check,
            "severity": severity,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "evidence": evidence or {}
        })

    def get_public_sources(self, permission):

        sources = []

        for item in permission.get("IpRanges", []):
            cidr = item.get("CidrIp")

            if cidr and self.is_public_cidr(cidr):
                sources.append({
                    "type": "IPv4",
                    "cidr": cidr
                })

        for item in permission.get("Ipv6Ranges", []):
            cidr = item.get("CidrIpv6")

            if cidr and self.is_public_cidr(cidr):
                sources.append({
                    "type": "IPv6",
                    "cidr": cidr
                })

        return sources

    @staticmethod
    def rule_includes_port(permission, port):

        protocol = str(permission.get("IpProtocol", ""))

        # AWS uses -1 to represent all protocols and all ports.
        if protocol == "-1":
            return True

        # Port checks below are for TCP rules.
        if protocol != "tcp":
            return False

        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")

        if from_port is None or to_port is None:
            return False

        return from_port <= port <= to_port

    def inspect_permission(self, group, permission):

        public_sources = self.get_public_sources(permission)

        if not public_sources:
            return

        protocol = str(permission.get("IpProtocol", "unknown"))

        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")

        evidence = {
            "group_id": group.get("GroupId"),
            "group_name": group.get("GroupName"),
            "protocol": protocol,
            "from_port": from_port,
            "to_port": to_port,
            "public_sources": public_sources
        }

        # Detect SSH exposure.
        if self.rule_includes_port(permission, 22):

            self.add_finding(
                group,
                "INTERNET_EXPOSED_SSH",
                "HIGH",
                "SSH access exposed to the internet",
                (
                    "This security group permits inbound traffic "
                    "to TCP port 22 from an unrestricted IPv4 or "
                    "IPv6 source."
                ),
                (
                    "Restrict SSH access to trusted IP addresses "
                    "or a private management network. Consider "
                    "using AWS Systems Manager Session Manager."
                ),
                evidence
            )

        # Detect RDP exposure.
        if self.rule_includes_port(permission, 3389):

            self.add_finding(
                group,
                "INTERNET_EXPOSED_RDP",
                "HIGH",
                "RDP access exposed to the internet",
                (
                    "This security group permits inbound traffic "
                    "to TCP port 3389 from an unrestricted IPv4 "
                    "or IPv6 source."
                ),
                (
                    "Restrict RDP access to trusted IP addresses "
                    "or use a secure remote-access solution."
                ),
                evidence
            )

        # Detect all-protocol exposure.
        if protocol == "-1":

            self.add_finding(
                group,
                "UNRESTRICTED_INBOUND_TRAFFIC",
                "HIGH",
                "All inbound protocols exposed to the internet",
                (
                    "This security group allows all inbound "
                    "protocols and ports from an unrestricted "
                    "IPv4 or IPv6 source."
                ),
                (
                    "Replace the unrestricted rule with specific "
                    "protocols, ports, and trusted source ranges."
                ),
                evidence
            )

        # Detect other unrestricted TCP/UDP ports.
        elif not (
            self.rule_includes_port(permission, 22)
            or self.rule_includes_port(permission, 3389)
        ):

            self.add_finding(
                group,
                "UNRESTRICTED_INBOUND_PORT",
                "MEDIUM",
                "Inbound port exposed to the internet",
                (
                    "This security group permits inbound traffic "
                    "to a port or protocol from an unrestricted "
                    "IPv4 or IPv6 source."
                ),
                (
                    "Confirm that this service must be internet "
                    "accessible. Restrict its source CIDRs and "
                    "ports to the minimum required."
                ),
                evidence
            )

    def inspect_group(self, group):

        for permission in group.get("IpPermissions", []):
            self.inspect_permission(group, permission)

    def scan(self):

        self.findings = []
        self.errors = []

        security_groups = []
        next_token = None

        # Retrieve every page of security groups.
        while True:

            params = {}

            if next_token:
                params["NextToken"] = next_token

            try:
                response = self.ec2.describe_security_groups(
                    **params
                )

            except ClientError as error:

                self.errors.append({
                    "resource": "AWS Account",
                    "operation": "DescribeSecurityGroups",
                    "error": self.error_code(error)
                })

                break

            security_groups.extend(
                response.get("SecurityGroups", [])
            )

            new_token = response.get("NextToken")

            if not new_token:
                break

            if new_token == next_token:
                self.errors.append({
                    "resource": "AWS Account",
                    "operation": "DescribeSecurityGroups",
                    "error": "PaginationTokenDidNotAdvance"
                })
                break

            next_token = new_token

        for group in security_groups:
            self.inspect_group(group)

        return {
            "service": "EC2",
            "scanned_security_groups": len(security_groups),
            "findings": self.findings,
            "errors": self.errors
        }


if __name__ == "__main__":

    scanner = EC2Scanner()
    results = scanner.scan()

    print("\n========== CLOUDGUARD EC2 SCAN ==========")
    print(
        "Security groups scanned:",
        results["scanned_security_groups"]
    )
    print("Findings:", len(results["findings"]))
    print("Errors:", len(results["errors"]))

    for finding in results["findings"]:
        print("\n----------------------------------------")
        print("Resource:", finding["resource"])
        print("Issue:", finding["title"])
        print("Severity:", finding["severity"])
        print("Evidence:", finding["evidence"])
        print("Recommendation:", finding["recommendation"])

    for error in results["errors"]:
        print("\n[SCAN ERROR]", error)

    print("\n========== SCAN COMPLETE ==========")
