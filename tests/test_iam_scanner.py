
from cloudguard.scanners.iam_scanner import IAMScanner


class FakeIAM:

    def __init__(
        self,
        users=None,
        mfa_devices=None,
        attached_policies=None,
        groups=None,
        policy_document=None
    ):
        self.users = users or []
        self.mfa_devices = mfa_devices or []
        self.attached_policies = attached_policies or []
        self.groups = groups or []
        self.policy_document = policy_document or {}

    def list_users(self):
        return {"Users": self.users}

    def list_mfa_devices(self, UserName):
        return {"MFADevices": self.mfa_devices}

    def list_attached_user_policies(self, UserName):
        return {"AttachedPolicies": self.attached_policies}

    def list_user_policies(self, UserName):
        return {"PolicyNames": []}

    def list_groups_for_user(self, UserName):
        return {"Groups": self.groups}

    def get_policy(self, PolicyArn):
        return {
            "Policy": {
                "DefaultVersionId": "v1"
            }
        }

    def get_policy_version(self, PolicyArn, VersionId):
        return {
            "PolicyVersion": {
                "Document": self.policy_document
            }
        }

    def list_attached_group_policies(self, GroupName):
        return {"AttachedPolicies": []}

    def list_group_policies(self, GroupName):
        return {"PolicyNames": []}


class PaginatedFakeIAM(FakeIAM):

    def __init__(self):
        super().__init__(users=[])
        self.calls = 0

    def list_users(self, **kwargs):
        self.calls += 1

        if self.calls == 1:
            return {
                "Users": [{"UserName": "user-one"}],
                "IsTruncated": True,
                "Marker": "page-2"
            }

        return {
            "Users": [{"UserName": "user-two"}],
            "IsTruncated": False
        }


class FakeSession:

    def __init__(self, fake_iam):
        self.fake_iam = fake_iam

    def client(self, service):
        if service == "iam":
            return self.fake_iam

        raise ValueError(f"Unexpected AWS service: {service}")


def run_scan(fake_iam):
    return IAMScanner(
        session=FakeSession(fake_iam)
    ).scan()


def test_detects_user_without_mfa():
    fake = FakeIAM(
        users=[{"UserName": "test-user"}]
    )

    result = run_scan(fake)

    assert any(
        f["check"] == "IAM_USER_WITHOUT_MFA"
        for f in result["findings"]
    )


def test_user_with_mfa_has_no_mfa_finding():
    fake = FakeIAM(
        users=[{"UserName": "test-user"}],
        mfa_devices=[{"SerialNumber": "arn:aws:iam::123:mfa/test"}]
    )

    result = run_scan(fake)

    assert not any(
        f["check"] == "IAM_USER_WITHOUT_MFA"
        for f in result["findings"]
    )


def test_detects_administrator_access_policy():
    fake = FakeIAM(
        users=[{"UserName": "admin-user"}],
        attached_policies=[{
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }]
    )

    result = run_scan(fake)

    assert any(
        f["check"] == "IAM_ADMINISTRATOR_ACCESS"
        for f in result["findings"]
    )


def test_detects_wildcard_policy():
    fake = FakeIAM(
        users=[{"UserName": "power-user"}],
        attached_policies=[{
            "PolicyName": "CustomPolicy",
            "PolicyArn": "arn:aws:iam::123:policy/CustomPolicy"
        }],
        policy_document={
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }
    )

    result = run_scan(fake)

    assert any(
        f["check"] == "IAM_OVERLY_PERMISSIVE_POLICY"
        for f in result["findings"]
    )


def test_reports_correct_user_count():
    fake = FakeIAM(
        users=[
            {"UserName": "user-one"},
            {"UserName": "user-two"}
        ]
    )

    result = run_scan(fake)

    assert result["scanned_users"] == 2
    assert result["errors"] == []


def test_retrieves_users_from_multiple_pages():
    fake = PaginatedFakeIAM()

    result = run_scan(fake)

    assert result["scanned_users"] == 2
    assert fake.calls == 2
    assert result["errors"] == []
