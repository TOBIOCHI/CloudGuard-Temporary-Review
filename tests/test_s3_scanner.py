from cloudguard.scanners.s3_scanner import S3Scanner


class FakeSession:
    def __init__(self, policy_public=False, public_acl=False,
                 account_block=None, bucket_block=None):
        self.policy_public = policy_public
        self.public_acl = public_acl
        self.account_block = account_block or {}
        self.bucket_block = bucket_block or {}

    def client(self, service):
        if service == "s3":
            return FakeS3(self)
        if service == "s3control":
            return FakeS3Control(self)
        if service == "sts":
            return FakeSTS()
        raise ValueError(service)


class FakeS3:
    def __init__(self, session):
        self.session = session

    def list_buckets(self):
        return {"Buckets": [{"Name": "test-bucket"}]}

    def get_public_access_block(self, Bucket):
        return {"PublicAccessBlockConfiguration": self.session.bucket_block}

    def get_bucket_policy_status(self, Bucket):
        return {"PolicyStatus": {"IsPublic": self.session.policy_public}}

    def get_bucket_acl(self, Bucket):
        grants = []
        if self.session.public_acl:
            grants.append({
                "Grantee": {
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                },
                "Permission": "READ"
            })
        return {"Grants": grants}


class FakeS3Control:
    def __init__(self, session):
        self.session = session

    def get_public_access_block(self, AccountId):
        return {"PublicAccessBlockConfiguration": self.session.account_block}


class FakeSTS:
    def get_caller_identity(self):
        return {"Account": "123456789012"}


def run_scan(session):
    return S3Scanner(session=session).scan()


def test_detects_public_bucket_policy():
    result = run_scan(FakeSession(policy_public=True))
    assert any(
        f["check"] == "PUBLIC_BUCKET_POLICY"
        and f["severity"] == "HIGH"
        for f in result["findings"]
    )


def test_detects_public_bucket_acl():
    result = run_scan(FakeSession(public_acl=True))
    assert any(
        f["check"] == "PUBLIC_BUCKET_ACL"
        and f["severity"] == "HIGH"
        for f in result["findings"]
    )


def test_detects_missing_block_public_access():
    result = run_scan(FakeSession())
    assert any(
        f["check"] == "BLOCK_PUBLIC_ACCESS_DISABLED"
        for f in result["findings"]
    )


def test_protected_bucket_has_no_public_policy_finding():
    protection = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True
    }
    result = run_scan(FakeSession(account_block=protection))

    assert not any(
        f["check"] == "PUBLIC_BUCKET_POLICY"
        for f in result["findings"]
    )
    assert not any(
        f["check"] == "BLOCK_PUBLIC_ACCESS_DISABLED"
        for f in result["findings"]
    )


def test_scanner_reports_bucket_count():
    result = run_scan(FakeSession())
    assert result["scanned_buckets"] == 1
    assert result["errors"] == []
