
from cloudguard.scanners.ec2_scanner import EC2Scanner


class FakeEC2:

    def __init__(self, groups=None, pages=None):
        self.groups = groups or []
        self.pages = pages
        self.calls = 0

    def describe_security_groups(self, **kwargs):

        self.calls += 1

        if self.pages is not None:

            if self.calls == 1:
                return self.pages[0]

            return self.pages[1]

        return {"SecurityGroups": self.groups}


class FakeSession:

    def __init__(self, fake_ec2):
        self.fake_ec2 = fake_ec2

    def client(self, service):

        if service == "ec2":
            return self.fake_ec2

        raise ValueError(service)


def run_scan(fake_ec2):
    return EC2Scanner(
        session=FakeSession(fake_ec2)
    ).scan()


def make_group(permission):

    return {
        "GroupId": "sg-123456",
        "GroupName": "test-security-group",
        "IpPermissions": [permission]
    }


def test_detects_ssh_open_to_ipv4_internet():

    fake = FakeEC2(groups=[
        make_group({
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        })
    ])

    result = run_scan(fake)

    assert any(
        f["check"] == "INTERNET_EXPOSED_SSH"
        and f["severity"] == "HIGH"
        for f in result["findings"]
    )


def test_detects_rdp_open_to_ipv6_internet():

    fake = FakeEC2(groups=[
        make_group({
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
        })
    ])

    result = run_scan(fake)

    assert any(
        f["check"] == "INTERNET_EXPOSED_RDP"
        and f["severity"] == "HIGH"
        for f in result["findings"]
    )


def test_detects_other_unrestricted_inbound_port():

    fake = FakeEC2(groups=[
        make_group({
            "IpProtocol": "tcp",
            "FromPort": 8080,
            "ToPort": 8080,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        })
    ])

    result = run_scan(fake)

    assert any(
        f["check"] == "UNRESTRICTED_INBOUND_PORT"
        and f["severity"] == "MEDIUM"
        for f in result["findings"]
    )


def test_private_source_does_not_trigger_public_finding():

    fake = FakeEC2(groups=[
        make_group({
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "192.168.1.0/24"}]
        })
    ])

    result = run_scan(fake)

    assert result["findings"] == []


def test_detects_all_protocols_open_to_internet():

    fake = FakeEC2(groups=[
        make_group({
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        })
    ])

    result = run_scan(fake)

    assert any(
        f["check"] == "UNRESTRICTED_INBOUND_TRAFFIC"
        and f["severity"] == "HIGH"
        for f in result["findings"]
    )


def test_retrieves_security_groups_from_multiple_pages():

    fake = FakeEC2(pages=[
        {
            "SecurityGroups": [{
                "GroupId": "sg-page-one",
                "GroupName": "first-group",
                "IpPermissions": []
            }],
            "NextToken": "page-two"
        },
        {
            "SecurityGroups": [{
                "GroupId": "sg-page-two",
                "GroupName": "second-group",
                "IpPermissions": []
            }]
        }
    ])

    result = run_scan(fake)

    assert result["scanned_security_groups"] == 2
    assert fake.calls == 2
    assert result["errors"] == []
