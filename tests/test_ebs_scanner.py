
from cloudguard.scanners.ebs_scanner import EBSScanner


class FakeEC2:

    def __init__(self, volumes=None, pages=None):
        self.volumes = volumes or []
        self.pages = pages
        self.calls = 0

    def describe_volumes(self, **kwargs):

        self.calls += 1

        if self.pages is not None:

            if self.calls == 1:
                return self.pages[0]

            return self.pages[1]

        return {"Volumes": self.volumes}


class FakeSession:

    def __init__(self, fake_ec2):
        self.fake_ec2 = fake_ec2

    def client(self, service):

        if service == "ec2":
            return self.fake_ec2

        raise ValueError(service)


def run_scan(fake_ec2):
    return EBSScanner(
        session=FakeSession(fake_ec2)
    ).scan()


def test_detects_unencrypted_volume():

    fake = FakeEC2(volumes=[{
        "VolumeId": "vol-123",
        "Encrypted": False,
        "State": "available",
        "Size": 20,
        "AvailabilityZone": "eu-north-1a",
        "VolumeType": "gp3"
    }])

    result = run_scan(fake)

    assert any(
        f["check"] == "EBS_VOLUME_UNENCRYPTED"
        and f["severity"] == "MEDIUM"
        for f in result["findings"]
    )


def test_encrypted_volume_has_no_finding():

    fake = FakeEC2(volumes=[{
        "VolumeId": "vol-456",
        "Encrypted": True,
        "State": "in-use",
        "Size": 50,
        "AvailabilityZone": "eu-north-1a",
        "VolumeType": "gp3"
    }])

    result = run_scan(fake)

    assert result["findings"] == []


def test_reports_correct_volume_count():

    fake = FakeEC2(volumes=[
        {"VolumeId": "vol-1", "Encrypted": True},
        {"VolumeId": "vol-2", "Encrypted": False}
    ])

    result = run_scan(fake)

    assert result["scanned_volumes"] == 2
    assert result["errors"] == []


def test_retrieves_volumes_from_multiple_pages():

    fake = FakeEC2(pages=[
        {
            "Volumes": [{
                "VolumeId": "vol-page-one",
                "Encrypted": True
            }],
            "NextToken": "page-two"
        },
        {
            "Volumes": [{
                "VolumeId": "vol-page-two",
                "Encrypted": False
            }]
        }
    ])

    result = run_scan(fake)

    assert result["scanned_volumes"] == 2
    assert fake.calls == 2
    assert len(result["findings"]) == 1
    assert result["errors"] == []


def test_empty_volume_list():

    fake = FakeEC2()

    result = run_scan(fake)

    assert result["scanned_volumes"] == 0
    assert result["findings"] == []
    assert result["errors"] == []
