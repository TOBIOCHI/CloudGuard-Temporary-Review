
from cloudguard.scanners.cloudtrail_scanner import CloudTrailScanner


class FakeCloudTrail:
    def __init__(self, trails=None, logging=True):
        self.trails = trails or []
        self.logging = logging

    def describe_trails(self, **kwargs):
        return {"trailList": self.trails}

    def get_trail_status(self, Name):
        return {"IsLogging": self.logging}


class FakeSession:
    def __init__(self, client):
        self.fake_client = client

    def client(self, service_name):
        return self.fake_client


def make_trail(
    name="test-trail",
    multi_region=True,
    validation=True
):
    return {
        "Name": name,
        "TrailARN": f"arn:aws:cloudtrail:eu-north-1:123456789012:trail/{name}",
        "HomeRegion": "eu-north-1",
        "IsMultiRegionTrail": multi_region,
        "IsOrganizationTrail": False,
        "LogFileValidationEnabled": validation,
        "S3BucketName": "test-cloudtrail-bucket"
    }


def test_detects_no_customer_managed_trail():
    fake = FakeCloudTrail(trails=[])
    scanner = CloudTrailScanner(session=FakeSession(fake))

    results = scanner.scan()

    assert results["scanned_trails"] == 0
    assert any(
        finding["check"] == "NO_CUSTOM_TRAIL"
        for finding in results["findings"]
    )


def test_detects_trail_that_is_not_logging():
    fake = FakeCloudTrail(
        trails=[make_trail()],
        logging=False
    )
    scanner = CloudTrailScanner(session=FakeSession(fake))

    results = scanner.scan()

    assert any(
        finding["check"] == "CLOUDTRAIL_NOT_LOGGING"
        for finding in results["findings"]
    )


def test_detects_non_multi_region_trail():
    fake = FakeCloudTrail(
        trails=[make_trail(multi_region=False)]
    )
    scanner = CloudTrailScanner(session=FakeSession(fake))

    results = scanner.scan()

    assert any(
        finding["check"] == "CLOUDTRAIL_NOT_MULTI_REGION"
        for finding in results["findings"]
    )


def test_detects_disabled_log_file_validation():
    fake = FakeCloudTrail(
        trails=[make_trail(validation=False)]
    )
    scanner = CloudTrailScanner(session=FakeSession(fake))

    results = scanner.scan()

    assert any(
        finding["check"] == "CLOUDTRAIL_LOG_FILE_VALIDATION_DISABLED"
        for finding in results["findings"]
    )


def test_secure_trail_has_no_findings():
    fake = FakeCloudTrail(
        trails=[make_trail()],
        logging=True
    )
    scanner = CloudTrailScanner(session=FakeSession(fake))

    results = scanner.scan()

    assert results["scanned_trails"] == 1
    assert results["findings"] == []


def test_reports_correct_trail_count():
    fake = FakeCloudTrail(
        trails=[
            make_trail(name="trail-one"),
            make_trail(name="trail-two")
        ]
    )
    scanner = CloudTrailScanner(session=FakeSession(fake))

    results = scanner.scan()

    assert results["scanned_trails"] == 2
