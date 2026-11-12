
from cloudguard.scanners.rds_scanner import RDSScanner


class FakeRDS:

    def __init__(self, instances=None, pages=None):
        self.instances = instances or []
        self.pages = pages
        self.calls = 0

    def describe_db_instances(self, **kwargs):

        self.calls += 1

        if self.pages is not None:

            if self.calls == 1:
                return self.pages[0]

            return self.pages[1]

        return {"DBInstances": self.instances}


class FakeSession:

    def __init__(self, fake_rds):
        self.fake_rds = fake_rds

    def client(self, service):

        if service == "rds":
            return self.fake_rds

        raise ValueError(service)


def run_scan(fake_rds):
    return RDSScanner(
        session=FakeSession(fake_rds)
    ).scan()


def make_instance(identifier, publicly_accessible):

    return {
        "DBInstanceIdentifier": identifier,
        "Engine": "postgres",
        "EngineVersion": "16.3",
        "PubliclyAccessible": publicly_accessible,
        "Endpoint": {
            "Address": f"{identifier}.example.amazonaws.com",
            "Port": 5432
        },
        "DBSubnetGroup": {
            "VpcId": "vpc-123456"
        },
        "VpcSecurityGroups": [
            {"VpcSecurityGroupId": "sg-123456"}
        ],
        "DBInstanceStatus": "available"
    }


def test_detects_publicly_accessible_database():

    fake = FakeRDS(instances=[
        make_instance("public-db", True)
    ])

    result = run_scan(fake)

    assert any(
        f["check"] == "RDS_PUBLICLY_ACCESSIBLE"
        and f["severity"] == "MEDIUM"
        for f in result["findings"]
    )


def test_private_database_has_no_finding():

    fake = FakeRDS(instances=[
        make_instance("private-db", False)
    ])

    result = run_scan(fake)

    assert result["findings"] == []


def test_reports_correct_database_count():

    fake = FakeRDS(instances=[
        make_instance("db-one", True),
        make_instance("db-two", False)
    ])

    result = run_scan(fake)

    assert result["scanned_instances"] == 2
    assert result["errors"] == []


def test_retrieves_databases_from_multiple_pages():

    fake = FakeRDS(pages=[
        {
            "DBInstances": [
                make_instance("db-page-one", False)
            ],
            "Marker": "page-two"
        },
        {
            "DBInstances": [
                make_instance("db-page-two", True)
            ]
        }
    ])

    result = run_scan(fake)

    assert result["scanned_instances"] == 2
    assert fake.calls == 2
    assert len(result["findings"]) == 1
    assert result["errors"] == []


def test_empty_database_list():

    fake = FakeRDS()

    result = run_scan(fake)

    assert result["scanned_instances"] == 0
    assert result["findings"] == []
    assert result["errors"] == []
