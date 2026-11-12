
import boto3
from botocore.exceptions import ClientError, BotoCoreError

PROFILE = "cloudguard-audit"
REGION = "eu-north-1"

session = boto3.Session(
    profile_name=PROFILE,
    region_name=REGION
)

def check_service(name, operation):
    try:
        operation()
        print(f"[PASS] {name}")
    except ClientError as error:
        code = error.response["Error"]["Code"]
        print(f"[FAIL] {name}: {code}")
    except BotoCoreError as error:
        print(f"[ERROR] {name}: {error}")


print("\n=== CLOUDGUARD AWS PERMISSION TEST ===\n")

# S3
s3 = session.client("s3")
check_service("S3 - List buckets", s3.list_buckets)

# IAM
iam = session.client("iam")
check_service("IAM - Account summary", iam.get_account_summary)

# EC2
ec2 = session.client("ec2")
check_service(
    "EC2 - Describe security groups",
    ec2.describe_security_groups
)

# RDS
rds = session.client("rds")
check_service(
    "RDS - Describe database instances",
    rds.describe_db_instances
)

# CloudTrail
cloudtrail = session.client("cloudtrail")
check_service(
    "CloudTrail - Describe trails",
    cloudtrail.describe_trails
)

print("\n=== TEST COMPLETE ===")
