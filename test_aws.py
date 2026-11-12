
import boto3

# Connect using the AWS CLI profile
session = boto3.Session(profile_name="cloudguard-audit")

# Connect to AWS Security Token Service
sts = session.client("sts")

# Verify the AWS identity
identity = sts.get_caller_identity()

print("AWS Account:", identity["Account"])
print("Connected Identity:", identity["Arn"])
