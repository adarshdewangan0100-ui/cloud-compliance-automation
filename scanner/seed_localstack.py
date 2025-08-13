#!/usr/bin/env python3
import os, json, time
import boto3
from botocore.config import Config

region = os.getenv("AWS_REGION", "us-east-1")
endpoint = os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566")

cfg = Config(retries={"max_attempts": 10, "mode": "standard"})

s3  = boto3.client("s3", region_name=region, endpoint_url=endpoint, config=cfg)
ec2 = boto3.client("ec2", region_name=region, endpoint_url=endpoint, config=cfg)
iam = boto3.client("iam", endpoint_url=endpoint, config=cfg)
rds = boto3.client("rds", region_name=region, endpoint_url=endpoint, config=cfg)

def seed_s3():
    bucket = "demo-public-bucket"
    try:
        s3.create_bucket(Bucket=bucket)
    except Exception:
        pass
    # Public ACL
    s3.put_bucket_acl(
        Bucket=bucket,
        AccessControlPolicy={
            "Grants": [{
                "Grantee": {"Type":"Group","URI":"http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ"
            }],
            "Owner": {"DisplayName":"owner","ID":"owner-id"}
        }
    )
    # No block-public-access set (so it will trigger)
    print(f"[seed] S3: created public bucket {bucket}")

def seed_ec2():
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg  = ec2.create_security_group(
        GroupName="demo-open-sg",
        Description="Open to world for demo",
        VpcId=vpc
    )["GroupId"]
    # Ingress 0.0.0.0/0 on 22, 80, 443
    for p in [22, 80, 443]:
        ec2.authorize_security_group_ingress(
            GroupId=sg,
            IpProtocol="tcp",
            FromPort=p,
            ToPort=p,
            CidrIp="0.0.0.0/0"
        )
    print(f"[seed] EC2: created SG {sg} with open ports")

def seed_iam():
    try:
        iam.create_user(UserName="demo-user")
    except Exception:
        pass
    iam.create_access_key(UserName="demo-user")
    print("[seed] IAM: created demo-user + access key")

def seed_rds():
    # LocalStack won’t fully spin a DB, but call creates a stub so code paths exist.
    try:
        rds.create_db_instance(
            DBInstanceIdentifier="demo-db",
            AllocatedStorage=20,
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="postgres",
            MasterUserPassword="postgres",
            PubliclyAccessible=False
        )
    except Exception:
        pass
    print("[seed] RDS: created demo-db (stub)")

if __name__ == "__main__":
    seed_s3()
    seed_ec2()
    seed_iam()
    seed_rds()
    print("[seed] Done.")
