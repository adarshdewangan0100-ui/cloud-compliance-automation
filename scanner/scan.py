#!/usr/bin/env python3
import boto3, botocore, os, json, datetime
from typing import List, Dict

TS = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M")
REPORT_MD   = f"reports/report_{TS}.md"
REPORT_JSON = f"reports/report_{TS}.json"

region    = os.getenv("AWS_REGION", "us-east-1")
endpoint  = os.getenv("AWS_ENDPOINT_URL")          # set in LocalStack mode
mock_mode = os.getenv("MOCK_MODE", "").lower()     # 'demo' | 'localstack' | ''

def aws_client(svc):
    kwargs = {"region_name": region}
    if endpoint:
        kwargs["endpoint_url"] = endpoint
    return boto3.client(svc, **kwargs)

# ---------------- DEMO DATA ----------------
def demo_findings():
    return {
        "S3 Public Access": [{
            "service":"S3","bucket":"demo-public-bucket",
            "issue":"Public access detected",
            "details":"Bucket ACL grants public access, Public Access Block not configured"
        }],
        "S3 Default Encryption": [{
            "service":"S3","bucket":"demo-public-bucket",
            "issue":"Default encryption not enforced"
        }],
        "Security Groups Open Ports": [
            {"service":"EC2","security_group":"sg-12345","name":"demo-open-sg","issue":"Port 22 (SSH) open to the world"},
            {"service":"EC2","security_group":"sg-12345","name":"demo-open-sg","issue":"Port 80 (HTTP) open to the world"},
            {"service":"EC2","security_group":"sg-12345","name":"demo-open-sg","issue":"Port 443 (HTTPS) open to the world"},
        ],
        "IAM Old Access Keys": [{
            "service":"IAM","user":"demo-user","access_key_id":"AKIA...DEMO",
            "issue":"Access key older than 90 days (180 days)"
        }],
        "EBS Unencrypted": [{
            "service":"EC2","volume_id":"vol-abc123",
            "issue":"EBS volume not encrypted"
        }],
        "RDS Unencrypted": [{
            "service":"RDS","db_instance_identifier":"demo-db",
            "issue":"RDS storage not encrypted"
        }],
        "ECR Tag Immutability": [{
            "service":"ECR","repository":"demo-repo",
            "issue":"Image tag mutability enabled (should be IMMUTABLE)"
        }],
        "CloudTrail Enabled": [{
            "service":"CloudTrail","issue":"No trails found (CloudTrail not enabled)"
        }],
        "GuardDuty Enabled": [{
            "service":"GuardDuty","issue":"No detectors found (GuardDuty not enabled)"
        }],
    }

# --------------- REAL CHECKS ---------------
def check_s3_public(s3):
    out=[]; resp=s3.list_buckets()
    for b in resp.get('Buckets', []):
        name=b['Name']; public=False; reason=[]
        try:
            acl=s3.get_bucket_acl(Bucket=name)
            for g in acl.get('Grants', []):
                uri=g.get('Grantee',{}).get('URI','')
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    public=True; reason.append("Bucket ACL grants public access")
        except botocore.exceptions.ClientError: pass
        try:
            pol=s3.get_bucket_policy(Bucket=name)
            for st in json.loads(pol['Policy']).get('Stat
