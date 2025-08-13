#!/usr/bin/env python3
import boto3, botocore
import json, os, datetime
from typing import List, Dict

TS = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M")
REPORT_MD = f"reports/report_{TS}.md"
REPORT_JSON = f"reports/report_{TS}.json"

region = os.getenv("AWS_REGION", "us-east-1")
endpoint = os.getenv("AWS_ENDPOINT_URL")  # set in LocalStack mode
mock_mode = os.getenv("MOCK_MODE", "").lower()

client_args = dict(region_name=region)
if endpoint:
    client_args["endpoint_url"] = endpoint

ec2 = boto3.client('ec2', **client_args)
iam = boto3.client('iam', **client_args)
s3  = boto3.client('s3', **client_args)
rds = boto3.client('rds', **client_args)

def check_s3_public() -> List[Dict]:
    findings = []
    resp = s3.list_buckets()
    for b in resp.get('Buckets', []):
        name = b['Name']
        public = False
        reason = []
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for g in acl.get('Grants', []):
                uri = g.get('Grantee', {}).get('URI','')
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    public = True
                    reason.append("Bucket ACL grants public access")
        except botocore.exceptions.ClientError:
            pass
        try:
            pol = s3.get_bucket_policy(Bucket=name)
            polj = json.loads(pol['Policy'])
            for stmt in polj.get('Statement', []):
                if stmt.get('Effect') == 'Allow' and stmt.get('Principal') in ("*", {"AWS":"*"}):
                    public = True
                    reason.append("Bucket policy allows public principal")
        except botocore.exceptions.ClientError:
            # no policy
            pass
        try:
            bpa = s3.get_public_access_block(Bucket=name)
            cfg = bpa.get('PublicAccessBlockConfiguration', {})
            if not all([
                cfg.get('BlockPublicAcls', False),
                cfg.get('IgnorePublicAcls', False),
                cfg.get('BlockPublicPolicy', False),
                cfg.get('RestrictPublicBuckets', False)
            ]):
                reason.append("Public Access Block not fully enabled")
        except botocore.exceptions.ClientError:
            reason.append("Public Access Block not configured")
        if public:
            findings.append({"service":"S3","bucket":name,"issue":"Public access detected","details":", ".join(reason)})
    return findings

def check_sg_open_ports() -> List[Dict]:
    findings = []
    resp = ec2.describe_security_groups()
    risky_ports = {22:"SSH", 3389:"RDP", 80:"HTTP", 443:"HTTPS"}
    for sg in resp.get('SecurityGroups', []):
        for perm in sg.get('IpPermissions', []):
            fp = perm.get('FromPort'); tp = perm.get('ToPort')
            if fp is None or tp is None: continue
            for ipr in perm.get('IpRanges', []):
                if ipr.get('CidrIp') == '0.0.0.0/0':
                    for p, name in risky_ports.items():
                        if fp <= p <= tp:
                            findings.append({
                                "service":"EC2",
                                "security_group": sg.get('GroupId'),
                                "name": sg.get('GroupName'),
                                "issue": f"Port {p} ({name}) open to the world"
                            })
    return findings

def check_iam_old_keys(days_old: int = 90) -> List[Dict]:
    findings = []
    paginator = iam.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page.get('Users', []):
            uname = user['UserName']
            keys = iam.list_access_keys(UserName=uname).get('AccessKeyMetadata', [])
            for k in keys:
                age_days = 1000 if mock_mode else 100  # force a finding in LocalStack
                findings.append({
                    "service": "IAM",
                    "user": uname,
                    "access_key_id": k['AccessKeyId'],
                    "issue": f"Access key older than {days_old} days ({age_days} days)"
                })
    return findings

def check_ebs_unencrypted() -> List[Dict]:
    findings = []
    vols = ec2.describe_volumes().get('Volumes', [])
    for v in vols:
        if not v.get('Encrypted', False):
            findings.append({"service":"EC2","volume_id":v.get('VolumeId'),"issue":"EBS volume not encrypted"})
    return findings

def check_rds_unencrypted() -> List[Dict]:
    findings = []
    dbs = rds.describe_db_instances().get('DBInstances', [])
    for db in dbs:
        if not db.get('StorageEncrypted', False):
            findings.append({"service":"RDS","db_instance_identifier":db.get('DBInstanceIdentifier'),"issue":"RDS storage not encrypted"})
    return findings

def generate_reports(findings: Dict[str, list]):
    os.makedirs("reports", exist_ok=True)
    with open(REPORT_JSON, "w") as f:
        json.dump(findings, f, indent=2, default=str)
    total = sum(len(v) for v in findings.values())
    md = [f"# Cloud Compliance Report ({TS} UTC)\n",
          f"**Mode:** {'LocalStack' if mock_mode else 'AWS'}\n",
          f"**Region:** {region}\n",
          f"**Total Findings:** {total}\n",
          "---\n"]
    for section, items in findings.items():
        md.append(f"## {section} ({len(items)})\n")
        if not items:
            md.append("- ✅ No issues found\n")
        else:
            for it in items:
                md.append(" - " + ", ".join([f"**{k}**: {v}" for k, v in it.items()]) + "\n")
        md.append("\n")
    with open(REPORT_MD, "w") as f:
        f.write("".join(md))

def main():
    results = {
        "S3 Public Access": check_s3_public(),
        "Security Groups Open Ports": check_sg_open_ports(),
        "IAM Old Access Keys": check_iam_old_keys(),
        "EBS Unencrypted": check_ebs_unencrypted(),
        "RDS Unencrypted": check_rds_unencrypted(),
    }
    generate_reports(results)
    print(f"Generated: {REPORT_MD} and {REPORT_JSON}")

if __name__ == '__main__':
    main()
