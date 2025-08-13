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
            for st in json.loads(pol['Policy']).get('Statement', []):
                if st.get('Effect')=='Allow' and st.get('Principal') in ("*", {"AWS":"*"}):
                    public=True; reason.append("Bucket policy allows public principal")
        except botocore.exceptions.ClientError: pass
        try:
            bpa=s3.get_public_access_block(Bucket=name)
            cfg=bpa.get('PublicAccessBlockConfiguration', {})
            if not all([cfg.get('BlockPublicAcls',False),cfg.get('IgnorePublicAcls',False),
                        cfg.get('BlockPublicPolicy',False),cfg.get('RestrictPublicBuckets',False)]):
                reason.append("Public Access Block not fully enabled")
        except botocore.exceptions.ClientError:
            reason.append("Public Access Block not configured")
        if public: out.append({"service":"S3","bucket":name,"issue":"Public access detected","details":", ".join(reason)})
    return out

def check_s3_default_encryption(s3):
    out=[]; resp=s3.list_buckets()
    for b in resp.get('Buckets', []):
        name=b['Name']
        try:
            s3.get_bucket_encryption(Bucket=name)
        except botocore.exceptions.ClientError as e:
            code=e.response.get("Error",{}).get("Code")
            if code in ("ServerSideEncryptionConfigurationNotFoundError","NoSuchEncryptionConfiguration","InvalidRequest"):
                out.append({"service":"S3","bucket":name,"issue":"Default encryption not enforced"})
    return out

def check_sg_open_ports(ec2):
    out=[]; resp=ec2.describe_security_groups()
    risky={22:"SSH",3389:"RDP",80:"HTTP",443:"HTTPS"}
    for sg in resp.get('SecurityGroups', []):
        for p in sg.get('IpPermissions', []):
            fp=p.get('FromPort'); tp=p.get('ToPort')
            if fp is None or tp is None: continue
            for r in p.get('IpRanges', []):
                if r.get('CidrIp')=='0.0.0.0/0':
                    for port,name in risky.items():
                        if fp<=port<=tp:
                            out.append({"service":"EC2","security_group":sg.get('GroupId'),
                                        "name":sg.get('GroupName'),
                                        "issue":f"Port {port} ({name}) open to the world"})
    return out

def check_iam_old_keys(iam, days_old=90):
    out=[]; pag=iam.get_paginator('list_users')
    for page in pag.paginate():
        for u in page.get('Users', []):
            uname=u['UserName']
            for k in iam.list_access_keys(UserName=uname).get('AccessKeyMetadata', []):
                out.append({"service":"IAM","user":uname,"access_key_id":k['AccessKeyId'],
                            "issue":f"Access key older than {days_old} days (100+ days)"})
    return out

def check_ebs_unencrypted(ec2):
    return [{"service":"EC2","volume_id":v.get('VolumeId'),"issue":"EBS volume not encrypted"}
            for v in ec2.describe_volumes().get('Volumes', []) if not v.get('Encrypted', False)]

def check_rds_unencrypted(rds):
    return [{"service":"RDS","db_instance_identifier":db.get('DBInstanceIdentifier'),"issue":"RDS storage not encrypted"}
            for db in rds.describe_db_instances().get('DBInstances', []) if not db.get('StorageEncrypted', False)]

def check_ecr_tag_immutability(ecr):
    out=[]
    try:
        for r in ecr.describe_repositories().get('repositories', []):
            if r.get('imageTagMutability','MUTABLE')!='IMMUTABLE':
                out.append({"service":"ECR","repository":r.get('repositoryName'),
                            "issue":"Image tag mutability enabled (should be IMMUTABLE)"})
    except Exception:
        out.append({"service":"ECR","issue":"Unable to check repositories (service not available)"})
    return out

def check_cloudtrail_enabled(ct):
    try:
        if not ct.describe_trails().get('trailList', []):
            return [{"service":"CloudTrail","issue":"No trails found (CloudTrail not enabled)"}]
    except Exception:
        return [{"service":"CloudTrail","issue":"CloudTrail not available"}]
    return []

def check_guardduty_enabled(gd):
    try:
        if not gd.list_detectors().get('DetectorIds', []):
            return [{"service":"GuardDuty","issue":"No detectors found (GuardDuty not enabled)"}]
    except Exception:
        return [{"service":"GuardDuty","issue":"GuardDuty not available"}]
    return []

def write_reports(findings: Dict[str,list]):
    os.makedirs("reports", exist_ok=True)
    with open(REPORT_JSON,"w") as f: json.dump(findings,f,indent=2,default=str)
    total=sum(len(v) for v in findings.values())
    md=[f"# Cloud Compliance Report ({TS} UTC)\n",
        f"**Mode:** {mock_mode or 'aws'}\n",
        f"**Region:** {region}\n",
        f"**Total Findings:** {total}\n","---\n"]
    for section,items in findings.items():
        md.append(f"## {section} ({len(items)})\n")
        if not items: md.append("- ✅ No issues found\n")
        else:
            for it in items:
                md.append(" - " + ", ".join([f"**{k}**: {v}" for k,v in it.items()]) + "\n")
        md.append("\n")
    with open(REPORT_MD,"w") as f: f.write("".join(md))

def main():
    # ---- IMPORTANT: demo short-circuit BEFORE any AWS calls ----
    if mock_mode == "demo":
        write_reports(demo_findings())
        print("Generated DEMO reports.")
        return

    # LocalStack or AWS
    s3=aws_client('s3'); ec2=aws_client('ec2'); iam=aws_client('iam'); rds=aws_client('rds')
    ecr=aws_client('ecr'); ct=aws_client('cloudtrail'); gd=aws_client('guardduty')
    findings = {
        "S3 Public Access":            check_s3_public(s3),
        "S3 Default Encryption":       check_s3_default_encryption(s3),
        "Security Groups Open Ports":  check_sg_open_ports(ec2),
        "IAM Old Access Keys":         check_iam_old_keys(iam),
        "EBS Unencrypted":             check_ebs_unencrypted(ec2),
        "RDS Unencrypted":             check_rds_unencrypted(rds),
        "ECR Tag Immutability":        check_ecr_tag_immutability(ecr),
        "CloudTrail Enabled":          check_cloudtrail_enabled(ct),
        "GuardDuty Enabled":           check_guardduty_enabled(gd),
    }
    write_reports(findings)
    print("Generated reports.")

if __name__ == "__main__":
    main()
