# cloud-compliance-automation

# Context
The org needed to operationalize security checks mapped to common controls (e.g., C5/NIST-like), with evidence for audits.

# Problem

Manual security checks were inconsistent.

No central view of violations across accounts.

Vulnerable images reached staging.

# Constraints

Work across multiple AWS accounts.

Produce simple evidence for auditors.

Minimal friction for dev teams.

# Solution

Built a Python CLI to scan AWS (boto3) for misconfigs: public S3, wide-open SGs, old IAM keys, unencrypted EBS/RDS.

Added container image scanning (Trivy) to CI with policy gates.

Generated HTML/Markdown compliance reports with pass/fail and remediation steps.

Scheduled runs; alerts to Slack on critical findings.

# Architecture (high level)
Scheduler → Python scanners (AWS APIs) + CI image scans → Findings DB/JSON → Report generator → Slack/email & artifact uploads.

# Outcomes (measurable)

🧯 High-risk misconfigs reduced by >70% in 4 weeks.

📜 Audit evidence generated on demand.

🚫 Vulnerable images blocked pre-deploy.

# My Role
Defined controls, wrote scanners, integrated Trivy gates, built reporting, aligned with engineering leads.

Artifacts to show

Sample compliance report (HTML/MD)

Trivy pipeline gate screenshot

CLI help output & example JSON
