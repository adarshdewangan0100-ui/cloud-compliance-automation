# cloud-compliance-automation

I’ve built a lightweight cloud compliance pipeline that runs in GitHub Actions and produces a clear report of common AWS risks. It checks things like public S3 access, missing default encryption, open Security Groups, old IAM keys, unencrypted EBS/RDS, CloudTrail/GuardDuty status, and ECR tag immutability.
The workflow can run in a demo mode (no credentials), against a sandbox (LocalStack), or in your AWS account using a read-only IAM role. You get both a human-readable Markdown report and a JSON file that can feed dashboards or tickets.

What the report shows
Summary: total findings by category

S3: buckets with public ACL/policy; buckets missing default encryption

Network: Security Groups with 0.0.0.0/0 on risky ports (22/3389/80/443)

IAM: access keys older than policy (e.g., 90 days)

Storage & DB: EBS and RDS volumes/instances without encryption

Audit & Threat: CloudTrail/ GuardDuty not enabled

Container Registry: ECR repositories that allow mutable tags

Each item includes the resource id + a plain-English description so remediation is obvious.

How it runs (options)
Demo mode (what you saw today): zero credentials, generates realistic sample findings to preview the workflow and report format.

LocalStack mode: runs against an AWS emulator (no cloud costs) for a fuller end-to-end demo.

Real AWS mode (recommended for assessments): runs in your account with a read-only IAM role (ideally via GitHub OIDC, so no static keys). Nothing leaves your account—artifacts are stored in your repo.

Deliverables I provide
GitHub repo with the workflow + scanner, wired for your environment

A baseline compliance report (MD + JSON) and a prioritized remediation plan

(Optional) Implementation of fixes: S3 encryption, SG lockdown, enable CloudTrail/GuardDuty, ECR tag immutability, key rotation, etc.

(Optional) Quality-of-life add-ons: Slack/Email alerts, scheduled runs, severity scoring, ticket auto-creation, Trivy container scans, policy-as-code (e.g., OPA/Conftest).

Engagement steps
20–30 min setup call

I create a minimal read-only IAM role (or use your existing one)

Run baseline scan → deliver the report

Walkthrough (30–45 min) with quick wins & risk ranking

Remediation sprint(s) and re-scan to show risk reduction

Costs & security
No costs for demo/LocalStack.

For real runs, cloud costs are minimal and billed to your AWS account.

Access is read-only, preferably via OIDC (no long-lived secrets).

If you want, I can also:

add a summary table with severity badges at the top of the Markdown report (looks great in screenshots), and

include a Trivy image scan job for ECR images.

Say the word and I’ll drop those upgrades into your repo next.
