# UniVex — Cloud Security Guide

> Author: BitR1FT

This guide covers configuring UniVex to scan AWS, Azure, and GCP environments for security misconfigurations, IAM privilege escalation paths, exposed resources, and compliance gaps.

---

## Table of Contents

1. [Overview](#1-overview)
2. [AWS Security Scanning](#2-aws-security-scanning)
3. [Azure Security Scanning](#3-azure-security-scanning)
4. [Google Cloud (GCP) Scanning](#4-google-cloud-gcp-scanning)
5. [Container & Kubernetes Security](#5-container--kubernetes-security)
6. [Cloud Scan Workflow](#6-cloud-scan-workflow)
7. [Interpreting Results](#7-interpreting-results)
8. [Remediation Guidance](#8-remediation-guidance)

---

## 1. Overview

UniVex v1.0.0 includes a dedicated cloud security module with 19 tools across three providers:

| Provider | Tools | Coverage |
|----------|-------|----------|
| **AWS** | 6 | S3, IAM, Security Groups, CloudTrail, RDS, Lambda |
| **Azure** | 4 | Storage, ARM, RBAC, Key Vault |
| **GCP** | 3 | Cloud Storage, IAM, Compute |
| **Containers** | 3 | Docker, docker-compose, image scanning |
| **Kubernetes** | 3 | RBAC, Pod Security, Secrets, Network Policies |

---

## 2. AWS Security Scanning

### Prerequisites

1. Create a dedicated IAM user or role for UniVex with read-only permissions
2. Attach the `SecurityAudit` managed policy (AWS-managed, read-only)
3. Generate access keys or use instance role / OIDC

### Configuration

```bash
# Add to .env or pass as environment variables
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1

# For multi-region scanning
AWS_SCAN_REGIONS=us-east-1,eu-west-1,ap-southeast-1
```

### Minimum IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:ListAllMyBuckets",
        "iam:ListUsers",
        "iam:ListPolicies",
        "iam:GetPolicyVersion",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:GenerateCredentialReport",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeVpcs",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "rds:DescribeDBInstances",
        "lambda:ListFunctions",
        "lambda:GetPolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

### Running AWS Scans

```bash
# Via API
curl -X POST http://localhost:8000/api/agent/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "Scan my AWS environment for security issues"}'

# Available tools (call directly via agent)
# - scan_s3_buckets          — Public bucket detection, ACL analysis
# - scan_iam_privileges      — Admin users, stale keys, privilege escalation
# - scan_security_groups     — 0.0.0.0/0 inbound rules, unrestricted SSH/RDP
# - check_cloudtrail         — Logging gaps, encryption status
# - scan_rds_instances       — Public access, encryption at rest
# - scan_lambda_functions    — Public function policies, outdated runtimes
```

### AWS Checks

| Check | Severity | CIS Benchmark |
|-------|----------|--------------|
| S3 bucket with public read/write | Critical | CIS 2.1.5 |
| IAM user with admin policy directly attached | High | CIS 1.16 |
| Security group with `0.0.0.0/0` on port 22 | High | CIS 5.2 |
| CloudTrail disabled or not logging | High | CIS 3.1 |
| RDS instance with `PubliclyAccessible=true` | Critical | CIS 2.3.2 |
| MFA not enabled for root account | Critical | CIS 1.5 |
| Access keys older than 90 days | Medium | CIS 1.14 |
| Lambda function with public resource policy | High | — |

---

## 3. Azure Security Scanning

### Prerequisites

1. Register an Azure AD application (service principal)
2. Assign `Security Reader` role at subscription level
3. Note: Application (client) ID, Directory (tenant) ID, and client secret

### Configuration

```bash
AZURE_CLIENT_ID=your-app-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_TENANT_ID=your-tenant-id
AZURE_SUBSCRIPTION_ID=your-subscription-id
```

### Running Azure Scans

```bash
# Available tools
# - scan_azure_storage       — Public blob containers, secure transfer
# - scan_azure_arm_policies  — Missing locks, policy compliance
# - scan_azure_rbac          — Owner role assignments, guest users
# - scan_azure_key_vault     — Soft delete, purge protection, access policies
```

### Azure Checks

| Check | Severity | Azure Policy |
|-------|----------|-------------|
| Storage account with public blob access | Critical | — |
| Storage account without HTTPS-only | High | — |
| Guest user with Owner/Contributor role | Critical | — |
| Subscription without resource locks | Medium | — |
| Key Vault without soft delete | High | — |
| Network Security Group with `*` inbound | High | — |
| SQL Server without Transparent Data Encryption | High | — |

---

## 4. Google Cloud (GCP) Scanning

### Prerequisites

1. Create a GCP service account
2. Assign `Security Reviewer` role (`roles/iam.securityReviewer`)
3. Download service account JSON key

### Configuration

```bash
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
GCP_PROJECT_ID=my-project-id
```

### Running GCP Scans

```bash
# Available tools
# - scan_gcp_storage         — Public buckets, uniform access, logging
# - scan_gcp_iam             — Primitive roles (Owner/Editor), service account keys
# - scan_gcp_compute         — Firewall rules, public IPs, OS Login
```

### GCP Checks

| Check | Severity | CIS GCP |
|-------|----------|---------|
| Cloud Storage bucket with allUsers access | Critical | 5.1 |
| IAM binding with `roles/owner` for external user | Critical | 1.1 |
| Firewall rule allowing `0.0.0.0/0` on SSH (22) | High | 3.6 |
| Service account key older than 90 days | Medium | 1.6 |
| Compute instance with default service account | Medium | 4.2 |
| Cloud SQL instance without SSL | High | 6.4 |
| GKE cluster without network policy | High | 7.11 |

---

## 5. Container & Kubernetes Security

### Docker Container Scanning

```bash
# Scan a running container
curl -X POST http://localhost:8000/api/agent/chat \
  -d '{"message": "Scan container univex-backend for security issues"}'

# Available checks:
# - Privileged mode enabled
# - Host network/PID/IPC namespaces shared
# - Writable root filesystem
# - Capabilities (SYS_ADMIN, NET_ADMIN, etc.)
# - Secrets in environment variables
# - Image running as root
```

### Kubernetes Cluster Scanning

```bash
# Configure kubeconfig
KUBECONFIG=/path/to/kubeconfig

# Available tools
# - scan_k8s_rbac            — ClusterRoleBindings with wildcard perms
# - scan_pod_security        — Privileged pods, hostPath mounts
# - scan_k8s_secrets         — Secrets in env vars, configmaps
# - scan_network_policies    — Missing network segmentation
```

### Kubernetes Checks

| Check | Severity | CIS K8s |
|-------|----------|---------|
| ClusterRoleBinding with `*` resources + verbs | Critical | 5.1.1 |
| Pod with `privileged: true` | Critical | 5.2.2 |
| Pod mounting `/etc/kubernetes` hostPath | Critical | 5.2.6 |
| Secret stored in ConfigMap (plaintext) | High | 5.4.1 |
| No NetworkPolicy for namespace | Medium | 5.3.2 |
| Container running as root | Medium | 5.2.7 |
| Container without resource limits | Low | 5.2.11 |

---

## 6. Cloud Scan Workflow

### Single-Provider Scan

```
User → Chat: "Scan my AWS account"
Agent → Planner: decompose into sub-tasks
   scan_s3_buckets
   scan_iam_privileges
   scan_security_groups
   check_cloudtrail
   scan_rds_instances
   scan_lambda_functions
Agent → Aggregator: collect + deduplicate findings
Agent → Report: generate cloud security report
```

### Campaign: Multi-Account Scan

```bash
# Create a multi-account campaign
curl -X POST http://localhost:8000/api/campaigns \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Q1 Cloud Security Audit",
    "type": "cloud",
    "targets": [
      {"type": "aws", "account_id": "123456789012", "regions": ["us-east-1"]},
      {"type": "azure", "subscription_id": "sub-id"},
      {"type": "gcp", "project_id": "my-project"}
    ],
    "tools": ["scan_s3_buckets", "scan_iam_privileges", "scan_azure_storage"],
    "schedule": {"type": "once"}
  }'
```

---

## 7. Interpreting Results

Cloud scan results are returned as structured findings:

```json
{
  "id": "uuid",
  "severity": "CRITICAL",
  "type": "s3_public_bucket",
  "title": "S3 bucket 'my-data' allows public read access",
  "resource": "arn:aws:s3:::my-data",
  "provider": "aws",
  "region": "us-east-1",
  "evidence": {
    "acl": "public-read",
    "policy": "...",
    "public_access_block": null
  },
  "cis_benchmark": "2.1.5",
  "remediation": "Enable S3 Block Public Access and remove public ACLs",
  "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"]
}
```

---

## 8. Remediation Guidance

### AWS Remediation

```bash
# Block S3 public access
aws s3api put-public-access-block \
  --bucket BUCKET_NAME \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Restrict security group
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxx \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Enable CloudTrail
aws cloudtrail create-trail \
  --name univex-audit-trail \
  --s3-bucket-name my-cloudtrail-bucket \
  --is-multi-region-trail
aws cloudtrail start-logging --name univex-audit-trail
```

### Azure Remediation

```bash
# Disable public blob access on storage account
az storage account update \
  --name mystorageaccount \
  --resource-group myRG \
  --allow-blob-public-access false

# Enable HTTPS-only
az storage account update \
  --name mystorageaccount \
  --resource-group myRG \
  --https-only true
```

### GCP Remediation

```bash
# Remove public access from Cloud Storage bucket
gsutil iam ch -d allUsers gs://my-bucket
gsutil iam ch -d allAuthenticatedUsers gs://my-bucket

# Remove overly permissive firewall rule
gcloud compute firewall-rules delete allow-all-ssh
```

---

*UniVex v1.0.0 — Cloud Security Guide | BitR1FT*
