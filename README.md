---
title: "Williams InfoSec Cloud Security Terraform Modules"
description: "Enterprise-grade IaC for multi-cloud security hardening (AWS, Azure, GCP)"
author: "Ola Williams, Williams InfoSec LLC"
version: "1.0.0"
date: "2026-06-10"
---

# Cloud Security Terraform Module Library

**Author:** Ola Williams | **Firm:** Williams InfoSec LLC | **Website:** [williamsinfosec.com](https://williamsinfosec.com)

---

## 📋 Overview

A **production-ready, compliance-aligned Terraform module library** for hardening cloud security postures across AWS, Azure, and GCP. Each module is designed for independent use or composition into larger security automation workflows.

### What This Library Delivers

✅ **Immediate-value remediations** (network hardening, logging enablement)  
✅ **Compliance automation** mapped to NIST 800-53, SOC 2, HIPAA, ISO 27001, FedRAMP  
✅ **Multi-cloud parity** (AWS Security Groups ↔ Azure NSGs ↔ GCP Firewalls)  
✅ **Continuous monitoring** integration (CloudWatch, Sentinel, SCC)  
✅ **Pre-change state snapshots** for safe rollback  
✅ **Zero-trust ready** (least-privilege, explicit allow lists, deny-by-default patterns)

---

## 🏗️ Architecture

### Module Structure

```
.
├── main.tf                              # Root module (provider config, module orchestration)
├── aws-network-hardening.tf             # AWS: Security Group hardening + VPC Flow Logs
├── azure-nsg-hardening.tf               # Azure: NSG governance + flow log centralization
├── gcp-firewall-hardening.tf            # GCP: VPC firewall + SCC integration + rule logging
│
├── modules/
│   ├── aws-network-hardening/           # AWS module source (reusable)
│   ├── azure-nsg-hardening/             # Azure module source (reusable)
│   ├── gcp-firewall-hardening/          # GCP module source (reusable)
│   ├── compliance-automation/           # Policy-as-Code, continuous monitoring
│   └── azure-identity-hardening/        # Azure PIM, RBAC governance
│
├── environments/
│   ├── dev.tfvars                       # Dev-specific overrides
│   ├── staging.tfvars                   # Staging-specific overrides
│   └── prod.tfvars                      # Production (restricted, sensit secrets)
│
├── examples/
│   ├── aws-example.tf                   # Minimal AWS deployment
│   ├── azure-example.tf                 # Minimal Azure deployment
│   └── gcp-example.tf                   # Minimal GCP deployment
│
├── README.md                             # This file
├── COMPLIANCE.md                         # Detailed compliance mappings
├── CHANGELOG.md                          # Version history
└── .gitignore                            # Exclude secrets, plan files, .tfstate
```

---

## 🚀 Quick Start

### Prerequisites

- **Terraform** ≥ 1.4
- **AWS CLI** v2 (for AWS provider) or **Azure CLI** v2.40+ (for Azure) or **gcloud SDK** ≥ 470.0.0 (for GCP)
- **Cloud credentials** configured locally (AWS profiles, Azure login, GCP auth)
- **Terraform state backend** configured (S3, Azure Storage, GCS, or local for dev)

### 1. Clone or Download

```bash
git clone https://github.com/williamsinfosec-dev/social-media.git
cd social-media/terraform-modules

# Or download as ZIP from GitHub releases
```

### 2. Initialize Terraform

```bash
# Initialize with all required providers
terraform init

# Or specify a backend:
# terraform init -backend-config="bucket=my-terraform-state" \
#                 -backend-config="key=cloud-security/terraform.tfstate" \
#                 -backend-config="region=us-east-1"
```

### 3. Configure Variables

Create `environments/prod.tfvars`:

```hcl
# Basic
cloud_provider  = "aws"  # or "azure" or "gcp"
environment     = "prod"
project_name    = "acme-corp"
region          = "us-east-1"

# Security hardening
block_public_access_rules = true
sensitive_ports           = [22, 3389, 5984, 9200, 27017, 6379]
allowed_management_cidrs  = ["10.0.0.0/8", "203.0.113.0/24"]  # Your bastion IPs

# Compliance
compliance_framework      = "nist-800-53"  # or "hipaa", "soc2", "iso27001"
enable_continuous_monitoring = true
enforce_encryption        = true

# Backup/audit
backup_bucket = "acme-corp-hardening-backups"

# Optional: SIEM integration (Azure)
# siem_workspace_id = "/subscriptions/xxx/resourceGroups/yyy/providers/Microsoft.OperationalInsights/workspaces/zzz"
```

### 4. Plan Changes

```bash
# Dry-run: show what will be created/modified
terraform plan -var-file="environments/prod.tfvars" -out=tfplan

# Review the plan carefully — check for:
# ✓ Correct regions, project names, resource counts
# ✓ No unintended rule overwrites
# ✓ Sensitive data not logged to stdout
```

### 5. Apply Safely

```bash
# Apply with saved plan (safer than direct apply)
terraform apply tfplan

# Alternative: direct apply with auto-approval (requires careful review first)
# terraform apply -var-file="environments/prod.tfvars" -auto-approve
```

### 6. Validate Results

```bash
# Show all outputs (resource IDs, compliance status, etc.)
terraform output -json | jq .

# Specific outputs
terraform output deployment_summary
terraform output remediation_status
```

---

## 📊 Compliance Mappings

### NIST 800-53 Rev. 5

| Control | Implementation | Module |
|---------|---|---|
| **AC-3** (Access Control) | Security groups restrict 0.0.0.0/0 on SSH/RDP | aws-network-hardening, azure-nsg-hardening, gcp-firewall-hardening |
| **AC-4** (Data Flow Enforcement) | Flow logs capture network traffic | aws-network-hardening, azure-nsg-hardening, gcp-firewall-hardening |
| **CA-7** (Continuous Monitoring) | Cloud Config, Azure Policy, GCP SCC Premium | compliance-automation |
| **SA-3** (System Development Life Cycle) | Policy-as-Code in CI/CD | All modules |

### SOC 2 TSC (Trust Service Criteria)

| Criteria | Implementation | Module |
|---|---|---|
| **CC6.6** (Logical & Physical Access) | Restrict SSH/RDP to approved IPs | aws-network-hardening, azure-nsg-hardening, gcp-firewall-hardening |
| **CC6.7** (Boundary Protection) | VPC/VNet isolation, firewall rules | aws-network-hardening, azure-nsg-hardening, gcp-firewall-hardening |
| **CC7.2** (Logging & Monitoring) | Flow logs to SIEM, CloudWatch, Sentinel | aws-network-hardening, azure-nsg-hardening, gcp-firewall-hardening |
| **CC1.4** (Governance & Management) | Terraform state versioning, change tracking | All modules |

### HIPAA & HITRUST CSF

| Requirement | Implementation | Module |
|---|---|---|
| **§164.312(a)(1)** (Network Access Controls) | Firewall rules, NSGs restrict unauthenticated access | aws-network-hardening, azure-nsg-hardening, gcp-firewall-hardening |
| **§164.312(b)** (Audit Controls) | Flow logs, centralized logging | aws-network-hardening, azure-nsg-hardening, gcp-firewall-hardening |
| **A.8.20, A.8.21** (ISO 27001) | User access management, restrict access | aws-network-hardening, azure-nsg-hardening, gcp-firewall-hardening |

### FedRAMP Moderate

| Requirement | Implementation | Module |
|---|---|---|
| **AC-3, AC-4** | Access control, data flow | aws-network-hardening, azure-nsg-hardening, gcp-firewall-hardening |
| **SI-4** (Information System Monitoring) | Flow logs, continuous monitoring | aws-network-hardening, azure-nsg-hardening, gcp-firewall-hardening |

---

## 🔐 Security Best Practices (Built-In)

### 1. **Least-Privilege Access**

- Default: DENY all ingress
- Explicit: ALLOW only specified CIDR blocks on sensitive ports
- Pattern: Bastion-based access (not direct public routes)

```hcl
# ✓ Good: Restrict to known bastion IPs
allowed_management_cidrs = ["10.0.1.0/24"]  # Internal bastion subnet

# ✗ Bad: Left as empty (no rules applied for safety)
allowed_management_cidrs = []  # Safeguard prevents accidental rules

# ✗ Very Bad: Not to be used
allowed_management_cidrs = ["0.0.0.0/0"]  # This will be rejected
```

### 2. **State Snapshots Before Changes**

Each module creates backups of discovered resources before applying remediation:

```hcl
# AWS: S3 backups
terraform apply → backup_bucket/aws-hardening/2026-06-10T14-30-45Z/firewall-rules.json

# Azure: Can be added
terraform apply → similar structure in Blob storage

# GCP: GCS backups
terraform apply → backup_bucket/gcp-hardening/2026-06-10T14-30-45Z/
```

Enables **rollback without manual recovery**:

```bash
# Restore from backup if needed
aws s3 cp s3://backup-bucket/aws-hardening/2026-06-10T14-30-45Z/ /tmp/backup/ --recursive
# Then review & re-apply with `no-op` configuration
```

### 3. **Continuous Compliance Scanning**

- AWS Config monitors rule drift
- Azure Policy enforces standards
- GCP SCC Premium detects exposures in real-time

```hcl
enable_continuous_monitoring = true
compliance_framework = "nist-800-53"
# → Auto-enabled Config Rules, Policy assignments, SCC findings
```

### 4. **Encryption by Default**

- S3 bucket backups: AES-256
- Azure Storage: TLS 1.2+
- GCS: Google-managed encryption
- Terraform state: Use encrypted backends

### 5. **Audit Logging**

All changes logged to:

- **AWS:** CloudTrail (API), VPC Flow Logs (network)
- **Azure:** Activity Log (API), NSG Flow Logs (network)
- **GCP:** Cloud Audit Logs (API), Firewall rule logs (network)

---

## 🛠️ Module Reference

### AWS Network Hardening

**File:** `aws-network-hardening.tf`

**Scope:**
- Discover all VPCs & Security Groups
- Enable VPC Flow Logs → CloudWatch
- Restrict SSH (22), RDP (3389), MongoDB (27017), Redis (6379) to approved CIDRs
- Create S3 backup bucket with versioning

**Inputs:**
```hcl
cloud_provider              = "aws"
block_public_access_rules  = true
allowed_management_cidrs   = ["10.0.1.0/24", "203.0.113.0/24"]
backup_bucket              = "my-backups"
```

**Outputs:**
```json
{
  "vpc_ids": ["vpc-12345", "vpc-67890"],
  "vpc_flow_logs_enabled": {
    "enabled": true,
    "log_group": "/aws/vpc/flowlogs/acme-corp",
    "vpc_count": 2
  },
  "remediation_applied": {
    "ssh_rules": 3,
    "rdp_rules": 3,
    "mongodb_rules": 3,
    "redis_rules": 3
  }
}
```

---

### Azure NSG Hardening

**File:** `azure-nsg-hardening.tf`

**Scope:**
- Discover all NSGs in subscription
- Enable NSG Flow Logs → Log Analytics
- Create security rules for SSH, RDP, MongoDB, Redis (restricted to approved CIDRs)
- Optional: Apply Azure Policy for governance

**Inputs:**
```hcl
cloud_provider           = "azure"
block_public_access_rules = true
allowed_management_cidrs = ["10.0.1.0/24"]
siem_workspace_id        = "/subscriptions/.../workspaces/my-workspace"
```

**Outputs:**
```json
{
  "nsg_count": 12,
  "nsg_flow_logs_enabled": {
    "enabled": true,
    "log_analytics_workspace": "/subscriptions/.../workspaces/my-workspace",
    "retention_days": 30
  },
  "nsg_security_rules_created": {
    "ssh_rules": 2,
    "rdp_rules": 2,
    "mongodb_rules": 2,
    "redis_rules": 2
  }
}
```

---

### GCP Firewall Hardening

**File:** `gcp-firewall-hardening.tf`

**Scope:**
- Discover firewall rules exposing sensitive ports to 0.0.0.0/0
- Enable firewall rule logging → Cloud Logging
- Create SCC custom module for continuous findings
- Restrict SSH, RDP, MongoDB, Redis to approved CIDRs

**Inputs:**
```hcl
cloud_provider         = "gcp"
block_public_access_rules = true
allowed_management_cidrs  = ["10.0.1.0/24"]
gcp_organization_id      = "123456789"
enable_scc_premium       = true
```

**Outputs:**
```json
{
  "firewall_rules_remediated": {
    "ssh_rules": 1,
    "rdp_rules": 1,
    "logging_enabled": 1
  },
  "scc_custom_module": {
    "name": "acme-corp-firewall-exposure",
    "id": "projects/123/securityHealthChecks/..."
  },
  "firewall_logging_enabled": {
    "enabled": true,
    "sink_name": "acme-corp-firewall-logs"
  }
}
```

---

## 📈 Common Use Cases

### Use Case 1: NIST 800-53 AC-3/AC-4 Hardening (FinTech Startup)

**Goal:** Restrict network access to sensitive ports (AC-3), enforce flow logging (AC-4)

**Configuration:**
```hcl
cloud_provider               = "aws"
compliance_framework         = "nist-800-53"
block_public_access_rules    = true
allowed_management_cidrs     = ["203.0.113.0/25"]  # Bastion subnet
enable_continuous_monitoring = true
```

**Outcome:**
- ✓ SSH/RDP rules restricted to bastion CIDR only
- ✓ VPC Flow Logs enabled across all VPCs
- ✓ Config Rules monitor for drift
- ✓ Audit trail in CloudTrail + VPC Flow Logs

---

### Use Case 2: HIPAA Compliance for SaaS Database

**Goal:** Network access controls, audit logging, encryption

**Configuration:**
```hcl
cloud_provider           = "azure"
compliance_framework     = "hipaa"
block_public_access_rules = true
allowed_management_cidrs  = ["10.0.1.0/24"]
enable_nsg_logging        = true
siem_workspace_id         = "/subscriptions/xxx/resourceGroups/yyy/providers/Microsoft.OperationalInsights/workspaces/zzz"
enforce_encryption        = true
```

**Outcome:**
- ✓ MongoDB (27017) restricted to internal app servers only
- ✓ NSG Flow Logs ingested to Sentinel for audit
- ✓ All backups encrypted at-rest & in-transit
- ✓ Compliance report maps to HIPAA §164.312(a)(1), §164.312(b)

---

### Use Case 3: Multi-Cloud Security Posture (Enterprise)

**Goal:** Consistent hardening across AWS + Azure + GCP

**Configuration:** Run three separate deployments (one per cloud)

```bash
# AWS
terraform apply -var-file="environments/prod-aws.tfvars"

# Azure
terraform apply -var-file="environments/prod-azure.tfvars"

# GCP
terraform apply -var-file="environments/prod-gcp.tfvars"
```

**Outcome:**
- ✓ Same security rules enforced across all clouds
- ✓ Centralized logging (Sentinel, CloudWatch, Cloud Logging)
- ✓ Unified compliance dashboard

---

## 🔄 Change Management & Rollback

### Workflow: Safe Hardening with Approval Gate

**Step 1: Plan (audit-only)**
```bash
terraform plan -var-file="prod.tfvars" -out=tfplan
# Review: How many rules will be modified? Which NSGs? Any unexpected changes?
```

**Step 2: Snapshot (pre-change backup)**
```bash
# Modules automatically create backups in S3/GCS/Blob
terraform apply -var-file="prod.tfvars" -target=aws_s3_bucket.backup_bucket -auto-approve
```

**Step 3: Apply with Approval**
```bash
# After stakeholder review (CISO, Network team), apply full configuration
terraform apply tfplan

# Email approval is still recommended for compliance audit trail
```

**Step 4: Validate**
```bash
terraform output remediation_status
# "Hardening rules applied: 12 total"

# Check SIEM/console for log ingestion
aws logs tail /aws/vpc/flowlogs/acme-corp --follow
```

**Step 5: Rollback (if needed)**

If issues arise, restore from backup:

```bash
# Restore snapshot
aws s3 cp s3://backup-bucket/aws-hardening/2026-06-10T14-30-45Z/firewall-rules.json /tmp/

# Re-apply with `block_public_access_rules = false` (no-op)
terraform apply -var-file="prod.tfvars" -var block_public_access_rules=false

# Then manually re-enable after investigation
```

---

## 🎯 Deployment Checklist

Before pushing to production:

- [ ] **Credentials:** AWS/Azure/GCP keys configured locally or via OIDC
- [ ] **Terraform version:** `terraform --version` shows ≥ 1.4
- [ ] **Plan reviewed:** `terraform plan` output checked for correctness
- [ ] **Bastion IPs:** `allowed_management_cidrs` set to actual jump host subnet(s)
- [ ] **Compliance framework:** Set to your primary requirement (NIST/HIPAA/SOC2)
- [ ] **State backend:** Remote backend configured (S3/Blob/GCS, not local)
- [ ] **Approval:** CTO/CISO/Network team sign-off obtained
- [ ] **Backups:** Backup bucket created & versioning enabled
- [ ] **Monitoring:** SIEM workspace/Log Analytics workspace deployed
- [ ] **Alerting:** CloudWatch/Sentinel alerts configured for suspicious activity

---

## 🆘 Troubleshooting

### Issue: "allowed_management_cidrs is empty" safeguard preventing rule creation

**Solution:**
```hcl
# This is intentional! Set approved management IPs:
allowed_management_cidrs = ["203.0.113.0/24"]  # Actual bastion CIDR
```

### Issue: "permission denied" on NSG updates

**Solution:**
```bash
# Ensure role has Microsoft.Network/networkSecurityGroups/* permissions
az role assignment create \
  --assignee <user/service-principal> \
  --role "Network Contributor"
```

### Issue: Terraform state lock conflict

**Solution:**
```bash
# List locks
terraform force-unlock <LOCK_ID>

# Or wait for previous operation to complete (5-10 min typical)
```

### Issue: GCP SCC findings not showing up

**Solution:**
```bash
# Ensure SCC Premium is activated
gcloud scc manage services update scc_premium --enable --organization=123456789

# Check Custom Module
gcloud scc custom-modules list --organization=123456789
```

---

## 📚 References & Further Reading

- **NIST 800-53 Rev. 5:** https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
- **AWS Security Best Practices:** https://docs.aws.amazon.com/security/
- **Azure Security Baselines:** https://learn.microsoft.com/en-us/security/benchmark/azure/
- **GCP Security Command Center:** https://cloud.google.com/security-command-center/docs
- **Terraform Docs:** https://www.terraform.io/docs
- **Williams InfoSec Blog:** https://williamsinfosec.com/blog

---

## 🤝 Support & Consulting

**For production deployments, audits, or custom configurations:**

📧 **Email:** olamide@williamsinfosec.com  
🌐 **Website:** https://williamsinfosec.com  
📞 **Upwork:** [Williams InfoSec Profile](https://upwork.com)

---

## 📄 License

© 2026 Williams InfoSec LLC. All rights reserved.

This code is provided as-is for educational and consulting purposes. Use at your own risk in production environments. Compliance responsibility remains with the organization deploying these modules.

---

**Version:** 1.0.0 | **Last Updated:** 2026-06-10 | **Maintained By:** Ola Williams
