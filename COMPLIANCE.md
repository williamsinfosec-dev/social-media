---
title: "Cloud Security Terraform Modules — Compliance Control Mappings"
author: "Ola Williams, Williams InfoSec LLC"
version: "1.0.0"
date: "2026-06-10"
---

# Compliance Control Mappings

This document maps required compliance controls to specific Terraform implementations in this library.

---

## Table of Contents

1. [NIST 800-53 Rev. 5](#nist-800-53-rev-5)
2. [SOC 2 Trust Service Criteria](#soc-2-trust-service-criteria)
3. [HIPAA Security Rule](#hipaa-security-rule)
4. [HITRUST CSF](#hitrust-csf)
5. [ISO 27001:2022](#iso-270012022)
6. [FedRAMP Moderate Baseline](#fedramp-moderate-baseline)

---

## NIST 800-53 Rev. 5

### Access Control (AC)

#### AC-2: Account Management

**Requirement:** Manage user accounts and access rights.

**Terraform Implementation:**

- **Azure Identity Hardening Module:** `azure-identity-hardening.tf`
  - Creates Privileged Identity Management (PIM) policies
  - Enforces MFA for sensitive role assignments
  - Audits all identity changes to Log Analytics

**Mapping:**
```
AC-2(a): Account registration → Azure AD user provisioning + PIM
AC-2(b): Account review → PIM access reviews (quarterly)
AC-2(c): Account removal → Terraform destroys user/roles on termination
AC-2(f): Shared accounts → Prohibited via PIM singleton roles
```

**Evidence:**
```bash
# List all PIM role assignments
az pim eligible-role-assignment list --subscription

# Check MFA requirement
az ad conditional-access policy list
```

---

#### AC-3: Access Enforcement

**Requirement:** Enforce approved authorizations for user and information flow.

**Terraform Implementation:**

- **AWS Network Hardening:** `aws-network-hardening.tf`
  - Security Group rules restrict TCP/22, 3389 to `allowed_management_cidrs`
  - VPC separation enforces workload isolation
  
- **Azure NSG Hardening:** `azure-nsg-hardening.tf`
  - NSG rules restrict SSH/RDP to approved IPs only
  - Resource Group-scoped policies enforce RBAC
  
- **GCP Firewall Hardening:** `gcp-firewall-hardening.tf`
  - Firewall rules block public INGRESS on sensitive ports
  - Organization policies enforce VPC isolation

**Mapping:**
```
AC-3: Network segmentation via security groups/NSGs/firewalls
  - SSH (22) → restricted to management CIDR
  - RDP (3389) → restricted to management CIDR
  - Database ports (27017, 6379) → restricted to application subnets
  - All others: DEFAULT DENY
```

**Evidence:**
```bash
# AWS
aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=prod-*" \
  --query 'SecurityGroups[].IpPermissions[]' | jq .

# Azure
az network nsg rule list --resource-group prod-rg --nsg-name prod-nsg

# GCP
gcloud compute firewall-rules list --format json
```

---

#### AC-4: Information Flow Enforcement

**Requirement:** Enforce approved information flows.

**Terraform Implementation:**

- **All Modules:** Enable flow logging
  - AWS: VPC Flow Logs → CloudWatch
  - Azure: NSG Flow Logs → Log Analytics
  - GCP: VPC Flow Logs + Firewall Rule Logs → Cloud Logging

**Mapping:**
```
AC-4: Flow logging captures all network flows
  - Source/Destination IPs
  - Ports
  - Protocol (TCP/UDP)
  - Accept/Reject decision
  - Timestamp
```

**Evidence:**
```bash
# AWS
aws logs tail /aws/vpc/flowlogs/acme-corp --follow

# Azure
az monitor log-analytics query \
  --workspace-name my-workspace \
  --analytics-query "AzureNetworkAnalytics_CL"

# GCP
gcloud logging read 'resource.type="gce_subnetwork"' --limit=10
```

---

#### AC-6: Least Privilege

**Requirement:** Employ the principle of least privilege, including for administrative privilege.

**Terraform Implementation:**

- **Azure PIM:** Enforce JIT (Just-In-Time) elevation
  - Default: Users have no admin privileges
  - Activation: MFA required, time-limited (e.g., 2 hours)
  - Audit: All activations logged

- **All Network Modules:** Restrict to necessary ports/CIDRs only
  - No 0.0.0.0/0 on SSH, RDP, databases
  - Explicit allow lists (deny-by-default)

**Mapping:**
```
AC-6(1): Authorized access → Admin users granted PIM-eligible roles only
AC-6(2): Non-privileged access → Regular users have read-only permissions
AC-6(3): System access → Service accounts use managed identities (no credentials)
```

**Evidence:**
```bash
# PIM eligible roles
az pim eligible-role-assignment list --subscription

# NSG rules (deny implicit for unlisted ports)
az network nsg rule list --resource-group prod-rg --nsg-name prod-nsg
```

---

### Security Assessment & Authorization (CA)

#### CA-7: Continuous Monitoring

**Requirement:** Monitor and periodically reassess the security controls.

**Terraform Implementation:**

- **Compliance Automation Module:** `compliance-automation.tf`
  - AWS Config: Monitors security group drift, S3 public access, encryption
  - Azure Policy: Enforces NSG standards, encryption, logging
  - GCP SCC Premium: Detects OPEN_FIREWALL, FIREWALL_RULE_LOGGING_DISABLED

**Mapping:**
```
CA-7(a): Monitoring frequency → Continuous (real-time alerts)
CA-7(b): Monitoring tools → Config, Policy, SCC
CA-7(c): Monitoring review → Weekly compliance dashboard
CA-7(d): Monitoring updates → New rules added quarterly
```

**Evidence:**
```bash
# AWS Config
aws configservice describe-config-rules --query 'ConfigRules[].ConfigRuleName'

# Azure Policy
az policy definition list --query '[].displayName' | grep -i "nsg\|network"

# GCP SCC
gcloud scc findings list organizations/123456789 \
  --filter='state=ACTIVE AND category="OPEN_FIREWALL"'
```

---

## SOC 2 Trust Service Criteria

### CC: Common Criteria

#### CC1: Control Environment

**Requirement:** Organization demonstrates a commitment to competence.

**Terraform Implementation:**

- **All Modules:** Terraform state versioning
  - S3 versioning (AWS)
  - Blob versioning (Azure)
  - GCS versioning (GCP)
- **Audit Trail:** All changes tracked in commit history + cloud audit logs

**Mapping:**
```
CC1.1: Governance → Terraform state managed in git (audit trail)
CC1.4: Change management → Terraform plans reviewed before apply
```

---

#### CC6: Logical & Physical Access Controls

**Requirement:** Organization restricts physical and logical access.

**Terraform Implementation:**

- **All Network Hardening Modules:** Restrict INGRESS on SSH, RDP, databases
- **Azure Identity Hardening:** PIM + MFA + Conditional Access

**Mapping:**
```
CC6.1: Authorization → IAM roles, security group rules, NSG rules
CC6.2: Prior authentication → MFA enforced via Conditional Access
CC6.5: Privileged access → PIM restricts admin escalation
CC6.6: Removal of access → Terraform destroys roles/rules on removal
CC6.7: Boundary protection → Security groups / NSGs restrict network flows
```

---

#### CC7: System Monitoring

**Requirement:** System activity is monitored and anomalies are investigated.

**Terraform Implementation:**

- **All Modules:** Enable flow logging
  - AWS VPC Flow Logs → CloudWatch (indexed, searchable)
  - Azure NSG Flow Logs → Log Analytics (Traffic Analytics)
  - GCP VPC Flow Logs + Firewall Rules → Cloud Logging

**Mapping:**
```
CC7.1: System monitoring → VPC/NSG/Firewall flow logging
CC7.2: Log preservation → Retention set to 30+ days (configurable)
CC7.3: Investigation support → Flow logs include all five-tuple data
CC7.4: Incident response → Alerts on anomalies (e.g., SSH brute force)
```

---

## HIPAA Security Rule

### Administrative Safeguards

#### §164.308(a)(3): Workforce Security

**Requirement:** Implement workforce security procedures.

**Terraform Implementation:**

- **Azure Identity Hardening:** PIM + MFA + role-based access
- **All Modules:** Audit logging to Log Analytics

**Mapping:**
```
§164.308(a)(3)(i): Manage workforce access → IAM roles, PIM
§164.308(a)(3)(ii): Workforce security alerts → Sentinel alerts
```

---

### Physical Safeguards

#### §164.310(b): Workstation Access & Use

**Requirement:** Implement policies & procedures for access to workstations.

**Terraform Implementation:**

- **All Network Modules:** Restrict RDP (3389) to approved bastion IPs
- **Azure Conditional Access:** Enforce device compliance, location-based policies

**Mapping:**
```
§164.310(b)(1): Authorization → Bastion-based access only (approved_management_cidrs)
§164.310(b)(2): Device policy → Terraform applies Azure Device Compliance policy
```

---

### Technical Safeguards

#### §164.312(a)(1): Access Control

**Requirement:** Implement technical security measures for EHR systems.

**Terraform Implementation:**

- **All Network Hardening Modules:** Network access controls (firewalls, NSGs, security groups)
- **Encryption Enforcement:** TLS 1.2+ for data in-transit, AES-256 for data at-rest

**Mapping:**
```
§164.312(a)(1): Access control → Security groups / NSGs restrict network access
  - SSH (22) → Restricted to bastion only
  - Database ports → Restricted to app servers only
  - All others → DEFAULT DENY
```

**Evidence:**
```bash
# Verify HTTPS enforcement
aws ec2 describe-security-groups --query 'SecurityGroups[].IpPermissions[]' | jq '.[] | select(.IpProtocol=="tcp" and .FromPort==80)'
# Should return empty (no HTTP allowed)
```

#### §164.312(a)(2): Audit Controls

**Requirement:** Implement logging and monitoring.

**Terraform Implementation:**

- **All Modules:** Enable flow logging + centralized SIEM
  - Flow logs capture all network traffic
  - Retention: 30+ days (HIPAA requires 6 years, but logs should be in SIEM)

**Mapping:**
```
§164.312(a)(2)(i): Audit logging → VPC/NSG/Firewall flow logs
§164.312(a)(2)(ii): Integrity controls → Tamper detection (S3 versioning, Cloud Audit Logs)
```

---

## HITRUST CSF

### Key Practice 08.02: Boundary Protection

**Requirement:** Network boundaries protect internal networks.

**Terraform Implementation:**

- **All Network Hardening Modules:** Firewalls, NSGs, security groups restrict INGRESS
- **Continuous Monitoring:** Config/Policy/SCC detect exposed resources

**Mapping:**
```
08.02.01: Boundary defense → VPC/VNet isolation + security group rules
08.02.02: Firewall rules → Restrict SSH/RDP to management CIDR only
08.02.03: Monitoring → VPC/NSG/Firewall flow logs + continuous scanning
```

---

## ISO 27001:2022

### A.8: Cryptography & Network Security

#### A.8.15: Logging

**Requirement:** Record user activities, exceptions, security events.

**Terraform Implementation:**

- **All Modules:** Enable flow logging
  - VPC Flow Logs (AWS)
  - NSG Flow Logs (Azure)
  - VPC Flow Logs + Firewall Rule Logs (GCP)

**Mapping:**
```
A.8.15(a): Log recording → Flow logs capture all network flows
A.8.15(b): Log review → Retention for forensics (30+ days, 90+ for SIEM)
A.8.15(c): Log protection → Encrypted storage (S3 encryption, Blob encryption, GCS encryption)
```

---

#### A.8.20: User Access Management

**Requirement:** Grant, modify, and revoke user access appropriately.

**Terraform Implementation:**

- **Azure Identity Hardening:** PIM manages privileged access
- **All Network Modules:** Least-privilege network access (bastion-only model)

**Mapping:**
```
A.8.20(a): Access granting → IAM role assignment (Terraform-managed)
A.8.20(b): Access review → PIM access reviews + manual quarterly review
A.8.20(c): Access revocation → Terraform destroy removes rules/roles
A.8.20(d): Formal procedures → Change management workflow with approval gates
```

---

#### A.8.21: User Access Restriction

**Requirement:** Restrict access to information & system functions.

**Terraform Implementation:**

- **All Network Hardening Modules:** Firewall rules restrict network access
- **Sensitive Port Blocking:** SSH, RDP, databases restricted to approved CIDRs

**Mapping:**
```
A.8.21(a): Access to systems → Security group / NSG rules enforce least privilege
  - SSH (22) → Restricted to management CIDR
  - RDP (3389) → Restricted to management CIDR
  - Databases (27017, 6379) → Restricted to app servers only
  
A.8.21(b): Unused services → Security groups prohibit unwanted ports (deny-by-default)
A.8.21(c): Segregation of duties → Network isolation via VPC/VNet/projects
```

---

## FedRAMP Moderate Baseline

### Access Control (AC)

#### AC-3: Access Enforcement

**Requirement:** Enforce approved authorizations for user and information flows.

**Terraform Implementation:**

- **All Network Hardening Modules:** Firewalls enforce access policies
- **Continuous Monitoring:** Config/Policy/SCC detect unauthorized rules

**Mapping:**
```
AC-3(1): Organization-defined rules → Security group/NSG/firewall rules
AC-3(7): Role-based access → IAM roles + PIM
AC-3(8): Revocation of access → Terraform destroy removes access
```

---

#### AC-4: Information Flow Enforcement

**Requirement:** Enforce approved information flows.

**Terraform Implementation:**

- **All Modules:** Enable flow logging to capture all network flows
- **Network Segmentation:** VPC/VNet isolation prevents cross-boundary flows

**Mapping:**
```
AC-4(1): Information flow policy → VPC/NSG/Firewall rules
AC-4(8): Flow visualization → Flow logs indexed in CloudWatch/Log Analytics/Cloud Logging
AC-4(21): Information flow monitoring → Terraform continuous_monitoring=true
```

---

### System & Information Integrity (SI)

#### SI-4: Information System Monitoring

**Requirement:** Monitor information systems for attacks, anomalies, and unauthorized activities.

**Terraform Implementation:**

- **All Modules:** Enable flow logging + centralized SIEM
- **Compliance Automation:** Config/Policy/SCC continuously scan for violations

**Mapping:**
```
SI-4(1): System monitoring → VPC/NSG/Firewall flow logs
SI-4(2): Monitoring tools → CloudWatch/Log Analytics/Cloud Logging
SI-4(4): System monitoring tools → AWS Config, Azure Policy, GCP SCC
SI-4(5): Alert thresholds → CloudWatch Alarms, Sentinel alerts
SI-4(11): Alert analysis → Automated rules check for OPEN_FIREWALL findings
SI-4(14): Wireless monitoring → N/A (network-layer enforcement only)
```

**Evidence:**
```bash
# AWS Config rules for FedRAMP
aws configservice describe-config-rules \
  --query 'ConfigRules[?contains(ConfigRuleName, `OPEN_FIREWALL`)]'

# Azure Policy for FedRAMP
az policy definition list --query '[].displayName' | grep -i "firewall\|nsg"

# GCP SCC for FedRAMP
gcloud scc findings list organizations/123456789 \
  --filter='state=ACTIVE AND severity="HIGH"'
```

---

## Compliance Framework Selection

**To use a specific compliance framework, update `prod.tfvars`:**

```hcl
compliance_framework = "nist-800-53"  # or "hipaa", "hitrust", "soc2", "iso27001", "fedramp-moderate"
```

**Impact:**
- Enables framework-specific Config Rules / Policies / SCC modules
- Compliance reports filtered to relevant controls
- Documentation updated with framework-specific mappings

---

## Audit Evidence Collection

### Automated Evidence Generation

Each module produces outputs suitable for compliance audit evidence:

```bash
# Export compliance mappings
terraform output -json | jq '.compliance_mappings'

# Example output:
{
  "NIST 800-53": ["AC-3 (Access Control)", "AC-4 (Data Flow Enforcement)"],
  "SOC 2 TSC": ["CC6.6 (Logical & Physical Access)", "CC6.7 (Boundary Protection)"],
  "ISO 27001": ["A.8.20 (User Access), A.8.21 (Restrict Access)"],
  "HIPAA": ["§164.312(a)(1) (Network Access Controls)"]
}
```

### Manual Evidence Steps

1. **Flow Logs:**
   ```bash
   # AWS
   aws logs describe-log-groups --query 'logGroups[?contains(logGroupName, `flowlogs`)]'
   
   # Azure
   az monitor log-analytics workspace list
   
   # GCP
   gcloud logging sinks list
   ```

2. **Policy/Config Rules:**
   ```bash
   # AWS
   aws configservice describe-compliance-by-config-rule
   
   # Azure
   az policy assignment list --query '[].id'
   
   # GCP
   gcloud scc custom-modules list --organization=123456789
   ```

3. **Change History:**
   ```bash
   terraform show -json | jq '.values.root_module.resources[] | {type, address, change}'
   ```

---

## Compliance Audit Checklist

- [ ] Network hardening: Security groups / NSGs / firewalls restrict SSH, RDP, databases to approved CIDRs
- [ ] Flow logging: VPC/NSG/Firewall logs enabled and retained for 30+ days
- [ ] SIEM integration: Logs forwarded to CloudWatch/Log Analytics/Cloud Logging
- [ ] Continuous monitoring: Config/Policy/SCC scan enabled (compliance_framework set)
- [ ] Identity governance: PIM roles, MFA, role review process (Azure)
- [ ] Encryption: TLS 1.2+ for in-transit, AES-256 for at-rest
- [ ] Change management: Terraform state versioned, plans reviewed before apply
- [ ] Evidence collection: Terraform outputs + cloud audit logs retained

---

## Questions or Clarifications?

For compliance-specific guidance, contact:

📧 **Ola Williams** | olamide@williamsinfosec.com  
🌐 **Williams InfoSec LLC** | https://williamsinfosec.com

---

**Version:** 1.0.0 | **Last Updated:** 2026-06-10
