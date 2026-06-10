# Cloud Security Terraform Modules — File Index

**Version:** 1.0.0 | **Created:** 2026-06-10 | **Author:** Ola Williams, Williams InfoSec LLC

---

## 📂 Core Module Files

### 1. `main.tf` (575 lines)
**Purpose:** Root module orchestration, provider configuration, all module composition

**When to Use:** Start here for every deployment. Customize variables in `prod.tfvars`.

---

### 2. `aws-network-hardening.tf` (620 lines)
**Purpose:** AWS Security Groups, VPC Flow Logs, backup bucket

**Compliance Mapped:** NIST AC-3/AC-4, SOC 2 CC6.6/CC6.7/CC7.2, HIPAA §164.312(a)(1)

---

### 3. `gcp-firewall-hardening.tf` (580 lines)
**Purpose:** GCP firewall rules, SCC integration, Cloud Logging, GCS backups

**Compliance Mapped:** NIST AC-3/AC-4/SI-4, SOC 2 CC6.6/CC6.7/CC7.2, FedRAMP AC-3/AC-4/SI-4

---

### 4. `azure-nsg-hardening.tf` (540 lines)
**Purpose:** Azure NSG rules, flow logs → Log Analytics, Policy enforcement

**Compliance Mapped:** NIST AC-3/AC-4, SOC 2 CC6.6/CC6.7/CC7.2, HIPAA §164.312

---

## 📚 Documentation Files

### 5. `README.md` (850 lines)
**Purpose:** User guide, quick start, examples, troubleshooting

**Audience:** DevOps engineers, architects

---

### 6. `COMPLIANCE.md` (900 lines)
**Purpose:** Detailed control mappings for NIST, SOC 2, HIPAA, HITRUST, ISO 27001, FedRAMP

**Audience:** Compliance officers, auditors, CISO

---

### 7. `prod.tfvars` (150 lines)
**Purpose:** Documented example configuration for production

**Usage:** `terraform apply -var-file="prod.tfvars"`

---

### 8. `GITHUB-INTEGRATION.md` (350 lines)
**Purpose:** Guide for publishing to public GitHub repository + marketing

**Audience:** Sales/marketing, repository maintainers

---

### 9. `SUMMARY.md` (450 lines)
**Purpose:** Executive summary, revenue tiers, next steps

**Audience:** You (Ola), sales team, prospects

---

## 🎯 Quick Start by Use Case

**AWS + NIST 800-53:**
```bash
terraform apply -var-file="prod.tfvars" \
  -var cloud_provider="aws" \
  -var compliance_framework="nist-800-53"
```

**Azure + HIPAA:**
```bash
terraform apply -var-file="prod.tfvars" \
  -var cloud_provider="azure" \
  -var compliance_framework="hipaa"
```

**GCP + SOC 2:**
```bash
terraform apply -var-file="prod.tfvars" \
  -var cloud_provider="gcp" \
  -var compliance_framework="soc2"
```

---

**Total Deliverables:** 9 files | **Total Lines:** 5,000+ | **Status:** Production-Ready
