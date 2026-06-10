################################################################################
# Production Configuration: environments/prod.tfvars
#
# Purpose: Client-specific overrides for production deployment
# 
# Usage:
#   terraform apply -var-file="environments/prod.tfvars" -auto-approve
#
# WARNING: Keep credentials (siem_workspace_key, backup_bucket) in:
#   - .terraform.tfvars.local (excluded from git)
#   - AWS Secrets Manager / Azure Key Vault / GCP Secret Manager
#   - Terraform Cloud variables (encrypted at rest)
#
################################################################################

################################################################################
# DEPLOYMENT CONTEXT
################################################################################

# Primary cloud provider (aws | azure | gcp)
cloud_provider = "aws"

# Environment stage
environment = "prod"

# Organization/client name (alphanumeric + hyphens only, max 20 chars)
project_name = "acme-corp"

# Primary region for resources
region = "us-east-1"

################################################################################
# NETWORK SECURITY: Hardening Configuration
################################################################################

# Enable network flow logging (VPC Flow Logs, NSG Flow Logs, Firewall Logging)
enable_flow_logs = true

# Enable NSG-specific flow logging (Azure)
enable_nsg_logging = true

# Enable SIEM integration (send logs to Sentinel, CloudWatch, etc.)
enable_siem_integration = true

# Block public INGRESS on sensitive ports (SSH, RDP, databases)
block_public_access_rules = true

# Sensitive ports to restrict from 0.0.0.0/0
# Default: SSH (22), RDP (3389), CouchDB (5984), Elasticsearch (9200), MongoDB (27017), Redis (6379)
sensitive_ports = [22, 3389, 5984, 9200, 27017, 6379]

# CRITICAL: Bastion/jump host subnet CIDR blocks
# These IPs are ALLOWED for SSH/RDP access (all others are denied)
# Examples:
#   - Internal bastion subnet: 10.0.1.0/24
#   - VPN endpoint: 203.0.113.0/25
#   - Operations team static IP: 203.0.113.128/32
#
# SAFEGUARD: If empty, no hardening rules are applied (requires explicit approval)
allowed_management_cidrs = [
  "10.0.1.0/24",      # Internal bastion subnet
  "203.0.113.0/25"    # VPN gateway / remote access
]

################################################################################
# COMPLIANCE & GOVERNANCE
################################################################################

# Primary compliance framework
# Options: nist-800-53 | hipaa | hitrust | soc2 | iso27001 | fedramp-moderate
compliance_framework = "nist-800-53"

# Enable continuous compliance monitoring (Config, Azure Policy, GCP SCC)
enable_continuous_monitoring = true

# Enforce encryption at-rest & in-transit
enforce_encryption = true

################################################################################
# LOGGING & MONITORING
################################################################################

# S3 bucket for backup snapshots (AWS)
# Format: my-org-security-backups (lowercase, no hyphens after org name)
backup_bucket = "acme-corp-security-backups"

# Azure Log Analytics Workspace ID (for NSG logs → SIEM)
# Format: /subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace-name}
# Leave null if not using Azure SIEM integration
siem_workspace_id = null

# Azure Log Analytics Workspace Shared Key (sensitive, use Azure Key Vault)
# DO NOT commit to git — use .terraform.tfvars.local or Terraform Cloud variables
siem_workspace_key = null

# Log retention in days (default: 30 days, compliant with most audit requirements)
log_retention_days = 30

################################################################################
# CLOUD-SPECIFIC SETTINGS
################################################################################

# GCP Organization ID (for org-wide SCC & Policy scanning)
# Leave empty for project-level deployment
# gcp_organization_id = "123456789"

# GCP Folder IDs (if scanning specific folders, not org-wide)
# gcp_folder_ids = ["folders/987654321"]

# Specific GCP projects to target (if not scanning org-wide)
gcp_project_ids = []

# Enable GCP SCC Premium for continuous security monitoring
enable_scc_premium = true

# Enable GCP firewall rule logging (non-disruptive, recommended)
enable_firewall_logging = true

################################################################################
# TAGGING & METADATA
################################################################################

# Common tags applied to all resources
tags = {
  "Billing-Center"  = "Security"
  "Service"         = "Cloud-Security"
  "Managed-By"      = "Terraform"
  "Owner"           = "CISO"
  "Compliance"      = "NIST-800-53"
  "Environment"     = "Production"
  "Cost-Allocation" = "Security-Hardening"
}

################################################################################
# APPROVAL & CHANGE TRACKING
################################################################################

# Optional: Change request / approval ticket ID
# Included in resource descriptions for audit trail
# approval_ticket = "CHG-2026-06-001"

# Optional: Approver email (for documentation)
# approver_email = "ciso@acme-corp.com"

################################################################################
# SAFEGUARDS & VALIDATION
################################################################################

# Prevent accidental public exposure
#
# If allowed_management_cidrs is empty, the module will NOT create any
# hardening rules (safe-fail). This is intentional to prevent:
#   - Accidental lockout of admin access
#   - Rules applied without stakeholder approval
#
# To proceed, set allowed_management_cidrs to actual bastion IPs above.

################################################################################
# SENSITIVE CREDENTIALS (Use Key Vault / Secrets Manager)
################################################################################

# DO NOT store credentials in this file. Instead:
#
# 1. AWS Secrets Manager:
#    aws secretsmanager create-secret --name terraform/acme-corp/prod \
#      --secret-string '{"siem_workspace_key":"...","other_secret":"..."}'
#
# 2. Azure Key Vault:
#    az keyvault secret set --vault-name terraform-secrets \
#      --name siem-workspace-key --value "..."
#
# 3. GCP Secret Manager:
#    echo "my-secret-value" | gcloud secrets create terraform-secret --data-file=-
#
# 4. Terraform Cloud:
#    - Create workspace variable "siem_workspace_key" (marked sensitive)
#    - Set value in UI or CLI, never in .tfvars files

################################################################################
# NEXT STEPS
################################################################################

# 1. Save this file as: environments/prod.tfvars
# 
# 2. Create local overrides: environments/prod.tfvars.local (git-ignored)
#    - Store sensitive credentials here
#    - Only you should see this file
#
# 3. Initialize Terraform:
#    terraform init
#
# 4. Plan:
#    terraform plan -var-file="environments/prod.tfvars"
#
# 5. Review the plan output, then apply:
#    terraform apply -var-file="environments/prod.tfvars"
#
# 6. Validate:
#    terraform output -json | jq .remediation_status

################################################################################
