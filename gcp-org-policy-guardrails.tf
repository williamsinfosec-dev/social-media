################################################################################
# MODULE: GCP Organization Policy Guardrails (Landing Zone Baseline)
#
# Refactored from production gcloud remediation playbooks (org-wide SCC
# enablement, storage encryption enforcement, firewall hardening sweeps)
# into declarative, preventative org policy constraints.
#
# WHAT THIS MODULE DOES:
#   Codifies the preventative guardrails that remediation sweeps repeatedly
#   enforce reactively - shifting from "find and fix" to "cannot happen":
#     - Public IP restrictions on VMs and Cloud SQL
#     - Uniform bucket-level access + public access prevention on GCS
#     - OS Login + serial port lockdown on Compute
#     - Service account key hygiene (no user-managed keys)
#     - Domain-restricted IAM sharing
#     - Resource location restriction (data residency / sovereignty)
#
# DESIGNED FOR: FedRAMP / Assured Workloads landing zones where restrictive
# policies must be applied deliberately - every constraint is individually
# toggleable, and the module supports folder-scoped rollout so a policy can
# be proven in a workload folder before org-wide enforcement (avoiding the
# "restrictive policy breaks existing stacks" failure mode).
#
# COMPLIANCE MAPPINGS:
#   NIST 800-53 R5 : AC-3, AC-4, AC-6, CM-7, SC-7, SC-12, IA-2
#   FedRAMP High   : AC-3, AC-6, SC-7, SC-12, SC-28
#   SOC 2 TSC      : CC6.1, CC6.3, CC6.6
#   HIPAA          : §164.312(a)(1), §164.312(e)(1)
#   ISO 27001:2022 : A.5.15, A.8.3, A.8.20
#
# Author: Williams InfoSec LLC | https://williamsinfosec.com
################################################################################

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.10.0"
    }
  }
}

# ------------------------------------------------------------------------------
# VARIABLES
# ------------------------------------------------------------------------------

variable "parent" {
  description = <<-EOT
    Parent node for policy enforcement: "organizations/ORG_ID" or
    "folders/FOLDER_ID". Use a folder first to prove out constraints
    against live workloads before promoting to the org node.
  EOT
  type = string

  validation {
    condition     = can(regex("^(organizations|folders)/[0-9]+$", var.parent))
    error_message = "parent must be organizations/<id> or folders/<id>."
  }
}

variable "enforce_no_external_vm_ips" {
  description = "Block external IPs on Compute instances (compute.vmExternalIpAccess)."
  type        = bool
  default     = true
}

variable "external_ip_exception_vms" {
  description = "VM resource paths exempted from the external IP block (e.g. approved NAT/bastion). Empty = deny all."
  type        = list(string)
  default     = []
}

variable "enforce_no_public_sql" {
  description = "Block public IPs on Cloud SQL instances (sql.restrictPublicIp)."
  type        = bool
  default     = true
}

variable "enforce_uniform_bucket_access" {
  description = "Require uniform bucket-level access on GCS (storage.uniformBucketLevelAccess)."
  type        = bool
  default     = true
}

variable "enforce_public_access_prevention" {
  description = "Enforce public access prevention on GCS (storage.publicAccessPrevention)."
  type        = bool
  default     = true
}

variable "enforce_os_login" {
  description = "Require OS Login on Compute instances (compute.requireOsLogin)."
  type        = bool
  default     = true
}

variable "enforce_serial_port_disable" {
  description = "Disable serial port access on Compute (compute.disableSerialPortAccess)."
  type        = bool
  default     = true
}

variable "enforce_no_sa_key_creation" {
  description = "Block user-managed service account key creation (iam.disableServiceAccountKeyCreation)."
  type        = bool
  default     = true
}

variable "allowed_iam_domains" {
  description = "Cloud Identity customer IDs (C0xxxxxxx) allowed in IAM policies. Empty list = constraint not deployed."
  type        = list(string)
  default     = []
}

variable "allowed_resource_locations" {
  description = "Location value group for data residency, e.g. [\"in:us-locations\"]. Empty list = constraint not deployed."
  type        = list(string)
  default     = []
}

# ------------------------------------------------------------------------------
# COMPUTE GUARDRAILS
# ------------------------------------------------------------------------------

# No external IPs on VMs - the #1 recurring finding in posture sweeps.
# Supports an explicit exception list for approved egress points.
resource "google_org_policy_policy" "vm_external_ip" {
  count  = var.enforce_no_external_vm_ips ? 1 : 0
  name   = "${var.parent}/policies/compute.vmExternalIpAccess"
  parent = var.parent

  spec {
    rules {
      dynamic "values" {
        for_each = length(var.external_ip_exception_vms) > 0 ? [1] : []
        content {
          allowed_values = var.external_ip_exception_vms
        }
      }
      deny_all = length(var.external_ip_exception_vms) == 0 ? "TRUE" : null
    }
  }
}

resource "google_org_policy_policy" "require_os_login" {
  count  = var.enforce_os_login ? 1 : 0
  name   = "${var.parent}/policies/compute.requireOsLogin"
  parent = var.parent

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

resource "google_org_policy_policy" "disable_serial_port" {
  count  = var.enforce_serial_port_disable ? 1 : 0
  name   = "${var.parent}/policies/compute.disableSerialPortAccess"
  parent = var.parent

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# ------------------------------------------------------------------------------
# STORAGE GUARDRAILS - codifies what bucket remediation scripts fix reactively
# ------------------------------------------------------------------------------

resource "google_org_policy_policy" "uniform_bucket_access" {
  count  = var.enforce_uniform_bucket_access ? 1 : 0
  name   = "${var.parent}/policies/storage.uniformBucketLevelAccess"
  parent = var.parent

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

resource "google_org_policy_policy" "public_access_prevention" {
  count  = var.enforce_public_access_prevention ? 1 : 0
  name   = "${var.parent}/policies/storage.publicAccessPrevention"
  parent = var.parent

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# ------------------------------------------------------------------------------
# DATABASE GUARDRAILS
# ------------------------------------------------------------------------------

resource "google_org_policy_policy" "sql_no_public_ip" {
  count  = var.enforce_no_public_sql ? 1 : 0
  name   = "${var.parent}/policies/sql.restrictPublicIp"
  parent = var.parent

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# ------------------------------------------------------------------------------
# IAM GUARDRAILS
# ------------------------------------------------------------------------------

# Long-lived SA keys are a standing audit finding; workload identity
# federation removes the need for them.
resource "google_org_policy_policy" "no_sa_key_creation" {
  count  = var.enforce_no_sa_key_creation ? 1 : 0
  name   = "${var.parent}/policies/iam.disableServiceAccountKeyCreation"
  parent = var.parent

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# Domain-restricted sharing - prevents IAM grants to identities outside
# approved Cloud Identity customers (external-account exfiltration control).
resource "google_org_policy_policy" "domain_restricted_sharing" {
  count  = length(var.allowed_iam_domains) > 0 ? 1 : 0
  name   = "${var.parent}/policies/iam.allowedPolicyMemberDomains"
  parent = var.parent

  spec {
    rules {
      values {
        allowed_values = var.allowed_iam_domains
      }
    }
  }
}

# ------------------------------------------------------------------------------
# DATA RESIDENCY - sovereignty / FedRAMP boundary control
# ------------------------------------------------------------------------------

resource "google_org_policy_policy" "resource_locations" {
  count  = length(var.allowed_resource_locations) > 0 ? 1 : 0
  name   = "${var.parent}/policies/gcp.resourceLocations"
  parent = var.parent

  spec {
    rules {
      values {
        allowed_values = var.allowed_resource_locations
      }
    }
  }
}

# ------------------------------------------------------------------------------
# OUTPUTS
# ------------------------------------------------------------------------------

output "enforced_constraints" {
  description = "Org policy constraints deployed by this module (audit evidence)."
  value = compact([
    try(google_org_policy_policy.vm_external_ip[0].name, ""),
    try(google_org_policy_policy.require_os_login[0].name, ""),
    try(google_org_policy_policy.disable_serial_port[0].name, ""),
    try(google_org_policy_policy.uniform_bucket_access[0].name, ""),
    try(google_org_policy_policy.public_access_prevention[0].name, ""),
    try(google_org_policy_policy.sql_no_public_ip[0].name, ""),
    try(google_org_policy_policy.no_sa_key_creation[0].name, ""),
    try(google_org_policy_policy.domain_restricted_sharing[0].name, ""),
    try(google_org_policy_policy.resource_locations[0].name, ""),
  ])
}

output "enforcement_scope" {
  description = "Node where constraints are enforced (folder-first rollout supported)."
  value       = var.parent
}
