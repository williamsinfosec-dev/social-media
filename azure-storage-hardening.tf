################################################################################
# MODULE: Azure Storage Account Network Hardening
#
# Refactored from production PowerShell remediation tooling
# (Remediate-StorageAccountNetworkAccess.ps1) into declarative Terraform.
#
# WHAT THIS MODULE DOES:
#   1. Hardens existing Storage Accounts: DefaultAction = Deny, explicit
#      CIDR allowlist, Bypass = AzureServices (Backup/Monitor keep working)
#   2. Deploys the built-in Azure Policy "Storage accounts should restrict
#      network access" in Audit or Deny mode for continuous compliance
#   3. Emits a compliance inventory output for audit evidence
#
# SAFEGUARD: If allowed_cidr_ranges is empty, NO network rules are applied.
# This mirrors the dry-run-first discipline of the original script and
# prevents accidental lockout of applications.
#
# COMPLIANCE MAPPINGS:
#   NIST 800-53 R5 : AC-3, AC-4, SC-7, SC-7(5)
#   FedRAMP Mod    : AC-3, SC-7
#   SOC 2 TSC      : CC6.1, CC6.6
#   HIPAA          : §164.312(a)(1), §164.312(e)(1)
#   ISO 27001:2022 : A.8.20, A.8.22
#
# Author: Williams InfoSec LLC | https://williamsinfosec.com
################################################################################

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.85.0"
    }
  }
}

# ------------------------------------------------------------------------------
# VARIABLES
# ------------------------------------------------------------------------------

variable "storage_accounts" {
  description = <<-EOT
    Map of storage accounts to harden. Key is a logical name; value contains
    the storage account name and its resource group. Sourced from the same
    inventory pattern as the original remediation script (CSV -> map).
  EOT
  type = map(object({
    name                = string
    resource_group_name = string
  }))
  default = {}
}

variable "allowed_cidr_ranges" {
  description = <<-EOT
    CIDR ranges permitted to reach the storage accounts (corporate ranges,
    VPN gateways, bastion hosts). SAFEGUARD: if empty, no rules are applied
    and the module is a no-op - preventing accidental lockout.
  EOT
  type    = list(string)
  default = []
}

variable "allowed_subnet_ids" {
  description = "Optional list of VNet subnet resource IDs to allow (service endpoints)."
  type        = list(string)
  default     = []
}

variable "bypass_azure_services" {
  description = "Allow trusted Azure services (Backup, Monitor) through the firewall."
  type        = bool
  default     = true
}

variable "deploy_policy" {
  description = "Deploy the built-in Azure Policy for continuous enforcement."
  type        = bool
  default     = true
}

variable "policy_scope_id" {
  description = "Subscription or management group ID for the policy assignment."
  type        = string
  default     = ""
}

variable "policy_effect" {
  description = "Policy effect: Audit (report-only) or Deny (block new violations)."
  type        = string
  default     = "Audit"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.policy_effect)
    error_message = "policy_effect must be Audit, Deny, or Disabled."
  }
}

# ------------------------------------------------------------------------------
# LOCALS - safeguard gate (mirrors the original script's safety requirement
# that remediation mode demands explicit targets)
# ------------------------------------------------------------------------------

locals {
  remediation_enabled = length(var.allowed_cidr_ranges) > 0 || length(var.allowed_subnet_ids) > 0
  accounts_to_harden  = local.remediation_enabled ? var.storage_accounts : {}
}

# ------------------------------------------------------------------------------
# DATA - read current state of each storage account (replaces the
# Get-AzStorageAccountNetworkRuleSet inventory phase)
# ------------------------------------------------------------------------------

data "azurerm_storage_account" "target" {
  for_each            = var.storage_accounts
  name                = each.value.name
  resource_group_name = each.value.resource_group_name
}

# ------------------------------------------------------------------------------
# REMEDIATION - network rules (replaces Set-AzStorageAccount remediation phase)
# DefaultAction = Deny + explicit allowlist + AzureServices bypass
# ------------------------------------------------------------------------------

resource "azurerm_storage_account_network_rules" "hardened" {
  for_each = local.accounts_to_harden

  storage_account_id = data.azurerm_storage_account.target[each.key].id

  default_action             = "Deny"
  ip_rules                   = var.allowed_cidr_ranges
  virtual_network_subnet_ids = var.allowed_subnet_ids
  bypass                     = var.bypass_azure_services ? ["AzureServices"] : ["None"]
}

# ------------------------------------------------------------------------------
# PREVENTION - built-in Azure Policy assignment for continuous compliance
# (Phase 3 of the original remediation playbook, codified)
# Built-in: "Storage accounts should restrict network access"
# ------------------------------------------------------------------------------

resource "azurerm_subscription_policy_assignment" "restrict_storage_network" {
  count = var.deploy_policy && var.policy_scope_id != "" ? 1 : 0

  name                 = "storage-restrict-network-access"
  display_name         = "Storage accounts should restrict network access"
  subscription_id      = var.policy_scope_id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/34c877ad-507e-4c82-993e-3452a6e0ad3c"

  parameters = jsonencode({
    effect = { value = var.policy_effect }
  })
}

# ------------------------------------------------------------------------------
# OUTPUTS - compliance evidence (replaces the CSV inventory export)
# ------------------------------------------------------------------------------

output "hardened_storage_accounts" {
  description = "Storage accounts with network rules applied (audit evidence)."
  value = {
    for k, v in azurerm_storage_account_network_rules.hardened : k => {
      storage_account = data.azurerm_storage_account.target[k].name
      default_action  = v.default_action
      ip_rule_count   = length(v.ip_rules)
      bypass          = v.bypass
    }
  }
}

output "remediation_enabled" {
  description = "False means the CIDR safeguard prevented any changes (no-op run)."
  value       = local.remediation_enabled
}

output "policy_assignment_id" {
  description = "ID of the continuous-compliance policy assignment, if deployed."
  value       = try(azurerm_subscription_policy_assignment.restrict_storage_network[0].id, null)
}
