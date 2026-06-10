################################################################################
# MODULE: Azure SQL Server Auditing & Continuous Compliance
#
# Refactored from production remediation tooling (Set-AzSqlServerAudit +
# az policy assignment workflow) into declarative Terraform.
#
# WHAT THIS MODULE DOES:
#   1. Enables SERVER-LEVEL auditing on Azure SQL servers, streaming to a
#      Log Analytics workspace (covers all current AND future databases on
#      each server - no per-database configuration drift)
#   2. Assigns the built-in DeployIfNotExists policy so any new SQL server
#      is automatically configured (Policy ID 7ff3c2da-8e06-4a7d-ba1e-fc4c3cc3e0b8)
#   3. Creates a remediation task to bring existing non-compliant servers
#      into line - the full Inventory -> Remediate -> Enforce lifecycle
#
# COMPLIANCE MAPPINGS:
#   NIST 800-53 R5 : AU-2, AU-3, AU-6, AU-12, CA-7
#   FedRAMP Mod    : AU-2, AU-6, SI-4
#   SOC 2 TSC      : CC7.2, CC7.3
#   HIPAA          : §164.312(b) (Audit Controls)
#   ISO 27001:2022 : A.8.15, A.8.16
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

variable "sql_servers" {
  description = "Map of SQL servers to enable auditing on. Key is a logical name."
  type = map(object({
    name                = string
    resource_group_name = string
  }))
  default = {}
}

variable "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics workspace receiving audit logs."
  type        = string
}

variable "audit_retention_days" {
  description = "Audit log retention in days (0 = unlimited / workspace-governed)."
  type        = number
  default     = 90
}

variable "deploy_policy" {
  description = "Assign the built-in DeployIfNotExists policy for new SQL servers."
  type        = bool
  default     = true
}

variable "policy_scope_id" {
  description = "Subscription ID (GUID) for the policy assignment scope."
  type        = string
  default     = ""
}

variable "policy_location" {
  description = "Location for the policy assignment managed identity."
  type        = string
  default     = "eastus"
}

variable "create_remediation_task" {
  description = "Create a remediation task for existing non-compliant servers."
  type        = bool
  default     = true
}

# ------------------------------------------------------------------------------
# DATA - resolve target servers (inventory phase)
# ------------------------------------------------------------------------------

data "azurerm_mssql_server" "target" {
  for_each            = var.sql_servers
  name                = each.value.name
  resource_group_name = each.value.resource_group_name
}

# ------------------------------------------------------------------------------
# REMEDIATION - server-level extended auditing to Log Analytics
# (replaces Set-AzSqlServerAudit -LogAnalyticsTargetState Enabled)
#
# Server-level auditing inherits to every database on the server, including
# databases created after this is applied - eliminating per-DB drift.
# ------------------------------------------------------------------------------

resource "azurerm_mssql_server_extended_auditing_policy" "this" {
  for_each = var.sql_servers

  server_id              = data.azurerm_mssql_server.target[each.key].id
  log_monitoring_enabled = true
  retention_in_days      = var.audit_retention_days
}

# Diagnostic setting routes SQLSecurityAuditEvents from the server's
# master database to the Log Analytics workspace.
resource "azurerm_monitor_diagnostic_setting" "sql_audit" {
  for_each = var.sql_servers

  name                       = "sql-audit-to-law"
  target_resource_id         = "${data.azurerm_mssql_server.target[each.key].id}/databases/master"
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "SQLSecurityAuditEvents"
  }
}

# ------------------------------------------------------------------------------
# PREVENTION - built-in DeployIfNotExists policy
# "Configure SQL servers to have auditing enabled to Log Analytics workspace"
# ------------------------------------------------------------------------------

resource "azurerm_subscription_policy_assignment" "sql_auditing" {
  count = var.deploy_policy && var.policy_scope_id != "" ? 1 : 0

  name                 = "sql-auditing-enforcement"
  display_name         = "SQL Server Auditing to Log Analytics"
  subscription_id      = "/subscriptions/${var.policy_scope_id}"
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/7ff3c2da-8e06-4a7d-ba1e-fc4c3cc3e0b8"
  location             = var.policy_location

  identity {
    type = "SystemAssigned"
  }

  parameters = jsonencode({
    logAnalyticsWorkspaceId = { value = var.log_analytics_workspace_id }
  })
}

# DeployIfNotExists needs rights to configure auditing on non-compliant servers
resource "azurerm_role_assignment" "policy_identity" {
  count = var.deploy_policy && var.policy_scope_id != "" ? 1 : 0

  scope                = "/subscriptions/${var.policy_scope_id}"
  role_definition_name = "SQL Security Manager"
  principal_id         = azurerm_subscription_policy_assignment.sql_auditing[0].identity[0].principal_id
}

# Remediation task brings EXISTING non-compliant servers into compliance
# (replaces Start-AzPolicyRemediation)
resource "azurerm_subscription_policy_remediation" "sql_auditing" {
  count = var.deploy_policy && var.create_remediation_task && var.policy_scope_id != "" ? 1 : 0

  name                 = "sql-auditing-remediation"
  subscription_id      = "/subscriptions/${var.policy_scope_id}"
  policy_assignment_id = azurerm_subscription_policy_assignment.sql_auditing[0].id
}

# ------------------------------------------------------------------------------
# OUTPUTS - compliance evidence
# ------------------------------------------------------------------------------

output "audited_sql_servers" {
  description = "SQL servers with server-level auditing enabled (audit evidence)."
  value = {
    for k, v in azurerm_mssql_server_extended_auditing_policy.this : k => {
      server_id      = v.server_id
      retention_days = v.retention_in_days
      log_monitoring = v.log_monitoring_enabled
    }
  }
}

output "policy_assignment_id" {
  description = "DeployIfNotExists policy assignment ID, if deployed."
  value       = try(azurerm_subscription_policy_assignment.sql_auditing[0].id, null)
}
