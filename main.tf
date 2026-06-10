################################################################################
# Williams InfoSec LLC — Cloud Security Module Library
# Repository: williamsinfosec-dev/social-media → client-demos
# Purpose: Production-grade, compliance-aligned IaC for cloud security hardening
# 
# This module provides reusable, enterprise-ready configurations for:
# - Network security posture hardening (multi-cloud)
# - Compliance automation (NIST 800-53, SOC 2, HIPAA, HITRUST)
# - Continuous monitoring & detection
# - Zero Trust architecture patterns
#
# Compliance Mappings:
#   - NIST 800-53 R5: AC-3, AC-6, SA-3, CA-7
#   - SOC 2 TSC: CC6.6, CC6.7, CC7.2, CC1.4
#   - ISO 27001:2022: A.8.20, A.8.21, A.8.15, A.8.16, A.5.1
#   - HIPAA: §164.312(a)(1), §164.312(b)
#
# Author: Ola Williams <olamide@williamsinfosec.com>
# Version: 1.0.0 | Last updated: 2026-06-10
#
# USAGE:
#   terraform init
#   terraform plan -var-file="environments/prod.tfvars"
#   terraform apply -var-file="environments/prod.tfvars" -auto-approve
#
# ARCHITECTURE OVERVIEW:
#   ├─ Provider selection (AWS, Azure, GCP)
#   ├─ Network hardening (firewall, NSG, security groups)
#   ├─ Logging & detection (SIEM integration)
#   ├─ Identity & access (IAM, PIM, role assignments)
#   └─ Compliance automation (policy-as-code, guardrails)
#
################################################################################

terraform {
  required_version = ">= 1.4"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  # Recommended: use remote state in prod
  # backend "s3" {
  #   bucket         = "org-terraform-state"
  #   key            = "cloud-security/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-locks"
  # }
}

################################################################################
# VARIABLES: Customize per deployment
################################################################################

variable "cloud_provider" {
  description = "Target cloud provider (aws|azure|gcp)"
  type        = string
  default     = "aws"
  
  validation {
    condition     = contains(["aws", "azure", "gcp"], var.cloud_provider)
    error_message = "cloud_provider must be 'aws', 'azure', or 'gcp'."
  }
}

variable "environment" {
  description = "Deployment environment (dev|staging|prod)"
  type        = string
  default     = "prod"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be 'dev', 'staging', or 'prod'."
  }
}

variable "project_name" {
  description = "Project/client name (used for naming & tagging)"
  type        = string
  
  validation {
    condition     = length(var.project_name) <= 20 && can(regex("^[a-z0-9-]*$", var.project_name))
    error_message = "project_name must be lowercase alphanumeric + hyphens (max 20 chars)."
  }
}

variable "region" {
  description = "Primary AWS region (e.g. us-east-1) or Azure region (e.g. eastus)"
  type        = string
  default     = "us-east-1"
}

variable "enable_flow_logs" {
  description = "Enable VPC/VNet flow logging for audit trails"
  type        = bool
  default     = true
}

variable "enable_nsg_logging" {
  description = "Enable NSG (Azure) or Security Group (AWS) flow logging"
  type        = bool
  default     = true
}

variable "enable_siem_integration" {
  description = "Forward logs to SIEM (Sentinel, CloudWatch, Cloud Logging)"
  type        = bool
  default     = false
}

variable "siem_workspace_id" {
  description = "Log Analytics Workspace ID for SIEM ingestion"
  type        = string
  default     = null
  sensitive   = true
}

variable "block_public_access_rules" {
  description = "Block public INGRESS rules on sensitive ports (22, 3389, 5984, 9200)"
  type        = bool
  default     = true
}

variable "sensitive_ports" {
  description = "Ports to restrict from 0.0.0.0/0 (SSH, RDP, etc.)"
  type        = list(number)
  default     = [22, 3389, 5984, 9200, 27017, 6379]
}

variable "allowed_management_cidrs" {
  description = "CIDR blocks allowed for bastion/jump host access"
  type        = list(string)
  default     = []
}

variable "compliance_framework" {
  description = "Primary compliance requirement (nist-800-53|hipaa|hitrust|soc2|iso27001)"
  type        = string
  default     = "nist-800-53"
}

variable "enable_continuous_monitoring" {
  description = "Enable Config/Policy continuous compliance scanning"
  type        = bool
  default     = true
}

variable "enforce_encryption" {
  description = "Enforce encryption at-rest & in-transit"
  type        = bool
  default     = true
}

variable "backup_bucket" {
  description = "GCS/S3 bucket for pre-change state backups"
  type        = string
  default     = null
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Managed_By = "Terraform"
    Module     = "cloud-security"
  }
}

################################################################################
# AWS PROVIDER & CONFIGURATION
################################################################################

provider "aws" {
  count = var.cloud_provider == "aws" ? 1 : 0

  region = var.region

  default_tags {
    tags = merge(
      var.tags,
      {
        Environment = var.environment
        Project     = var.project_name
        CreatedAt   = timestamp()
      }
    )
  }
}

################################################################################
# AZURE PROVIDER & CONFIGURATION
################################################################################

provider "azurerm" {
  count = var.cloud_provider == "azure" ? 1 : 0

  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

################################################################################
# GCP PROVIDER & CONFIGURATION
################################################################################

provider "google" {
  count = var.cloud_provider == "gcp" ? 1 : 0

  region = var.region
}

################################################################################
# DATA SOURCES: Discovery & reference
################################################################################

# AWS: Current account context
data "aws_caller_identity" "current" {
  count = var.cloud_provider == "aws" ? 1 : 0
}

data "aws_region" "current" {
  count = var.cloud_provider == "aws" ? 1 : 0
}

# Azure: Current subscription context
data "azurerm_client_config" "current" {
  count = var.cloud_provider == "azure" ? 1 : 0
}

# GCP: Current project context
data "google_client_config" "current" {
  count = var.cloud_provider == "gcp" ? 1 : 0
}

################################################################################
# MODULE 1: NETWORK SECURITY HARDENING (AWS)
# 
# Purpose: Remove public INGRESS on sensitive ports, enforce least privilege
# Compliance: NIST AC-3 (access control), SOC 2 CC6.6, ISO 27001 A.8.20
################################################################################

module "aws_network_hardening" {
  count = var.cloud_provider == "aws" ? 1 : 0
  
  source = "./modules/aws-network-hardening"

  project_name               = var.project_name
  environment                = var.environment
  region                     = var.region
  enable_flow_logs           = var.enable_flow_logs
  block_public_access_rules  = var.block_public_access_rules
  sensitive_ports            = var.sensitive_ports
  allowed_management_cidrs   = var.allowed_management_cidrs
  backup_bucket              = var.backup_bucket
  tags                       = var.tags

  providers = {
    aws = aws[0]
  }

  depends_on = [aws_s3_bucket.backup_bucket]
}

################################################################################
# MODULE 2: AZURE NETWORK SECURITY (NSG Governance)
#
# Purpose: Standardize NSG rules across subscriptions, enable flow logs
# Compliance: NIST AC-3, SOC 2 CC6.6, ISO 27001 A.8.20
################################################################################

module "azure_nsg_hardening" {
  count = var.cloud_provider == "azure" ? 1 : 0

  source = "./modules/azure-nsg-hardening"

  project_name              = var.project_name
  environment               = var.environment
  enable_nsg_logging        = var.enable_nsg_logging
  block_public_access_rules = var.block_public_access_rules
  sensitive_ports           = var.sensitive_ports
  allowed_management_cidrs  = var.allowed_management_cidrs
  siem_workspace_id         = var.siem_workspace_id
  tags                      = var.tags

  providers = {
    azurerm = azurerm[0]
  }
}

################################################################################
# MODULE 3: GCP FIREWALL HARDENING & SCC INTEGRATION
#
# Purpose: Harden VPC firewalls across projects, enable firewall rule logging
# Compliance: NIST AC-3, SOC 2 CC7.2 (monitoring), ISO 27001 A.8.15
################################################################################

module "gcp_firewall_hardening" {
  count = var.cloud_provider == "gcp" ? 1 : 0

  source = "./modules/gcp-firewall-hardening"

  project_name              = var.project_name
  environment               = var.environment
  region                    = var.region
  block_public_access_rules = var.block_public_access_rules
  sensitive_ports           = var.sensitive_ports
  allowed_management_cidrs  = var.allowed_management_cidrs
  backup_bucket             = var.backup_bucket
  tags                      = var.tags

  providers = {
    google = google[0]
  }
}

################################################################################
# MODULE 4: COMPLIANCE AUTOMATION (Policy-as-Code)
#
# Purpose: Continuous monitoring, guardrails, audit logging
# Compliance: NIST CA-7 (continuous monitoring), SOC 2 CC1.4
################################################################################

module "compliance_automation" {
  count = var.enable_continuous_monitoring ? 1 : 0

  source = "./modules/compliance-automation"

  cloud_provider           = var.cloud_provider
  project_name             = var.project_name
  environment              = var.environment
  compliance_framework     = var.compliance_framework
  enable_siem_integration  = var.enable_siem_integration
  siem_workspace_id        = var.siem_workspace_id
  tags                     = var.tags

  providers = {
    aws     = var.cloud_provider == "aws" ? aws[0] : null
    azurerm = var.cloud_provider == "azure" ? azurerm[0] : null
    google  = var.cloud_provider == "gcp" ? google[0] : null
  }
}

################################################################################
# MODULE 5: IDENTITY & ACCESS MANAGEMENT (Zero Trust)
#
# Purpose: IAM hardening, PIM setup, MFA enforcement
# Compliance: NIST AC-2, AC-6 (privilege management), SOC 2 CC6.1
################################################################################

module "identity_hardening" {
  count = var.cloud_provider == "azure" ? 1 : 0

  source = "./modules/azure-identity-hardening"

  project_name = var.project_name
  environment  = var.environment
  tags         = var.tags

  providers = {
    azurerm = azurerm[0]
  }
}

################################################################################
# AWS: Backup bucket for state snapshots
################################################################################

resource "aws_s3_bucket" "backup_bucket" {
  count = var.cloud_provider == "aws" && var.backup_bucket != null ? 1 : 0

  bucket = var.backup_bucket

  tags = merge(
    var.tags,
    { Name = "change-backup-bucket" }
  )
}

resource "aws_s3_bucket_versioning" "backup_bucket" {
  count = var.cloud_provider == "aws" && var.backup_bucket != null ? 1 : 0

  bucket = aws_s3_bucket.backup_bucket[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backup_bucket" {
  count = var.cloud_provider == "aws" && var.backup_bucket != null ? 1 : 0

  bucket = aws_s3_bucket.backup_bucket[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

################################################################################
# OUTPUTS: Critical resource references for downstream usage
################################################################################

output "deployment_summary" {
  description = "Summary of deployed security controls"
  value = {
    cloud_provider       = var.cloud_provider
    environment          = var.environment
    project_name         = var.project_name
    region               = var.region
    compliance_framework = var.compliance_framework
    flow_logs_enabled    = var.enable_flow_logs
    continuous_monitoring_enabled = var.enable_continuous_monitoring
  }
}

output "aws_account_id" {
  description = "AWS Account ID (if AWS provider)"
  value       = var.cloud_provider == "aws" ? data.aws_caller_identity.current[0].account_id : null
}

output "azure_subscription_id" {
  description = "Azure Subscription ID (if Azure provider)"
  value       = var.cloud_provider == "azure" ? data.azurerm_client_config.current[0].subscription_id : null
}

output "gcp_project_id" {
  description = "GCP Project ID (if GCP provider)"
  value       = var.cloud_provider == "gcp" ? data.google_client_config.current[0].project_id : null
}

output "backup_bucket_name" {
  description = "S3 bucket for change backups"
  value       = var.backup_bucket
  sensitive   = false
}

output "module_outputs" {
  description = "Aggregated outputs from all deployed modules"
  value = {
    network_hardening = var.cloud_provider == "aws" ? module.aws_network_hardening[0] : null
    nsg_hardening     = var.cloud_provider == "azure" ? module.azure_nsg_hardening[0] : null
    firewall_hardening = var.cloud_provider == "gcp" ? module.gcp_firewall_hardening[0] : null
    compliance        = var.enable_continuous_monitoring ? module.compliance_automation[0] : null
  }
}
