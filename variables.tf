##############################################################################
# ChaosGuard: shared variables
#
# Consumed by k8s-chaos-guard.tf (OSE/Kubernetes) and linux-chaos-guard.tf.
##############################################################################

variable "org_id" {
  description = "Harness organization ID that owns these ChaosGuard resources."
  type        = string

  validation {
    condition     = length(trimspace(var.org_id)) > 0
    error_message = "org_id must not be empty."
  }
}

variable "project_id" {
  description = "Harness project ID that owns these ChaosGuard resources."
  type        = string

  validation {
    condition     = length(trimspace(var.project_id)) > 0
    error_message = "project_id must not be empty."
  }
}

variable "user_groups_ids" {
  description = "Harness user group IDs every ChaosGuard rule applies to. Use '_project_all_users' to block everyone, or a narrower group so SREs/on-call can bypass via a separate group/condition."
  type        = list(string)
  default     = ["_project_all_users"]

  validation {
    condition     = length(var.user_groups_ids) > 0
    error_message = "user_groups_ids must contain at least one user group ID."
  }
}

##############################################################################
# Kubernetes-specific variables
##############################################################################

variable "k8s_prod_infra_ids" {
  description = "Production OSE/Kubernetes chaos infra IDs, composite \"{environmentId}/{infraId}\" (e.g. \"ose-prod/ose-cluster-01\"). Referenced by every condition in k8s-chaos-guard.tf."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.k8s_prod_infra_ids) > 0
    error_message = "k8s_prod_infra_ids must contain at least one Kubernetes chaos infrastructure ID before applying k8s-chaos-guard.tf."
  }

  validation {
    condition     = alltrue([for id in var.k8s_prod_infra_ids : length(split("/", id)) == 2])
    error_message = "Each k8s_prod_infra_ids entry must be in composite \"{environmentId}/{infraId}\" format (e.g. \"awseks/eksnewrtinfra\"), not a bare infra ID."
  }
}

variable "protected_namespaces" {
  description = "Namespaces that must never be targeted by high-impact faults without extra approval."
  type        = list(string)
  default     = ["prod", "payments", "checkout"]
}

variable "service_accounts" {
  description = "Every chaos service account used in this project. Keep in sync with accounts actually in use."
  type        = list(string)
  default     = ["litmus"]

  validation {
    condition     = length(var.service_accounts) > 0
    error_message = "service_accounts must contain at least one chaos service account."
  }
}

##############################################################################
# Linux-specific variables
##############################################################################

variable "linux_prod_infra_ids" {
  description = "Production Linux host/VM chaos infra IDs, composite \"{environmentId}/{infraId}\" (e.g. \"awslinux/prod-vm-pool\")."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.linux_prod_infra_ids) > 0
    error_message = "linux_prod_infra_ids must contain at least one Linux chaos infrastructure ID before applying linux-chaos-guard.tf."
  }

  validation {
    condition     = alltrue([for id in var.linux_prod_infra_ids : length(split("/", id)) == 2])
    error_message = "Each linux_prod_infra_ids entry must be in composite \"{environmentId}/{infraId}\" format (e.g. \"awslinux/prod-vm-pool\"), not a bare infra ID."
  }
}

variable "change_freeze_start_time" {
  description = "Epoch millis start time for the Linux change-freeze window covering all Linux faults (e.g. peak trading days, holiday freezes)."
  type        = number
  default     = 1711238400000 # 2024-03-24T00:00:00Z (adjust per freeze calendar)
}

variable "change_freeze_duration" {
  description = "Duration of each change-freeze occurrence (e.g. '24h')."
  type        = string
  default     = "24h"
}

variable "change_freeze_recurrence_type" {
  description = "Recurrence type for the change-freeze rule (e.g. Daily, Weekly)."
  type        = string
  default     = "Daily"
}

variable "change_freeze_until" {
  description = "Epoch millis at which the change-freeze recurrence ends. Use -1 for no end date."
  type        = number
  default     = -1
}

##############################################################################
# Shared time-window variables
##############################################################################

variable "rule_time_zone" {
  description = "Time zone used for all time windows below (IANA/standard zone name, e.g. UTC, Asia/Dubai)."
  type        = string
  default     = "UTC"

  validation {
    condition     = length(trimspace(var.rule_time_zone)) > 0
    error_message = "rule_time_zone must not be empty."
  }
}

variable "always_on_start_time" {
  description = "Epoch millis start time for the 'always on' (24x7, Daily, no end) rules."
  type        = number
  default     = 1711238400000 # 2024-03-24T00:00:00Z (adjust to a start date relevant to your org)
}

variable "always_on_duration" {
  description = "Duration string for each daily occurrence of the 'always on' rules (e.g. '24h')."
  type        = string
  default     = "24h"
}

variable "business_hours_start_time" {
  description = "Epoch millis start time for the daily business-hours change window during which resource-hog faults are blocked."
  type        = number
  default     = 1711267200000 # 2024-03-24T08:00:00Z (adjust to your business day start)
}

variable "business_hours_duration" {
  description = "Duration of the daily business-hours window (e.g. '9h' for 9-to-5)."
  type        = string
  default     = "9h"
}
