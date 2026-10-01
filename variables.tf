##############################################################################
# ChaosGuard: shared variables
#
# Consumed by both k8s-chaos-guard.tf and linux-chaos-guard.tf.
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

variable "approver_user_group_ids" {
  description = "Harness user group IDs that every ChaosGuard rule in this module applies to. Use '_project_all_users' to block everyone, or a narrower group of non-admin engineers so SREs/on-call can bypass via a separate group/condition."
  type        = list(string)
  default     = ["_project_all_users"]

  validation {
    condition     = length(var.approver_user_group_ids) > 0
    error_message = "approver_user_group_ids must contain at least one user group ID."
  }
}

##############################################################################
# Kubernetes-specific variables
##############################################################################

variable "k8s_prod_infra_ids" {
  description = "Chaos infrastructure IDs (Harness Delegate or Dedicated Chaos Infra) representing production Kubernetes clusters that the Kubernetes guardrails must protect. Must contain at least one ID, since every condition in k8s-chaos-guard.tf references infra_spec, and the Harness API rejects k8s_spec without it (and infra_spec.infra_ids rejects an empty list)."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.k8s_prod_infra_ids) > 0
    error_message = "k8s_prod_infra_ids must contain at least one Kubernetes chaos infrastructure ID before applying k8s-chaos-guard.tf."
  }
}

variable "protected_namespaces" {
  description = "Kubernetes namespaces (e.g. payments, checkout, prod) that should never be targeted by high-impact faults without extra approval."
  type        = list(string)
  default     = ["prod", "payments", "checkout"]
}

variable "allowed_chaos_service_accounts" {
  description = "Chaos service accounts that are approved to run the pod-api-block fault. Runs using any other service account (e.g. default) are blocked."
  type        = list(string)
  default     = ["litmus", "chaos-service-account"]
}

variable "openshift_prod_infra_ids" {
  description = "Chaos infrastructure IDs representing production OpenShift clusters. OpenShift is registered with Harness Chaos Engineering the same way as any other Kubernetes target (infra_type = \"KubernetesV2\"), so this is just a separate pool of infra IDs from k8s_prod_infra_ids: it scopes the node-fault blanket-block guardrail (see k8s-chaos-guard.tf) to OpenShift infra only, without changing behavior on EKS or any other Kubernetes infra already covered by k8s_prod_infra_ids. Must contain at least one ID."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.openshift_prod_infra_ids) > 0
    error_message = "openshift_prod_infra_ids must contain at least one OpenShift chaos infrastructure ID before applying the node-fault guardrail in k8s-chaos-guard.tf."
  }
}

##############################################################################
# Linux-specific variables
##############################################################################

variable "linux_prod_infra_ids" {
  description = "Chaos infrastructure IDs representing production Linux hosts/VMs that the Linux guardrails must protect. Must contain at least one ID, since the Harness API rejects machine_spec.infra_spec.infra_ids with an empty list."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.linux_prod_infra_ids) > 0
    error_message = "linux_prod_infra_ids must contain at least one Linux chaos infrastructure ID before applying linux-chaos-guard.tf."
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
  description = "Epoch millis start time for the 'always on' (24x7, Daily, no end) rules, e.g. pod-delete, time-chaos, zonal/regional-outage, network-fault and process-kill blocks."
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
