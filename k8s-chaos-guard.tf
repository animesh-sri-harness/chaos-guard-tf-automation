##############################################################################
# ChaosGuard: Kubernetes guardrails (KubernetesV2)
#
# Primary target: OpenShift (OSE). Also works for any KubernetesV2 platform
# (EKS, AKS, GKE, vanilla K8s).
#
# 6 condition/rule pairs. See README.md for the fault inventory and
# per-guardrail summary.
#
# Docs:
#   https://developer.harness.io/docs/resilience-testing/chaos-testing/governance/governance-in-execution/govern-run/
#   https://registry.terraform.io/providers/harness/harness/latest/docs/resources/chaos_security_governance_condition
#   https://registry.terraform.io/providers/harness/harness/0.42.1/docs/resources/chaos_security_governance_rule
##############################################################################

# "Match everything" uses EQUAL_TO against explicit wildcard values (see
# README "Implementation notes"). Service-account wildcards use
# var.service_accounts, the single source of truth for accounts in use.
locals {
  # Kubernetes node-fault catalog, by exact name. See README "Keeping the
  # node-fault list current".
  node_level_faults = [
    "kubelet-service-kill",
    "node-cpu-hog",
    "node-drain",
    "node-io-stress",
    "node-memory-hog",
    "node-network-latency",
    "node-network-loss",
    "node-restart",
    "node-taint",
  ]
}

##############################################################################
# Condition 1: block pod-delete against protected namespaces
##############################################################################

resource "harness_chaos_security_governance_condition" "k8s_block_pod_delete_protected_ns" {
  org_id      = var.org_id
  project_id  = var.project_id
  name        = "block-pod-delete-protected-namespaces"
  description = "Matches the pod-delete fault targeting protected namespaces (payments/checkout/prod)."
  infra_type  = "KubernetesV2"

  fault_spec {
    operator = "EQUAL_TO"

    faults {
      fault_type = "FAULT"
      name       = "pod-delete"
    }
  }

  k8s_spec {
    application_spec {
      operator = "EQUAL_TO"

      dynamic "workloads" {
        for_each = var.protected_namespaces
        content {
          namespace = workloads.value
        }
      }
    }

    # Not filtered by service account.
    chaos_service_account_spec {
      operator         = "EQUAL_TO"
      service_accounts = var.service_accounts
    }

    infra_spec {
      operator  = "EQUAL_TO"
      infra_ids = var.k8s_prod_infra_ids
    }
  }

  tags = ["chaos-guard", "k8s", "pod-delete", "protected-namespace"]
}

resource "harness_chaos_security_governance_rule" "k8s_block_pod_delete_protected_ns" {
  org_id         = var.org_id
  project_id     = var.project_id
  name           = "block-pod-delete-protected-namespaces"
  description    = "Blocks pod-delete from targeting protected/customer-facing namespaces at all times."
  is_enabled     = true
  condition_ids  = [harness_chaos_security_governance_condition.k8s_block_pod_delete_protected_ns.id]
  user_group_ids = var.user_groups_ids
  tags           = ["chaos-guard", "k8s", "pod-delete"]

  time_windows {
    time_zone  = var.rule_time_zone
    start_time = var.always_on_start_time
    duration   = var.always_on_duration

    recurrence {
      type  = "Daily"
      until = -1
    }
  }
}

##############################################################################
# Condition 2: block time-chaos (clock-skew) unconditionally in production
##############################################################################

resource "harness_chaos_security_governance_condition" "k8s_block_time_chaos" {
  org_id      = var.org_id
  project_id  = var.project_id
  name        = "block-time-chaos-prod"
  description = "Matches the time-chaos fault (used by the ssl-certificates-expiration template). Clock-skew faults can break TLS/certificate validation, auth token expiry and scheduler logic cluster-wide."
  infra_type  = "KubernetesV2"

  fault_spec {
    operator = "EQUAL_TO"

    faults {
      fault_type = "FAULT"
      name       = "time-chaos"
    }
  }

  k8s_spec {
    # Filtered by infra only, not namespace/SA.
    application_spec {
      operator = "EQUAL_TO"

      workloads {
        kind      = "*"
        label     = ""
        namespace = ""
      }
    }

    chaos_service_account_spec {
      operator         = "EQUAL_TO"
      service_accounts = var.service_accounts
    }

    infra_spec {
      operator  = "EQUAL_TO"
      infra_ids = var.k8s_prod_infra_ids
    }
  }

  tags = ["chaos-guard", "k8s", "time-chaos", "critical"]
}

resource "harness_chaos_security_governance_rule" "k8s_block_time_chaos" {
  org_id         = var.org_id
  project_id     = var.project_id
  name           = "block-time-chaos-prod"
  description    = "Unconditionally blocks time-chaos experiments against production Kubernetes infra."
  is_enabled     = true
  condition_ids  = [harness_chaos_security_governance_condition.k8s_block_time_chaos.id]
  user_group_ids = var.user_groups_ids
  tags           = ["chaos-guard", "k8s", "time-chaos"]

  time_windows {
    time_zone  = var.rule_time_zone
    start_time = var.always_on_start_time
    duration   = var.always_on_duration

    recurrence {
      type  = "Daily"
      until = -1
    }
  }
}

##############################################################################
# Condition 3: block node-network-loss (zonal/regional outage) in production
##############################################################################

resource "harness_chaos_security_governance_condition" "k8s_block_zonal_regional_outage" {
  org_id      = var.org_id
  project_id  = var.project_id
  name        = "block-zonal-regional-outage-prod"
  description = "Matches the node-network-loss fault (used by highblastradius-zonal-regional-failures) targeting production Kubernetes infra. Simulates a full zonal/regional outage, so it carries the widest blast radius of any deployed fault."
  infra_type  = "KubernetesV2"

  fault_spec {
    operator = "EQUAL_TO"

    faults {
      fault_type = "FAULT"
      name       = "node-network-loss"
    }
  }

  k8s_spec {
    # Filtered by infra only, not namespace/SA.
    application_spec {
      operator = "EQUAL_TO"

      workloads {
        kind      = "*"
        label     = ""
        namespace = ""
      }
    }

    chaos_service_account_spec {
      operator         = "EQUAL_TO"
      service_accounts = var.service_accounts
    }

    infra_spec {
      operator  = "EQUAL_TO"
      infra_ids = var.k8s_prod_infra_ids
    }
  }

  tags = ["chaos-guard", "k8s", "zonal-regional-outage", "critical"]
}

resource "harness_chaos_security_governance_rule" "k8s_block_zonal_regional_outage" {
  org_id         = var.org_id
  project_id     = var.project_id
  name           = "block-zonal-regional-outage-prod"
  description    = "Unconditionally blocks node-network-loss (highblastradius-zonal-regional-failures) against production Kubernetes infra."
  is_enabled     = true
  condition_ids  = [harness_chaos_security_governance_condition.k8s_block_zonal_regional_outage.id]
  user_group_ids = var.user_groups_ids
  tags           = ["chaos-guard", "k8s", "zonal-regional-outage"]

  time_windows {
    time_zone  = var.rule_time_zone
    start_time = var.always_on_start_time
    duration   = var.always_on_duration

    recurrence {
      type  = "Daily"
      until = -1
    }
  }
}

##############################################################################
# Condition 4: block network-disruption faults against protected namespaces
##############################################################################

resource "harness_chaos_security_governance_condition" "k8s_block_network_faults_protected_ns" {
  org_id      = var.org_id
  project_id  = var.project_id
  name        = "block-network-faults-protected-namespaces"
  description = "Matches pod-network-loss, pod-network-latency and pod-api-block targeting protected namespaces (payments/checkout/prod). Covers the standalone pod-network-loss template, k8s-pod-progressive-network-loss, k8s-pod-progressive-network-latency, lowblastradius-zonal-regional-failures and pod-api-block."
  infra_type  = "KubernetesV2"

  fault_spec {
    operator = "EQUAL_TO"

    faults {
      fault_type = "FAULT"
      name       = "pod-network-loss"
    }
    faults {
      fault_type = "FAULT"
      name       = "pod-network-latency"
    }
    faults {
      fault_type = "FAULT"
      name       = "pod-api-block"
    }
  }

  k8s_spec {
    application_spec {
      operator = "EQUAL_TO"

      dynamic "workloads" {
        for_each = var.protected_namespaces
        content {
          namespace = workloads.value
        }
      }
    }

    # Not filtered by service account.
    chaos_service_account_spec {
      operator         = "EQUAL_TO"
      service_accounts = var.service_accounts
    }

    infra_spec {
      operator  = "EQUAL_TO"
      infra_ids = var.k8s_prod_infra_ids
    }
  }

  tags = ["chaos-guard", "k8s", "network", "protected-namespace"]
}

resource "harness_chaos_security_governance_rule" "k8s_block_network_faults_protected_ns" {
  org_id         = var.org_id
  project_id     = var.project_id
  name           = "block-network-faults-protected-namespaces"
  description    = "Blocks network-disruption faults from targeting protected/customer-facing namespaces at all times."
  is_enabled     = true
  condition_ids  = [harness_chaos_security_governance_condition.k8s_block_network_faults_protected_ns.id]
  user_group_ids = var.user_groups_ids
  tags           = ["chaos-guard", "k8s", "network"]

  time_windows {
    time_zone  = var.rule_time_zone
    start_time = var.always_on_start_time
    duration   = var.always_on_duration

    recurrence {
      type  = "Daily"
      until = -1
    }
  }
}

##############################################################################
# Condition 5: freeze resource-hog faults during business hours
##############################################################################

resource "harness_chaos_security_governance_condition" "k8s_block_resource_hogs_business_hours" {
  org_id      = var.org_id
  project_id  = var.project_id
  name        = "block-resource-hogs-business-hours"
  description = "Matches pod-cpu-hog and pod-memory-hog (k8s-pod-progressive-cpu-hog, k8s-pod-progressive-memory-hog) against production Kubernetes infra, to be blocked during business hours."
  infra_type  = "KubernetesV2"

  fault_spec {
    operator = "EQUAL_TO"

    faults {
      fault_type = "FAULT"
      name       = "pod-cpu-hog"
    }
    faults {
      fault_type = "FAULT"
      name       = "pod-memory-hog"
    }
  }

  k8s_spec {
    # Filtered by infra only, not namespace/SA.
    application_spec {
      operator = "EQUAL_TO"

      workloads {
        kind      = "*"
        label     = ""
        namespace = ""
      }
    }

    chaos_service_account_spec {
      operator         = "EQUAL_TO"
      service_accounts = var.service_accounts
    }

    infra_spec {
      operator  = "EQUAL_TO"
      infra_ids = var.k8s_prod_infra_ids
    }
  }

  tags = ["chaos-guard", "k8s", "resource-hog", "business-hours"]
}

resource "harness_chaos_security_governance_rule" "k8s_block_resource_hogs_business_hours" {
  org_id         = var.org_id
  project_id     = var.project_id
  name           = "block-resource-hogs-business-hours"
  description    = "Blocks pod-cpu-hog/pod-memory-hog on production infra during business hours; allowed outside the window or during an approved game day."
  is_enabled     = true
  condition_ids  = [harness_chaos_security_governance_condition.k8s_block_resource_hogs_business_hours.id]
  user_group_ids = var.user_groups_ids
  tags           = ["chaos-guard", "k8s", "resource-hog"]

  time_windows {
    time_zone  = var.rule_time_zone
    start_time = var.business_hours_start_time
    duration   = var.business_hours_duration

    recurrence {
      type  = "Daily"
      until = -1
    }
  }
}

##############################################################################
# Condition 6: block every node-level fault on production Kubernetes infra
##############################################################################

resource "harness_chaos_security_governance_condition" "k8s_block_all_node_faults" {
  org_id      = var.org_id
  project_id  = var.project_id
  name        = "block-all-node-faults"
  description = "Matches every Kubernetes node-level fault (see local.node_level_faults) against production Kubernetes infra. Node-level faults disrupt the node itself, and everything scheduled on it, so application teams must not be able to run any of them, whether or not a template referencing that fault exists today."
  infra_type  = "KubernetesV2"

  fault_spec {
    operator = "EQUAL_TO"

    dynamic "faults" {
      for_each = local.node_level_faults
      content {
        fault_type = "FAULT"
        name       = faults.value
      }
    }
  }

  k8s_spec {
    # Filtered by infra only, not namespace/SA.
    application_spec {
      operator = "EQUAL_TO"

      workloads {
        kind      = "*"
        label     = ""
        namespace = ""
      }
    }

    chaos_service_account_spec {
      operator         = "EQUAL_TO"
      service_accounts = var.service_accounts
    }

    infra_spec {
      operator  = "EQUAL_TO"
      infra_ids = var.k8s_prod_infra_ids
    }
  }

  tags = ["chaos-guard", "k8s", "node-fault", "critical"]
}

resource "harness_chaos_security_governance_rule" "k8s_block_all_node_faults" {
  org_id         = var.org_id
  project_id     = var.project_id
  name           = "block-all-node-faults"
  description    = "Unconditionally blocks every Kubernetes node-level fault against production Kubernetes infra for application teams."
  is_enabled     = true
  condition_ids  = [harness_chaos_security_governance_condition.k8s_block_all_node_faults.id]
  user_group_ids = var.user_groups_ids
  tags           = ["chaos-guard", "k8s", "node-fault"]

  time_windows {
    time_zone  = var.rule_time_zone
    start_time = var.always_on_start_time
    duration   = var.always_on_duration

    recurrence {
      type  = "Daily"
      until = -1
    }
  }
}
