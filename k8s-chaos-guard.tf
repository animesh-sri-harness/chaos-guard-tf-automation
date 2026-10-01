##############################################################################
# ChaosGuard: Kubernetes (KubernetesV2) guardrails
#
# 7 condition/rule pairs. See README.md for the fault inventory and
# per-guardrail summary; variables in variables.tf, outputs in outputs.tf.
#
# Docs:
#   https://developer.harness.io/docs/resilience-testing/chaos-testing/governance/governance-in-execution/govern-run/
#   https://registry.terraform.io/providers/harness/harness/latest/docs/resources/chaos_security_governance_condition
#   https://registry.terraform.io/providers/harness/harness/0.42.1/docs/resources/chaos_security_governance_rule
##############################################################################

# k8s_spec requires all three sub-specs (application_spec,
# chaos_service_account_spec, infra_spec) even when a condition only
# filters on one. This fake service account is a NOT_EQUAL_TO "match
# everything" placeholder for chaos_service_account_spec when a condition
# isn't meant to filter by service account.
locals {
  match_all_chaos_service_account = ["__chaos-guard-match-all__"]

  # Complete Kubernetes "node fault" catalog (docs link below). Listed
  # explicitly because the condition API matches faults by exact name;
  # there's no "match this whole category" operator to rely on instead.
  #
  # Excludes "Kubelet density": that's a separate "Kube-Resilience" fault,
  # not a standard node fault. Add it here too if it should also be blocked.
  #
  # Docs: https://developer.harness.io/resilience-testing/chaos-engineering/faults/chaos-fault-categories/kubernetes/node
  # To refresh this list, re-check that page or query:
  #   harness_list(resource_type="chaos_fault", filters={category: "node", infrastructure: "KubernetesV2"})
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

    # Wildcard: this condition doesn't filter by service account.
    chaos_service_account_spec {
      operator         = "NOT_EQUAL_TO"
      service_accounts = local.match_all_chaos_service_account
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
  user_group_ids = var.approver_user_group_ids
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
    # Wildcards: this condition only filters by infra, not namespace/SA.
    application_spec {
      operator = "NOT_EQUAL_TO"
    }

    chaos_service_account_spec {
      operator         = "NOT_EQUAL_TO"
      service_accounts = local.match_all_chaos_service_account
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
  user_group_ids = var.approver_user_group_ids
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
    # Wildcards: this condition only filters by infra, not namespace/SA.
    application_spec {
      operator = "NOT_EQUAL_TO"
    }

    chaos_service_account_spec {
      operator         = "NOT_EQUAL_TO"
      service_accounts = local.match_all_chaos_service_account
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
  user_group_ids = var.approver_user_group_ids
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

    # Wildcard: this condition doesn't filter by service account.
    chaos_service_account_spec {
      operator         = "NOT_EQUAL_TO"
      service_accounts = local.match_all_chaos_service_account
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
  user_group_ids = var.approver_user_group_ids
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
# Condition 5: require an approved chaos service account for pod-api-block
##############################################################################

resource "harness_chaos_security_governance_condition" "k8s_require_approved_service_account" {
  org_id      = var.org_id
  project_id  = var.project_id
  name        = "require-approved-sa-for-pod-api-block"
  description = "Matches pod-api-block run using anything other than an approved chaos service account."
  infra_type  = "KubernetesV2"

  fault_spec {
    operator = "EQUAL_TO"

    faults {
      fault_type = "FAULT"
      name       = "pod-api-block"
    }
  }

  k8s_spec {
    # Wildcard: this condition doesn't filter by namespace.
    application_spec {
      operator = "NOT_EQUAL_TO"
    }

    chaos_service_account_spec {
      operator         = "NOT_EQUAL_TO"
      service_accounts = var.allowed_chaos_service_accounts
    }

    infra_spec {
      operator  = "EQUAL_TO"
      infra_ids = var.k8s_prod_infra_ids
    }
  }

  tags = ["chaos-guard", "k8s", "service-account", "app-level"]
}

resource "harness_chaos_security_governance_rule" "k8s_require_approved_service_account" {
  org_id         = var.org_id
  project_id     = var.project_id
  name           = "require-approved-sa-for-pod-api-block"
  description    = "Blocks pod-api-block unless run with an approved chaos service account."
  is_enabled     = true
  condition_ids  = [harness_chaos_security_governance_condition.k8s_require_approved_service_account.id]
  user_group_ids = var.approver_user_group_ids
  tags           = ["chaos-guard", "k8s", "service-account"]

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
# Condition 6: freeze resource-hog faults during business hours
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
    # Wildcards: this condition only filters by infra, not namespace/SA.
    application_spec {
      operator = "NOT_EQUAL_TO"
    }

    chaos_service_account_spec {
      operator         = "NOT_EQUAL_TO"
      service_accounts = local.match_all_chaos_service_account
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
  user_group_ids = var.approver_user_group_ids
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
# Condition 7: block every node-level fault on OpenShift
#
# Blocks the complete node-fault catalog (local.node_level_faults) so a
# newly added node-fault template can't slip through unprotected, even if
# no template references it yet.
#
# Scoped to var.openshift_prod_infra_ids only; EKS (var.k8s_prod_infra_ids)
# and all other guardrails above are unaffected.
##############################################################################

resource "harness_chaos_security_governance_condition" "k8s_block_all_node_faults_openshift" {
  org_id      = var.org_id
  project_id  = var.project_id
  name        = "block-all-node-faults-openshift"
  description = "Matches every Kubernetes node-level fault (see local.node_level_faults) against the OpenShift chaos infrastructure. Node-level faults disrupt the node itself, and everything scheduled on it, so application teams must not be able to run any of them, whether or not a template referencing that fault exists today."
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
    # Wildcards: this condition only filters by infra, not namespace/SA.
    application_spec {
      operator = "NOT_EQUAL_TO"
    }

    chaos_service_account_spec {
      operator         = "NOT_EQUAL_TO"
      service_accounts = local.match_all_chaos_service_account
    }

    infra_spec {
      operator  = "EQUAL_TO"
      infra_ids = var.openshift_prod_infra_ids
    }
  }

  tags = ["chaos-guard", "k8s", "node-fault", "openshift", "critical"]
}

resource "harness_chaos_security_governance_rule" "k8s_block_all_node_faults_openshift" {
  org_id         = var.org_id
  project_id     = var.project_id
  name           = "block-all-node-faults-openshift"
  description    = "Unconditionally blocks every Kubernetes node-level fault against the OpenShift chaos infrastructure for application teams."
  is_enabled     = true
  condition_ids  = [harness_chaos_security_governance_condition.k8s_block_all_node_faults_openshift.id]
  user_group_ids = var.approver_user_group_ids
  tags           = ["chaos-guard", "k8s", "node-fault", "openshift"]

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
