##############################################################################
# ChaosGuard – Linux guardrails
#
# 4 condition/rule pairs covering the Linux fault catalog: linux-cpu-stress,
# linux-memory-stress, linux-network-latency, linux-network-loss, and
# process-kill. See README.md for the fault inventory and per-guardrail
# summary; variables are declared in variables.tf, outputs in outputs.tf.
#
# Docs:
#   https://developer.harness.io/docs/resilience-testing/chaos-testing/governance/governance-in-execution/govern-run/
#   https://registry.terraform.io/providers/harness/harness/latest/docs/resources/chaos_security_governance_condition
#   https://registry.terraform.io/providers/harness/harness/0.42.1/docs/resources/chaos_security_governance_rule
##############################################################################

##############################################################################
# Condition 1 — block process-kill unconditionally on production Linux infra
##############################################################################

resource "harness_chaos_security_governance_condition" "linux_block_process_kill" {
  org_id      = var.org_id
  project_id  = var.project_id
  name        = "block-process-kill-prod"
  description = "Matches the process-kill fault against production Linux infra. Killing a process outright is one of the most destructive faults available and should always require an explicit, separately-approved exception."
  infra_type  = "Linux"

  fault_spec {
    operator = "EQUAL_TO"

    faults {
      fault_type = "FAULT"
      name       = "process-kill"
    }
  }

  machine_spec {
    infra_spec {
      operator  = "EQUAL_TO"
      infra_ids = var.linux_prod_infra_ids
    }
  }

  tags = ["chaos-guard", "linux", "process-kill", "critical"]
}

resource "harness_chaos_security_governance_rule" "linux_block_process_kill" {
  org_id         = var.org_id
  project_id     = var.project_id
  name           = "block-process-kill-prod"
  description    = "Unconditionally blocks process-kill experiments against production Linux infra."
  is_enabled     = true
  condition_ids  = [harness_chaos_security_governance_condition.linux_block_process_kill.id]
  user_group_ids = var.approver_user_group_ids
  tags           = ["chaos-guard", "linux", "process-kill"]

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
# Condition 2 — freeze CPU/memory stress faults during business hours
##############################################################################

resource "harness_chaos_security_governance_condition" "linux_block_resource_stress_business_hours" {
  org_id      = var.org_id
  project_id  = var.project_id
  name        = "block-resource-stress-business-hours"
  description = "Matches linux-cpu-stress and linux-memory-stress against production Linux infra, to be blocked during business hours."
  infra_type  = "Linux"

  fault_spec {
    operator = "EQUAL_TO"

    faults {
      fault_type = "FAULT"
      name       = "linux-cpu-stress"
    }
    faults {
      fault_type = "FAULT"
      name       = "linux-memory-stress"
    }
  }

  machine_spec {
    infra_spec {
      operator  = "EQUAL_TO"
      infra_ids = var.linux_prod_infra_ids
    }
  }

  tags = ["chaos-guard", "linux", "resource-hog", "business-hours"]
}

resource "harness_chaos_security_governance_rule" "linux_block_resource_stress_business_hours" {
  org_id         = var.org_id
  project_id     = var.project_id
  name           = "block-resource-stress-business-hours"
  description    = "Blocks linux-cpu-stress/linux-memory-stress on production Linux infra during business hours; allowed outside the window or during an approved game day."
  is_enabled     = true
  condition_ids  = [harness_chaos_security_governance_condition.linux_block_resource_stress_business_hours.id]
  user_group_ids = var.approver_user_group_ids
  tags           = ["chaos-guard", "linux", "resource-hog"]

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
# Condition 3 — block network faults against production Linux infra
##############################################################################

resource "harness_chaos_security_governance_condition" "linux_block_network_faults" {
  org_id      = var.org_id
  project_id  = var.project_id
  name        = "block-network-faults-prod"
  description = "Matches linux-network-latency and linux-network-loss against production Linux infra. Network faults on VM-based workloads tend to have a wide, hard-to-reverse blast radius."
  infra_type  = "Linux"

  fault_spec {
    operator = "EQUAL_TO"

    faults {
      fault_type = "FAULT"
      name       = "linux-network-latency"
    }
    faults {
      fault_type = "FAULT"
      name       = "linux-network-loss"
    }
  }

  machine_spec {
    infra_spec {
      operator  = "EQUAL_TO"
      infra_ids = var.linux_prod_infra_ids
    }
  }

  tags = ["chaos-guard", "linux", "network"]
}

resource "harness_chaos_security_governance_rule" "linux_block_network_faults" {
  org_id         = var.org_id
  project_id     = var.project_id
  name           = "block-network-faults-prod"
  description    = "Blocks linux-network-latency/linux-network-loss against production Linux infra at all times."
  is_enabled     = true
  condition_ids  = [harness_chaos_security_governance_condition.linux_block_network_faults.id]
  user_group_ids = var.approver_user_group_ids
  tags           = ["chaos-guard", "linux", "network"]

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
# Condition 4 — change-freeze covering all Linux faults
##############################################################################

resource "harness_chaos_security_governance_condition" "linux_change_freeze_all_faults" {
  org_id      = var.org_id
  project_id  = var.project_id
  name        = "change-freeze-all-linux-faults"
  description = "Matches every Linux fault guarded by this module (linux-cpu-stress, linux-memory-stress, linux-network-latency, linux-network-loss) against production infra, for use during org-wide change-freeze periods."
  infra_type  = "Linux"

  fault_spec {
    operator = "EQUAL_TO"

    faults {
      fault_type = "FAULT"
      name       = "linux-cpu-stress"
    }
    faults {
      fault_type = "FAULT"
      name       = "linux-memory-stress"
    }
    faults {
      fault_type = "FAULT"
      name       = "linux-network-latency"
    }
    faults {
      fault_type = "FAULT"
      name       = "linux-network-loss"
    }
  }

  machine_spec {
    infra_spec {
      operator  = "EQUAL_TO"
      infra_ids = var.linux_prod_infra_ids
    }
  }

  tags = ["chaos-guard", "linux", "change-freeze"]
}

resource "harness_chaos_security_governance_rule" "linux_change_freeze_all_faults" {
  org_id         = var.org_id
  project_id     = var.project_id
  name           = "change-freeze-all-linux-faults"
  description    = "Single toggle to block all Linux chaos experiments against production infra during a change-freeze window (e.g. peak trading days, holiday freezes)."
  is_enabled     = true
  condition_ids  = [harness_chaos_security_governance_condition.linux_change_freeze_all_faults.id]
  user_group_ids = var.approver_user_group_ids
  tags           = ["chaos-guard", "linux", "change-freeze"]

  time_windows {
    time_zone  = var.rule_time_zone
    start_time = var.change_freeze_start_time
    duration   = var.change_freeze_duration

    recurrence {
      type  = var.change_freeze_recurrence_type
      until = var.change_freeze_until
    }
  }
}
