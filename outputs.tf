##############################################################################
# ChaosGuard – outputs
##############################################################################

output "k8s_chaos_guard_condition_ids" {
  description = "IDs of all Kubernetes ChaosGuard conditions created by k8s-chaos-guard.tf."
  value = [
    harness_chaos_security_governance_condition.k8s_block_pod_delete_protected_ns.id,
    harness_chaos_security_governance_condition.k8s_block_time_chaos.id,
    harness_chaos_security_governance_condition.k8s_block_zonal_regional_outage.id,
    harness_chaos_security_governance_condition.k8s_block_network_faults_protected_ns.id,
    harness_chaos_security_governance_condition.k8s_require_approved_service_account.id,
    harness_chaos_security_governance_condition.k8s_block_resource_hogs_business_hours.id,
  ]
}

output "k8s_chaos_guard_rule_ids" {
  description = "IDs of all Kubernetes ChaosGuard rules created by k8s-chaos-guard.tf."
  value = [
    harness_chaos_security_governance_rule.k8s_block_pod_delete_protected_ns.id,
    harness_chaos_security_governance_rule.k8s_block_time_chaos.id,
    harness_chaos_security_governance_rule.k8s_block_zonal_regional_outage.id,
    harness_chaos_security_governance_rule.k8s_block_network_faults_protected_ns.id,
    harness_chaos_security_governance_rule.k8s_require_approved_service_account.id,
    harness_chaos_security_governance_rule.k8s_block_resource_hogs_business_hours.id,
  ]
}

output "linux_chaos_guard_condition_ids" {
  description = "IDs of all Linux ChaosGuard conditions created by linux-chaos-guard.tf."
  value = [
    harness_chaos_security_governance_condition.linux_block_process_kill.id,
    harness_chaos_security_governance_condition.linux_block_resource_stress_business_hours.id,
    harness_chaos_security_governance_condition.linux_block_network_faults.id,
    harness_chaos_security_governance_condition.linux_change_freeze_all_faults.id,
  ]
}

output "linux_chaos_guard_rule_ids" {
  description = "IDs of all Linux ChaosGuard rules created by linux-chaos-guard.tf."
  value = [
    harness_chaos_security_governance_rule.linux_block_process_kill.id,
    harness_chaos_security_governance_rule.linux_block_resource_stress_business_hours.id,
    harness_chaos_security_governance_rule.linux_block_network_faults.id,
    harness_chaos_security_governance_rule.linux_change_freeze_all_faults.id,
  ]
}
