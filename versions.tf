##############################################################################
# ChaosGuard: Terraform & provider requirements
##############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    harness = {
      source  = "harness/harness"
      version = ">= 0.42.1, < 1.0.0"
    }
  }
}

# Provider credentials are read from the environment and must NOT be hardcoded
# here or in any .tfvars file that gets committed to version control:
#   HARNESS_ACCOUNT_ID       : Harness account ID
#   HARNESS_PLATFORM_API_KEY : Next-Gen platform API key (service account
#                              token recommended for CI/CD use)
#   HARNESS_ENDPOINT         : optional, defaults to https://app.harness.io/gateway
provider "harness" {}
