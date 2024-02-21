variable "aws_region" {
  description = "Region in which to spin up EKS"
  default     = "ap-southeast-1"
}

variable "aws_account_id" {
  description = "AWS account ID"
  default     = "*"
}

variable "additional_subnets" {
  description = "Additional Subnets aside from those in your main vpc(e.g secondary cidr blocks)"
  type        = list(any)
  default     = []
}

variable "additional_whitelist_cidr_block_443" {
  description = "Additional cidr to allow inbound and outbound for port 443 to eks cluster"
  type        = list(any)
  default     = []
}

variable "additional_whitelist_cidr_block_443_description" {
  description = "Description for the additional cidr to allow inbound and outbound for port 443 to eks cluster"
  type        = list(any)
  default     = []
}

variable "cluster_version" {
  description = "Kubernetes version to use for the EKS cluster."
  type        = string
  default     = "1.13"
}

variable "cluster_endpoint_private_access" {
  description = "Indicates whether or not the Amazon EKS private API server endpoint is enabled."
  type        = bool
  default     = false
}

variable "cluster_endpoint_public_access" {
  description = "Indicates whether or not the Amazon EKS public API server endpoint is enabled."
  type        = bool
  default     = true
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "List of CIDR blocks which can access the Amazon EKS public API server endpoint."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "cluster_create_endpoint_private_access_sg_rule" {
  description = "Whether to create security group rules for the access to the Amazon EKS private API server endpoint."
  type        = bool
  default     = false
}

variable "cluster_log_retention_in_days" {
  description = "Log retention in days"
  type        = number
  default     = 90
}

variable "cluster_encryption_config" {
  description = "Configuration block with encryption configuration for the cluster. See examples/secrets_encryption/main.tf for example format"
  type = list(object({
    provider_key_arn = string
    resources        = list(string)
  }))
  default = []
}

variable "environment" {
  description = "Name for environment of this EKS cluster"
}

variable "enable_external_dns" {
  description = "(Legacy) Enables External DNS installation(policy) and attaches policy to worker groups"
  type        = bool
  default     = false
}

variable "enable_ssm" {
  description = "Enables SSM and Inspector"
  type        = bool
  default     = false
}

variable "enable_dynamic_pv" {
  description = "Enables dynamic persistent volume provisioning by allowing nodes to manage ec2 volumes and attaches policy to worker groups"
  type        = bool
  default     = false
}

variable "enable_kamus" {
  description = "(Legacy) Enables kamus by creating role, policy and trust relationship required for kamus usage"
  type        = bool
  default     = false
}

variable "enable_kube2iam" {
  description = "(Legacy) Enables kube2iam by creating role, policy and trust relationship required for kube2iam usage"
  type        = bool
  default     = false
}

variable "enable_alb" {
  description = "Enables alb by creating alb ingress controller policy required for alb ingress controller"
  type        = bool
  default     = false
}

variable "eks_cluster_name" {
  description = "Name of the EKS cluster. Also used as a prefix in names of related resources."
  type        = string
}

variable "tfstate_global_bucket" {
  description = "S3 where the remote state is stored"
}

variable "vpc_state_key" {
  description = "Key where the vpc remote state is stored"
  default     = "vpc"
}

variable "vpc_name" {
  description = "VPC Name"
}

variable "vpc_id" {
  description = "VPC ID"
}

variable "master_subnets_ids" {
  description = "Subnets used by EKS master nodes"
  type        = list(list(string))
}

variable "worker_public_subnets_ids" {
  description = "Public subnets used by worker nodes"
  type        = set(string)
}

variable "worker_private_subnets_ids" {
  description = "Private subnets used by worker nodes"
  type        = set(string)
}

variable "worker_intra_subnets_ids" {
  description = "Intra subnets used by worker nodes"
  type        = set(string)
}

variable "config_output_path" {
  description = "Where to save the Kubectl config file (if `write_kubeconfig = true`). Should end in a forward slash `/` ."
  type        = string
  default     = "./"
}

variable "intranet_worker_variables" {
  description = "Worker group declaration of nodes to be placed in intranet subnet"
  type        = list(any)
  default     = []
}

variable "intranet_worker_template_variables" {
  description = "Worker launch template group declaration of nodes to be placed in intranet subnet"
  type        = list(any)
  default     = []
}

variable "use_launch_template" {
  description = "Toggle use of launch template vs launch configuration"
  type        = bool
  default     = false
}

variable "write_kubeconfig" {
  description = "Whether to write a Kubectl config file containing the cluster configuration. Saved to `config_output_path`."
  type        = bool
  default     = true
}

variable "manage_aws_auth" {
  description = "Whether to apply the aws-auth configmap file."
  default     = true
}

variable "write_aws_auth_config" {
  description = "Whether to write the aws-auth configmap file."
  type        = bool
  default     = true
}

variable "map_accounts" {
  description = "Additional AWS account numbers to add to the aws-auth configmap."
  type        = list(string)

  default = []
}

variable "map_roles" {
  description = "Additional IAM roles to add to the aws-auth configmap."
  type = list(object({
    rolearn  = string
    username = string
    groups   = list(string)
  }))

  default = []
}

variable "map_users" {
  description = "Additional IAM users to add to the aws-auth configmap."
  type = list(object({
    userarn  = string
    username = string
    groups   = list(string)
  }))

  default = []
}

variable "module_source_version" {
  description = "Version of module to use"
  default     = "5.0.0"
}

variable "private_worker_variables" {
  description = "Worker group declaration of nodes to be placed in private subnet"
  type        = list(any)
  default     = []
}

variable "private_worker_template_variables" {
  description = "Worker launch template group declaration of nodes to be placed in private subnet"
  type        = list(any)
  default     = []
}

variable "public_worker_variables" {
  description = "Worker group declaration of nodes to be placed in public subnet"
  type        = list(any)
  default     = []
}

variable "public_worker_template_variables" {
  description = "Worker launch template group declaration of nodes to be placed in public subnet"
  type        = list(any)
  default     = []
}

variable "permissions_boundary" {
  description = "If provided, all IAM roles will be created with this permissions boundary attached."
  type        = string
  default     = ""
}

variable "tags" {
  description = "A map of tags to add to all resources."
  type        = map(string)
  default     = {}
}

variable "manage_cluster_iam_resources" {
  description = "Whether to let the module manage cluster IAM resources. If set to false, cluster_iam_role_name must be specified."
  type        = bool
  default     = true
}

variable "cluster_iam_role_name" {
  description = "IAM role name for the cluster. Only applicable if manage_cluster_iam_resources is set to false."
  type        = string
  default     = ""
}

variable "manage_worker_iam_resources" {
  description = "Whether to let the module manage worker IAM resources. If set to false, iam_instance_profile_name must be specified for workers."
  type        = bool
  default     = true
}

variable "kubeconfig_aws_authenticator_command" {
  description = "Command to use to fetch AWS EKS credentials."
  type        = string
  default     = "aws-iam-authenticator"
}

variable "kubeconfig_aws_authenticator_command_args" {
  description = "Default arguments passed to the authenticator command. Defaults to [token -i $cluster_name]."
  type        = list(string)
  default     = []
}

variable "kubeconfig_aws_authenticator_additional_args" {
  description = "Any additional arguments to pass to the authenticator such as the role to assume. e.g. [\"-r\", \"MyEksRole\"]."
  type        = list(string)
  default     = []
}

variable "kubeconfig_aws_authenticator_env_variables" {
  description = "Environment variables that should be used when executing the authenticator. e.g. { AWS_PROFILE = \"eks\"}."
  type        = map(string)
  default     = {}
}

variable "worker_additional_security_group_ids" {
  description = "A list of additional security group ids to attach to worker instances."
  type        = list(any)
  default     = []
}

variable "create_eks" {
  description = "Controls if EKS resources should be created (it affects almost all resources)"
  type        = bool
  default     = true
}

## Fargate variables

variable "fargate_profiles" {
  description = "Fargate profiles to create. See `fargate_profile` keys section in fargate submodule's README.md for more details"
  type        = any
  default     = {}
}

variable "create_fargate_pod_execution_role" {
  description = "Controls if the EKS Fargate pod execution IAM role should be created."
  type        = bool
  default     = true
}

variable "fargate_pod_execution_role_name" {
  description = "The IAM Role that provides permissions for the EKS Fargate Profile."
  type        = string
  default     = null
}

# addons (v1.18+ only)
variable "addon_create_vpc_cni" {
  description = "Use EKS built-in addon VPC CNI"
  type        = bool
  default     = false
}

variable "addon_create_kube_proxy" {
  description = "Use EKS built-in addon Kube Proxy"
  type        = bool
  default     = false
}

variable "addon_create_coredns" {
  description = "Use EKS built-in addon CoreDNS"
  type        = bool
  default     = false
}

variable "addon_vpc_cni_version" {
  description = "Specify VPC CNI addon version"
  type        = string
  default     = ""
}

variable "addon_kube_proxy_version" {
  description = "Specify Kube Proxy addon version"
  type        = string
  default     = ""
}

variable "addon_coredns_version" {
  description = "Specify CoreDNS addon version"
  type        = string
  default     = ""
}

variable "workers_additional_policies" {
  type = list(string)
  description = "Additional IAM policies to be added to workers"
  default = []

  validation {
    condition = anytrue([
      alltrue([
        for policy_arn in var.workers_additional_policies : can(regex("^arn:aws:iam::(?:\\d{12}|aws):policy/.+", policy_arn))
      ]),
      length(var.workers_additional_policies) == 0
    ])

    error_message = "'workers_additional_policies' must be a list of valid IAM policies's ARN."
  }
}

variable "workers_custom_policy" {
  description = "Custom IAM policy to be added to workers (supports heredoc syntax, e.g. <<EOF ... EOF)"
  type        = string
  default     = ""

  validation {
    condition = anytrue([
      can(jsondecode(var.workers_custom_policy)),
      length(var.workers_custom_policy) == 0
    ])

    error_message = "'workers_custom_policy' must be a valid JSON string."
  }
}
