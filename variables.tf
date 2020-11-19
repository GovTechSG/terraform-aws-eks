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
  type        = list
  default     = []
}

variable "additional_whitelist_cidr_block_443" {
  description = "Additional cidr to allow inbound and outbound for port 443 to eks cluster"
  type        = list
  default     = []
}

variable "additional_whitelist_cidr_block_443_description" {
  description = "Description for the additional cidr to allow inbound and outbound for port 443 to eks cluster"
  type        = list
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

variable "environment" {
  description = "Name for environment of this EKS cluster"
}

variable "enable_external_dns" {
  description = "Enables External DNS installation(policy) and attaches policy to worker groups"
  type        = bool
  default     = false
}

variable "enable_dynamic_pv" {
  description = "Enables dynamic persistent volume provisioning by allowing nodes to manage ec2 volumes and attaches policy to worker groups"
  type        = bool
  default     = false
}

variable "enable_kamus" {
  description = "Enables kamus by creating role, policy and trust relationship required for kamus usage"
  type        = bool
  default     = false
}

variable "enable_kube2iam" {
  description = "Enables kube2iam by creating role, policy and trust relationship required for kube2iam usage"
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

variable "config_output_path" {
  description = "Where to save the Kubectl config file (if `write_kubeconfig = true`). Should end in a forward slash `/` ."
  type        = string
  default     = "./"
}

variable "intranet_worker_variables" {
  description = "Worker group declaration of nodes to be placed in intranet subnet"
  type        = list
  default     = []
}

variable "intranet_worker_template_variables" {
  description = "Worker launch template group declaration of nodes to be placed in intranet subnet"
  type        = list
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
  type        = list
  default     = []
}

variable "private_worker_template_variables" {
  description = "Worker launch template group declaration of nodes to be placed in private subnet"
  type        = list
  default     = []
}

variable "public_worker_variables" {
  description = "Worker group declaration of nodes to be placed in public subnet"
  type        = list
  default     = []
}

variable "public_worker_template_variables" {
  description = "Worker launch template group declaration of nodes to be placed in public subnet"
  type        = list
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
  type        = list
  default     = []
}
