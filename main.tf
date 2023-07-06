locals {
  private_worker_groups = [
    for private_worker in var.private_worker_variables : merge({
      subnets = var.worker_private_subnets_ids
    }, private_worker)
  ]

  public_worker_groups = [for public_worker in var.public_worker_variables : merge({
    subnets = var.worker_public_subnets_ids
    }, public_worker)
  ]

  intranet_worker_groups = [for intranet_worker in var.intranet_worker_variables : merge({
    subnets = var.worker_intra_subnets_ids
    }, intranet_worker)
  ]

  worker_groups = flatten([local.private_worker_groups, local.public_worker_groups, local.intranet_worker_groups])

  private_worker_groups_launch_template = [
    for private_worker in var.private_worker_template_variables : merge({
      subnets = var.worker_private_subnets_ids
    }, private_worker)
  ]

  public_worker_groups_launch_template = [for public_worker in var.public_worker_template_variables : merge({
    subnets = var.worker_public_subnets_ids
    }, public_worker)
  ]

  intranet_worker_groups_launch_template = [for intranet_worker in var.intranet_worker_template_variables : merge({
    subnets = var.worker_intra_subnets_ids
    }, intranet_worker)
  ]

  worker_groups_launch_template = flatten([local.private_worker_groups_launch_template, local.public_worker_groups_launch_template, local.intranet_worker_groups_launch_template])

}

# references:
# 1. https://github.com/terraform-aws-modules/terraform-aws-eks
module "eks" {
  source                                         = "terraform-aws-modules/eks/aws"
  version                                        = "15.2.0"
  config_output_path                             = var.config_output_path
  create_eks                                     = var.create_eks
  cluster_name                                   = var.eks_cluster_name
  cluster_version                                = var.cluster_version
  cluster_enabled_log_types                      = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  cluster_endpoint_private_access                = var.cluster_endpoint_private_access
  cluster_endpoint_public_access                 = var.cluster_endpoint_public_access
  cluster_endpoint_public_access_cidrs           = var.cluster_endpoint_public_access_cidrs
  cluster_create_endpoint_private_access_sg_rule = var.cluster_create_endpoint_private_access_sg_rule
  cluster_iam_role_name                          = var.cluster_iam_role_name
  cluster_log_retention_in_days                  = var.cluster_log_retention_in_days
  cluster_encryption_config                      = var.cluster_encryption_config

  kubeconfig_name                              = "${var.eks_cluster_name}-${var.environment}-eks"
  kubeconfig_aws_authenticator_command         = var.kubeconfig_aws_authenticator_command
  kubeconfig_aws_authenticator_command_args    = var.kubeconfig_aws_authenticator_command_args
  kubeconfig_aws_authenticator_additional_args = var.kubeconfig_aws_authenticator_additional_args
  kubeconfig_aws_authenticator_env_variables   = var.kubeconfig_aws_authenticator_env_variables

  manage_cluster_iam_resources  = var.manage_cluster_iam_resources
  manage_worker_iam_resources   = var.manage_worker_iam_resources
  permissions_boundary          = var.permissions_boundary
  map_users                     = var.map_users
  map_roles                     = var.map_roles
  worker_groups                 = local.worker_groups
  worker_groups_launch_template = local.worker_groups_launch_template
  vpc_id                        = var.vpc_id

  #fargate
  create_fargate_pod_execution_role = var.create_fargate_pod_execution_role
  fargate_pod_execution_role_name   = var.fargate_pod_execution_role_name
  fargate_profiles                  = var.fargate_profiles

  subnets = flatten(var.master_subnets_ids)

  workers_additional_policies = concat(
    var.enable_dynamic_pv ? aws_iam_policy.dynamic-persistent-volume-provisioning.*.arn : [],
    var.enable_ssm ? ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore","arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"] : []
  )
  worker_additional_security_group_ids = var.worker_additional_security_group_ids

  tags = {
    Environment = var.environment
  }
}

resource "aws_security_group_rule" "allow_additional_cidr_443_ingress" {
  count       = length(var.additional_whitelist_cidr_block_443) > 0 ? length(var.additional_whitelist_cidr_block_443) : 0
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = [var.additional_whitelist_cidr_block_443[count.index]]

  security_group_id = module.eks.cluster_security_group_id
  description       = var.additional_whitelist_cidr_block_443_description[count.index]
}

resource "aws_iam_policy" "dynamic-persistent-volume-provisioning" {
  count = var.enable_dynamic_pv ? 1 : 0

  name        = "k8sDynamicPVProvisioning-${var.eks_cluster_name}"
  path        = "/"
  description = "Allows EKS nodes to dynamically create and manage ec2 volumes"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteSnapshot",
        "ec2:DeleteTags",
        "ec2:DeleteVolume",
        "ec2:DescribeInstances",
        "ec2:DescribeSnapshots",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role" "external-dns-role" {
  count                = var.enable_external_dns ? 1 : 0
  name                 = "external-dns-role-${var.eks_cluster_name}"
  permissions_boundary = var.permissions_boundary
  assume_role_policy   = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    },
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${module.eks.worker_iam_role_arn}"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}


resource "aws_iam_policy" "external-dns-policy" {
  count = var.enable_external_dns ? 1 : 0

  name        = "K8sExternalDNSPolicy-${var.eks_cluster_name}"
  path        = "/"
  description = "Allows EKS nodes to modify Route53 to support ExternalDNS."

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
      {
            "Effect": "Allow",
            "Action": "route53:GetChange",
            "Resource": "arn:aws:route53:::change/*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "route53:ListHostedZones",
          "route53:ListResourceRecordSets"
        ],
        "Resource": [
          "*"
        ]
      },
      {
        "Effect": "Allow",
        "Action": [
          "route53:ChangeResourceRecordSets"
        ],
        "Resource": [
          "*"
        ]
      }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "external-dns-attach" {
  count      = var.enable_external_dns ? 1 : 0
  role       = aws_iam_role.external-dns-role[0].name
  policy_arn = aws_iam_policy.external-dns-policy[0].arn
}


resource "aws_iam_role" "alb-role" {
  count                = var.enable_alb ? 1 : 0
  name                 = "alb-role-${var.eks_cluster_name}"
  permissions_boundary = var.permissions_boundary
  assume_role_policy   = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    },
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${module.eks.worker_iam_role_arn}"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "alb-ingresscontroller-policy" {
  count       = var.enable_alb ? 1 : 0
  name        = "alb-ingress-controller-policy-${var.eks_cluster_name}"
  description = "Policy for alb ingress controller pod to create alb resources"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "acm:DescribeCertificate",
        "acm:ListCertificates",
        "acm:GetCertificate"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CreateSecurityGroup",
        "ec2:CreateTags",
        "ec2:DeleteTags",
        "ec2:DeleteSecurityGroup",
        "ec2:DescribeAccountAttributes",
        "ec2:DescribeAddresses",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVpcs",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifyNetworkInterfaceAttribute",
        "ec2:RevokeSecurityGroupIngress"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:AddListenerCertificates",
        "elasticloadbalancing:AddTags",
        "elasticloadbalancing:CreateListener",
        "elasticloadbalancing:CreateLoadBalancer",
        "elasticloadbalancing:CreateRule",
        "elasticloadbalancing:CreateTargetGroup",
        "elasticloadbalancing:DeleteListener",
        "elasticloadbalancing:DeleteLoadBalancer",
        "elasticloadbalancing:DeleteRule",
        "elasticloadbalancing:DeleteTargetGroup",
        "elasticloadbalancing:DeregisterTargets",
        "elasticloadbalancing:DescribeListenerCertificates",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DescribeRules",
        "elasticloadbalancing:DescribeSSLPolicies",
        "elasticloadbalancing:DescribeTags",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetGroupAttributes",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticloadbalancing:ModifyListener",
        "elasticloadbalancing:ModifyLoadBalancerAttributes",
        "elasticloadbalancing:ModifyRule",
        "elasticloadbalancing:ModifyTargetGroup",
        "elasticloadbalancing:ModifyTargetGroupAttributes",
        "elasticloadbalancing:RegisterTargets",
        "elasticloadbalancing:RemoveListenerCertificates",
        "elasticloadbalancing:RemoveTags",
        "elasticloadbalancing:SetIpAddressType",
        "elasticloadbalancing:SetSecurityGroups",
        "elasticloadbalancing:SetSubnets",
        "elasticloadbalancing:SetWebACL"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole",
        "iam:GetServerCertificate",
        "iam:ListServerCertificates"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "cognito-idp:DescribeUserPoolClient"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "waf-regional:GetWebACLForResource",
        "waf-regional:GetWebACL",
        "waf-regional:AssociateWebACL",
        "waf-regional:DisassociateWebACL"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "tag:GetResources",
        "tag:TagResources"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "waf:GetWebACL"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "shield:DescribeProtection",
        "shield:GetSubscriptionState",
        "shield:DeleteProtection",
        "shield:CreateProtection",
        "shield:DescribeSubscription",
        "shield:ListProtections"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "alb-attach" {
  count      = var.enable_alb ? 1 : 0
  role       = aws_iam_role.alb-role[0].name
  policy_arn = aws_iam_policy.alb-ingresscontroller-policy[0].arn
}

resource "aws_iam_role" "kamus-role" {
  count                = var.enable_kamus ? 1 : 0
  name                 = "kamus-role-${var.eks_cluster_name}"
  permissions_boundary = var.permissions_boundary
  assume_role_policy   = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    },
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${module.eks.worker_iam_role_arn}"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "kamus-kms-policy" {
  count       = var.enable_kamus ? 1 : 0
  name        = "kamus-kms-policy-${var.eks_cluster_name}"
  description = "Policy for kamus to encrypt, decrypt and generateDataKey for k8s secrets"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": [
        "arn:aws:kms:${var.aws_region}:${var.aws_account_id}:key/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "kms:CreateAlias",
      "Resource": [
        "arn:aws:kms:${var.aws_region}:${var.aws_account_id}:alias/kamus*",
        "arn:aws:kms:${var.aws_region}:${var.aws_account_id}:key/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "kms:CreateKey",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "kamus-attach" {
  count      = var.enable_kamus ? 1 : 0
  role       = aws_iam_role.kamus-role[0].name
  policy_arn = aws_iam_policy.kamus-kms-policy[0].arn
}

resource "aws_eks_addon" "vpc-cni" {
  count = var.addon_create_vpc_cni ? 1 : 0

  cluster_name      = module.eks.cluster_id
  addon_name        = "vpc-cni"
  resolve_conflicts = "OVERWRITE"
  addon_version     = var.addon_vpc_cni_version

  tags = var.tags
}

resource "aws_eks_addon" "kube-proxy" {
  count = var.addon_create_kube_proxy ? 1 : 0

  cluster_name      = module.eks.cluster_id
  addon_name        = "kube-proxy"
  resolve_conflicts = "OVERWRITE"
  addon_version     = var.addon_kube_proxy_version

  tags = var.tags
}

resource "aws_eks_addon" "coredns" {
  count = var.addon_create_coredns ? 1 : 0

  cluster_name      = module.eks.cluster_id
  addon_name        = "coredns"
  resolve_conflicts = "OVERWRITE"
  addon_version     = var.addon_coredns_version

  tags = var.tags
}

data "terraform_remote_state" "vpc" {
  backend = "s3"

  config = {
    region = "${var.aws_region}"
    bucket = "${var.tfstate_global_bucket}"
    key    = "${var.vpc_state_key}"
  }
}
