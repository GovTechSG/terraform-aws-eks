# EKS

This module creates a kubernetes cluster on amazon web services(AWS). This module has a number of assumptions and dependencies with [https://gitlab.com/govtechsingapore/gdsace/terraform-modules/aws-vpc](https://gitlab.com/govtechsingapore/gdsace/terraform-modules/aws-vpc). It will probably not work with other infrastructure design, particularly on your subnet slices.
This module works with the VPC module as it follows the subnet types(public,private,intranet,database) defined in it.

### Usage
```hcl
module "eks" {
  eks_cluster_name = "shire"

  cluster_version = "1.14"

  # user and roles
  # references:
  # 1. [aws-iam-authenticator](https://github.com/kubernetes-sigs/aws-iam-authenticator)
  # 2. [awscli configuration](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)
  map_users = [
    {
      user_arn = "arn:aws:iam::${get_aws_account_id()}:user/USERNAME"
      username = "USERNAME"
      group    = "system:masters"
    }
  ]

  private_worker_variables = [
    {
      instance_type            = "r5.xlarge"
      asg_min_size             = "1"
      asg_desired_capacity     = "2"
      asg_max_size             = "4"
      iam_instance_profile_name = "eks-worker-private"
      ami_id                   = "ami-03a2cce9abe958c6c"
      name                     = "services"
      kubelet_extra_args       = ""
    },
    {
      instance_type            = "c5n.xlarge"
      asg_desired_capacity     = 0
      asg_max_size             = 4
      iam_instance_profile_name = "eks-worker-gitlab"
      ami_id                   = "ami-03a2cce9abe958c6c"
      name                     = "gitlab-runners"
      kubelet_extra_args       = "--register-with-taints=gitlab-runner=true:NoSchedule"
    }
  ]

  public_worker_variables = [
    {
      instance_type            = "m5.large"
      asg_desired_capacity     = 1
      asg_max_size             = 4
      iam_instance_profile_name = "eks-worker-public"
      name                     = "public-1"
      ami_id                   = "ami-03a2cce9abe958c6c"
      kubelet_extra_args       = "--register-with-taints=public=true:NoSchedule --node-labels=public-node=true"
    }
  ]


  cluster_endpoint_private_access = true
  cluster_endpoint_public_access = false
  permissions_boundary = "arn:aws:iam::${get_aws_account_id()}:policy/GCCIAccountBoundary"

  # write_kubeconfig = "true"
  config_output_path = "${get_terragrunt_dir()}/"
  additional_whitelist_cidr_block_443 = ["172.31.0.0/24"]
  additional_whitelist_cidr_block_443_description = ["description"]

  // remote state variables
  vpc_state_key = ""
  artifacts_base_path = get_terragrunt_dir()
  environment = "uat"
}
```


### Migration

#### 1.x.x to 2.x.x
- delete aws-auth configmap as it is now created using k8s provider.
-

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| additional\_whitelist\_cidr\_block\_443 | Additional cidr to allow inbound and outbound for port 443 to eks cluster | list | `<list>` | no |
| additional\_whitelist\_cidr\_block\_443\_description | Description for the additional cidr to allow inbound and outbound for port 443 to eks cluster | list | `<list>` | no |
| aws\_region | Region in which to spin up EKS | string | `"ap-southeast-1"` | no |
| cluster\_endpoint\_private\_access | Indicates whether or not the Amazon EKS private API server endpoint is enabled. | bool | `"false"` | no |
| cluster\_endpoint\_public\_access | Indicates whether or not the Amazon EKS public API server endpoint is enabled. | bool | `"true"` | no |
| cluster\_iam\_role\_name | IAM role name for the cluster. Only applicable if manage_cluster_iam_resources is set to false. | string | `""` | no |
| cluster\_version | Kubernetes version to use for the EKS cluster. | string | `"1.13"` | no |
| config\_output\_path | Where to save the Kubectl config file (if `write_kubeconfig = true`). Should end in a forward slash `/` . | string | `"./"` | no |
| eks\_cluster\_name | Name of the EKS cluster. Also used as a prefix in names of related resources. | string | n/a | yes |
| environment | Name for environment of this EKS cluster | string | n/a | yes |
| intranet\_worker\_variables | Worker group declaration of nodes to be placed in intranet subnet | list | `<list>` | no |
| manage\_aws\_auth | Whether to apply the aws-auth configmap file. | string | `"true"` | no |
| manage\_cluster\_iam\_resources | Whether to let the module manage cluster IAM resources. If set to false, cluster_iam_role_name must be specified. | bool | `"true"` | no |
| manage\_worker\_iam\_resources | Whether to let the module manage worker IAM resources. If set to false, iam_instance_profile_name must be specified for workers. | bool | `"true"` | no |
| map\_accounts | Additional AWS account numbers to add to the aws-auth configmap. | list(string) | `<list>` | no |
| map\_roles | Additional IAM roles to add to the aws-auth configmap. See examples/basic/variables.tf for example format. | list(map(string)) | `<list>` | no |
| map\_users | Additional IAM users to add to the aws-auth configmap. See examples/basic/variables.tf for example format. | list(map(string)) | `<list>` | no |
| module\_source\_version | Version of module to use | string | `"5.0.0"` | no |
| permissions\_boundary | If provided, all IAM roles will be created with this permissions boundary attached. | string | `""` | no |
| private\_worker\_variables | Worker group declaration of nodes to be placed in private subnet | list | `<list>` | no |
| public\_worker\_variables | Worker group declaration of nodes to be placed in public subnet | list | `<list>` | no |
| tags | A map of tags to add to all resources. | map(string) | `<map>` | no |
| tfstate\_global\_bucket | S3 where the remote state is stored | string | n/a | yes |
| vpc\_name | VPC Name | string | n/a | yes |
| vpc\_state\_key | Key where the vpc remote state is stored | string | `"vpc"` | no |
| worker\_additional\_security\_group\_ids | A list of additional security group ids to attach to worker instances | list | `[]]` | no |
| write\_aws\_auth\_config | Whether to write the aws-auth configmap file. | bool | `"true"` | no |
| write\_kubeconfig | Whether to write a Kubectl config file containing the cluster configuration. Saved to `config_output_path`. | bool | `"true"` | no |

## Outputs

| Name | Description |
|------|-------------|
| cloudwatch\_log\_group\_name | Name of cloudwatch log group created |
| cluster\_endpoint | Endpoint for EKS control plane. |
| cluster\_id | The name/id of the EKS cluster. |
| cluster\_security\_group\_id | Security group ids attached to the cluster control plane. |
| cluster\_version | The Kubernetes server version for the EKS cluster. |
| config\_map\_aws\_auth | A kubernetes configuration to authenticate to this EKS cluster. |
| kubectl\_config | kubectl config as generated by the module. |
| workers\_asg\_arns | IDs of the autoscaling groups containing workers. |
| workers\_asg\_names | Names of the autoscaling groups containing workers. |
| workers\_launch\_template\_ids | IDs of the worker launch templates. |
| workers\_user\_data | User data of worker groups |
