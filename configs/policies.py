from aws_cdk import aws_iam as _iam


class RolePolicyStatements:
    
    def __init__(self):
        pass

    @staticmethod
    def cas_policy_statetement():
        policy_stmnt = [
            _iam.PolicyStatement(
                actions=[
                    "autoscaling:DescribeAutoScalingGroups",
                    "autoscaling:DescribeAutoScalingInstances",
                    "autoscaling:DescribeLaunchConfigurations",
                    "autoscaling:DescribeScalingActivities",
                    "autoscaling:DescribeTags",
                    "ec2:DescribeInstanceTypes",
                    "ec2:DescribeLaunchTemplateVersions"],
                effect=_iam.Effect.ALLOW,
                resources=["*"]
            ),
            _iam.PolicyStatement(
                actions=[
                    "autoscaling:SetDesiredCapacity",
                    "autoscaling:TerminateInstanceInAutoScalingGroup",
                    "autoscaling:UpdateAutoScalingGroup",
                    "ec2:DescribeImages",
                    "ec2:GetInstanceTypesFromInstanceRequirements",
                    "eks:DescribeNodegroup"],
                effect=_iam.Effect.ALLOW,
                resources=["*"]
            )
        ]
        return policy_stmnt
        
    @staticmethod
    def alb_loadbalancer_statement():
        policy_stmnt = [
                    _iam.PolicyStatement(
                    actions=["iam:CreateServiceLinkedRole"],
                    effect=_iam.Effect.ALLOW,
                    resources=["*"],
                    conditions={
                        "StringEquals": {
                            "iam:AWSServiceName": "elasticloadbalancing.amazonaws.com"
                            }
                    },
                    sid="CreateServiceLinkedRoleForElasticLoadBalancing"
                    ),
                    _iam.PolicyStatement(
                        actions=["ec2:DescribeAccountAttributes",
                                 "ec2:DescribeAddresses",
                                 "ec2:DescribeAvailabilityZones",
                                 "ec2:DescribeInternetGateways",
                                 "ec2:DescribeVpcs",
                                 "ec2:DescribeVpcPeeringConnections",
                                 "ec2:DescribeSubnets",
                                 "ec2:DescribeSecurityGroups",
                                 "ec2:DescribeInstances",
                                 "ec2:DescribeNetworkInterfaces",
                                 "ec2:DescribeTags",
                                 "ec2:GetCore",
                                 "ec2:DescribeLaunchTemplates",
                                 "ec2:DescribeKeyPairs",
                                 "elasticloadbalancing:DescribeLoadBalancers",
                                 "elasticloadbalancing:DescribeLoadBalancerAttributes",
                                 "elasticloadbalancing:DescribeListeners",
                                 "elasticloadbalancing:DescribeListenerCertificates",
                                 "elasticloadbalancing:DescribeSSLPolicies",
                                 "elasticloadbalancing:DescribeRules",
                                 "elasticloadbalancing:DescribeTargetGroups",
                                 "elasticloadbalancing:DescribeTargetGroupAttributes",
                                 "elasticloadbalancing:DescribeTargetHealth",
                                 "elasticloadbalancing:DescribeTags"
                                 ],
                        effect=_iam.Effect.ALLOW,
                        resources=["*"]
                    ),
                    _iam.PolicyStatement(
                        actions=["cognito-idp:DescribeUserPoolClient",
                                 "acm:ListCertificates",
                                 "acm:DescribeCertificate",
                                 "iam:ListServerCertificates",
                                 "iam:GetServerCertificate",
                                 "waf-regional:GetWebACL",
                                 "waf-regional:GetWebACLForResource",
                                 "waf-regional:AssociateWebACL",
                                 "waf-regional:DisassociateWebACL",
                                 "wafv2:GetWebACL",
                                 "wafv2:GetWebACLForResource",
                                 "wafv2:AssociateWebACL",
                                 "wafv2:DisassociateWebACL",
                                 "shield:GetSubscriptionState",
                                 "shield:DescribeProtection",
                                 "shield:CreateProtection",
                                 "shield:DeleteProtection"
                                 ],
                        effect=_iam.Effect.ALLOW,
                        resources=["*"]
                    ),
                    _iam.PolicyStatement(
                        actions=["ec2:AuthorizeSecurityGroupIngress",
                                 "ec2:RevokeSecurityGroupIngress"
                                 ],
                        effect=_iam.Effect.ALLOW,
                        resources=["*"]
                    ),
                    _iam.PolicyStatement(
                        actions=["ec2:CreateSecurityGroup"],
                        effect=_iam.Effect.ALLOW,
                        resources=["*"]
                    ),
                    _iam.PolicyStatement(
                        actions=["ec2:CreateTags"],
                        effect=_iam.Effect.ALLOW,
                        resources=["arn:aws:ec2:*:*:security-group/*"],
                        conditions={
                            "StringEquals": {
                                "ec2:CreateAction": "CreateSecurityGroup"
                                },
                            "Null": {
                                "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                           }
                        }
                    ),
                    _iam.PolicyStatement(
                        actions=["ec2:CreateTags",
                                 "ec2:DeleteTags"],
                        effect=_iam.Effect.ALLOW,
                        resources=["arn:aws:ec2:*:*:security-group/*"],
                        conditions={
                            "Null": {
                                "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                                "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                                }
                        }
                    ),
                    _iam.PolicyStatement(
                        actions=["ec2:AuthorizeSecurityGroupIngress",
                                 "ec2:RevokeSecurityGroupIngress",
                                 "ec2:DeleteSecurityGroup"
                                 ],
                        resources=["*"],
                        effect=_iam.Effect.ALLOW,
                        conditions={
                            "Null": {
                                "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                                }
                        }
                    ),
                    _iam.PolicyStatement(
                        actions=["elasticloadbalancing:CreateLoadBalancer",
                                 "elasticloadbalancing:CreateTargetGroup"
                                 ],
                        effect=_iam.Effect.ALLOW,
                        resources=["*"],
                        conditions={
                            "Null": {
                                "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                                }
                        }
                    ),
                    _iam.PolicyStatement(
                        actions=["elasticloadbalancing:CreateListener",
                                 "elasticloadbalancing:DeleteListener",
                                 "elasticloadbalancing:CreateRule",
                                 "elasticloadbalancing:DeleteRule"
                                 ],
                        effect=_iam.Effect.ALLOW,
                        resources=["*"]
                    ),
                    _iam.PolicyStatement(
                        actions=["elasticloadbalancing:AddTags",
                                 "elasticloadbalancing:RemoveTags"
                                 ],
                        effect=_iam.Effect.ALLOW,
                        resources=[
                            "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                            "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                            "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
                            ],
                        conditions={
                            "Null": {
                                "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                                "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                                }
                        }
                    ),
                    _iam.PolicyStatement(
                        actions=["elasticloadbalancing:AddTags",
                                 "elasticloadbalancing:RemoveTags"
                                 ],
                        effect=_iam.Effect.ALLOW,
                        resources=[
                            "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
                            "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
                            "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
                            "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"
                            ],
                    ),
                    _iam.PolicyStatement(
                        actions=["elasticloadbalancing:ModifyLoadBalancerAttributes",
                                 "elasticloadbalancing:SetIpAddressType",
                                 "elasticloadbalancing:SetSecurityGroups",
                                 "elasticloadbalancing:SetSubnets",
                                 "elasticloadbalancing:DeleteLoadBalancer",
                                 "elasticloadbalancing:ModifyTargetGroup",
                                 "elasticloadbalancing:ModifyTargetGroupAttributes",
                                 "elasticloadbalancing:DeleteTargetGroup"
                                 ],
                        effect=_iam.Effect.ALLOW,
                        resources=["*"],
                        conditions={
                            "Null": {
                                "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                                }
                        }
                    ),
                    _iam.PolicyStatement(
                        actions=["elasticloadbalancing:AddTags"],
                        effect=_iam.Effect.ALLOW,
                        resources=["arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                                   "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                                   "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"],
                        conditions={
                            "StringEquals": {
                                "elasticloadbalancing:CreateAction": [
                                    "CreateTargetGroup",
                                    "CreateLoadBalancer"
                                    ]
                               },
                                "Null": {
                                "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                                }  
                             }                                                    
                        ),
                    _iam.PolicyStatement(
                        actions=["elasticloadbalancing:RegisterTargets",
                                 "elasticloadbalancing:DeregisterTargets"
                                 ],
                        effect=_iam.Effect.ALLOW,
                        resources=["arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"]
                    ),
                    _iam.PolicyStatement(
                        actions=["elasticloadbalancing:SetWebAcl",
                                 "elasticloadbalancing:ModifyListener",
                                 "elasticloadbalancing:AddListenerCertificates",
                                 "elasticloadbalancing:RemoveListenerCertificates",
                                 "elasticloadbalancing:ModifyRule"
                                 ],
                        effect=_iam.Effect.ALLOW,
                        resources=["*"]
                    ),
                ]      
        return policy_stmnt


    @staticmethod
    def amp_iamproxy_ingest_statement():
        policy_stmnt = [_iam.PolicyStatement(
                    actions=["aps:RemoteWrite", 
                             "aps:GetSeries", 
                             "aps:GetLabels",
                             "aps:GetMetricMetadata"
                            ],
                    effect=_iam.Effect.ALLOW,
                    resources=["*"],
                    sid="ingestpromteheusmetrics"
                    )]
        return policy_stmnt
    
    @staticmethod
    def amp_iamproxy_query_statement():
        policy_stmnt = [_iam.PolicyStatement(
                    actions=["aps:QueryMetrics",
                             "aps:GetSeries", 
                             "aps:GetLabels",
                             "aps:GetMetricMetadata"
                            ],
                    effect=_iam.Effect.ALLOW,
                    resources=["*"],
                    sid="querypromteheusmetrics"
                    )]
        return policy_stmnt
    

    @staticmethod
    def grafana_managed_statement():
        policy_stmnt = [
                  _iam.ManagedPolicy.from_aws_managed_policy_name("AWSGrafanaAccountAdministrator"),
                  _iam.ManagedPolicy.from_aws_managed_policy_name("AWSSSOMasterAccountAdministrator"),
                  _iam.ManagedPolicy.from_aws_managed_policy_name("AWSOrganizationsFullAccess"),
                  _iam.ManagedPolicy.from_aws_managed_policy_name("AWSSSODirectoryAdministrator"),
                  _iam.ManagedPolicy.from_aws_managed_policy_name("AWSMarketplaceManageSubscriptions"),
              ]               
        return policy_stmnt
    
    @staticmethod
    def grafana_inline_statement(self, acc_id):
        policy_stmnt = [
                    _iam.PolicyStatement(
                        actions=[
                            "aps:ListWorkspaces",
                            "aps:DescribeWorkspace",
                            "aps:QueryMetrics",
                            "aps:GetLabels",
                            "aps:GetSeries",
                            "aps:GetMetricMetadata"
                            ],
                        effect=_iam.Effect.ALLOW,
                        resources=["*"]
                    ),
                    _iam.PolicyStatement(
                        actions=["sns:Publish"],
                        effect=_iam.Effect.ALLOW,
                        resources=[f"arn:aws:sns:*:{acc_id}:grafana*"]
                    ),
              ]               
        return policy_stmnt


    
    @staticmethod
    def eks_cluster_statement():
        policy_stmnt = [
            _iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSWorkerNodePolicy"),
            _iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSClusterPolicy")
        ]               
        return policy_stmnt
    
    @staticmethod
    def eks_worker_statement():
        policy_stmnt = [
            _iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSWorkerNodePolicy"),
            _iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKS_CNI_Policy"),
            _iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ContainerRegistryReadOnly"),
            _iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"),
            _iam.ManagedPolicy.from_aws_managed_policy_name("ElasticLoadBalancingFullAccess")
        ]               
        return policy_stmnt


    @staticmethod
    def eks_master_statement():
        policy_stmnt = [
                  _iam.ManagedPolicy.from_aws_managed_policy_name("AdministratorAccess"),
              ]               
        return policy_stmnt
    
    @staticmethod
    def karp_node_statement():
        policy_stmnt = [
                  _iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSWorkerNodePolicy"),
                  _iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKS_CNI_Policy"),
                  _iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ContainerRegistryReadOnly"),
                  _iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")
              ]               
        return policy_stmnt

    @staticmethod
    def karp_controller_statement(self, clustername, clusterarn, rolearn, region):
        policy_stmnt = [_iam.PolicyStatement(
                    actions=["ssm:GetParameter",
                             "iam:PassRole",
                             "ec2:DescribeImages",
                             "ec2:RunInstances",
                             "ec2:DescribeSubnets",
                             "ec2:DescribeSecurityGroups",
                             "ec2:DescribeLaunchTemplates",
                             "ec2:DescribeInstances",
                             "ec2:DescribeInstanceTypes",
                             "ec2:DescribeInstanceTypeOfferings",
                             "ec2:DescribeAvailabilityZones",
                             "ec2:DeleteLaunchTemplate",
                             "ec2:CreateTags",
                             "ec2:CreateLaunchTemplate",
                             "ec2:CreateFleet",
                             "ec2:DescribeSpotPriceHistory",
                             "pricing:GetProducts"
                            ],
                    effect=_iam.Effect.ALLOW,
                    resources=["*"],
                    sid="karpenter"
                    ),                 
            _iam.PolicyStatement(
                        effect=_iam.Effect.ALLOW,
                        actions=["ec2:TerminateInstances"],
                        resources=["*"],
                        sid="ConditionalEC2Termination",
                        conditions={"StringLike": {"ec2:ResourceTag/karpenter.sh/nodepool": "*"}}
                    ),
            _iam.PolicyStatement(
                      effect=_iam.Effect.ALLOW,
                      actions=["iam:PassRole"],
                      resources=[f"{rolearn}-{clustername}"],
                      sid="PassNodeIAMRole",
                    ),
            _iam.PolicyStatement(
                      effect=_iam.Effect.ALLOW,
                      actions=["eks:DescribeCluster"],
                      resources=[f"{clusterarn}"],
                      sid="EKSClusterEndpointLookup",
                      ),
            _iam.PolicyStatement(
                      effect=_iam.Effect.ALLOW,
                      actions=["eks:DescribeCluster"],
                      resources=[f"{clusterarn}"],
                      sid="EKSClusterEndpointLookup",
                      ),
            _iam.PolicyStatement(
                      effect=_iam.Effect.ALLOW,
                      actions=["iam:CreateInstanceProfile"],
                      resources=["*"],
                      sid="AllowScopedInstanceProfileCreationActions",
                      conditions={
                          "StringEquals": {
                              "aws:RequestTag/kubernetes.io/cluster/{}".format(clustername): "owned",
                              "aws:RequestTag/topology.kubernetes.io/region": f"{region}"
                            },
                          "StringLike": {
                                "aws:RequestTag/karpenter.k8s.aws/ec2nodeclass": "*"
                             },
                          }
                      ),
            _iam.PolicyStatement(
                      effect=_iam.Effect.ALLOW,
                      actions=["iam:TagInstanceProfile"],
                      resources=["*"],
                      sid="AllowScopedInstanceProfileTagActions",
                      conditions={
                          "StringEquals": {
                              "aws:ResourceTag/kubernetes.io/cluster/{}".format(clustername): "owned",
                              "aws:ResourceTag/topology.kubernetes.io/region": f"{region}",
                              "aws:RequestTag/kubernetes.io/cluster/{}".format(clustername): "owned",
                              "aws:RequestTag/topology.kubernetes.io/region": f"{region}"
                            },
                          "StringLike": {
                                "aws:ResourceTag/karpenter.k8s.aws/ec2nodeclass": "*",
                                "aws:RequestTag/karpenter.k8s.aws/ec2nodeclass": "*"
                             },
                          }
                      ),                   
            _iam.PolicyStatement(
                      effect=_iam.Effect.ALLOW,
                      actions=["iam:AddRoleToInstanceProfile",
                               "iam:RemoveRoleFromInstanceProfile",
                               "iam:DeleteInstanceProfile"],
                      resources=["*"],
                      sid="AllowScopedInstanceProfileActions",
                      conditions={
                          "StringEquals": {
                              "aws:ResourceTag/kubernetes.io/cluster/{}".format(clustername): "owned",
                              "aws:ResourceTag/topology.kubernetes.io/region": f"{region}"
                            },
                          "StringLike": {
                              "aws:ResourceTag/karpenter.k8s.aws/ec2nodeclass": "*"
                             },
                          }
                      ),
            _iam.PolicyStatement(
                      effect=_iam.Effect.ALLOW,
                      actions=["iam:GetInstanceProfile"],
                      resources=["*"],
                      sid="AllowInstanceProfileReadActions"
                )          
              ]       
        return policy_stmnt
        
