import yaml
import os
import ssl
import json
import hashlib
from aws_cdk import (
    Aws,
    Tags,
    aws_aps as aps,
    aws_ec2 as ec2,
    aws_logs as logs,
    aws_iam as _iam,
    RemovalPolicy, 
    Stack,
    aws_eks as eks,    
    CfnJson,   
)
from constructs import Construct
from aws_cdk.lambda_layer_kubectl_v29 import KubectlV29Layer
from configs.policies import RolePolicyStatements
from configs.promvalues import PrometheusValues


def read_multiple_blocks_of_yaml(filename):
    with open(filename, 'r') as f:
        data = yaml.safe_load_all(f)
        return list(data)

    
def create_eks_thumbprint():
    cert = ssl.get_server_certificate(("oidc.eks.us-east-1.amazonaws.com", 443))
    der_cert = ssl.PEM_cert_to_DER_cert(cert)
    return hashlib.sha1(der_cert).hexdigest()


class KubernetesStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        thumbprint = create_eks_thumbprint()
        policy_statements = RolePolicyStatements()
        clustername = "EKSSpark"

        def string_equals(name_space, sa_name, oidc_prov):
            string = CfnJson(
                self, f'JsonCondition{sa_name}',
                value={
                    f'{oidc_prov}:sub': f'system:serviceaccount:{name_space}:{sa_name}',
                    f'{oidc_prov}:aud': 'sts.amazonaws.com'
                }
            )
            return string

        # create a vpc
        self.vpc = ec2.Vpc(self, "BaseVpc",
          ip_addresses=ec2.IpAddresses.cidr("192.168.0.0/16"),
          availability_zones=[f"{Aws.REGION}a", f"{Aws.REGION}b"],
          create_internet_gateway=True,
          enable_dns_hostnames=True,
          enable_dns_support=True,
          subnet_configuration=[
            ec2.SubnetConfiguration(
               cidr_mask=24,
               name='public1',
               subnet_type=ec2.SubnetType.PUBLIC,
              ),
            ec2.SubnetConfiguration(
               cidr_mask=24,
               name='private1',
               subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
              )]     
           )
        
        # create a flow log role and policy
        self.vpcflowlogrole = _iam.Role(self, "vpcflowlogsrole",
                assumed_by=_iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
                path="/"
        )
        self.vpcflowlogrole.attach_inline_policy(
            _iam.Policy(
                self, 
                "vpcflowlogspolicy",
                policy_name="VpcFlowLogsPolicy",
                statements=[_iam.PolicyStatement(
                    effect=_iam.Effect.ALLOW,
                    actions=["logs:CreateLogGroup", 
                             "logs:CreateLogStream", 
                             "logs:PutLogEvents",
                             "logs:DescribeLogGroups",
                             "logs:DescribeLogStreams",
                             "logs:DeleteLogGroup",
                             "logs:DeleteLogStream"
                            ],
                    resources=[f"arn:aws:logs:{Aws.ACCOUNT_ID}:{Aws.REGION}:log-group:/VPCforEKS/vpcflowlogs*"]
                   )
                ]
            )
        )

        # create a log group for vpc flow logs
        self.vpcflowloggroup = logs.LogGroup(
            self, 
            "vpcflowloggroup",
            log_group_name=f"/VPCforEKS/vpcflowlogs",
            retention= logs.RetentionDays.ONE_DAY,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        # create a flow log for vpc
        self.ec2_flowlog = ec2.FlowLog(self, "FlowLog",
          resource_type=ec2.FlowLogResourceType.from_vpc(self.vpc),
          destination=ec2.FlowLogDestination.to_cloud_watch_logs(self.vpcflowloggroup, self.vpcflowlogrole)
         )
        
        # create a dynamodb endpoint for vpc
        dynamo_db_endpoint = self.vpc.add_gateway_endpoint("DynamoDbEndpoint",
          service=ec2.GatewayVpcEndpointAwsService.DYNAMODB,
          subnets=[ec2.SubnetSelection(subnets=self.vpc.private_subnets)]
        )

        # create a s3 endpoint for vpc 
        s3_endpoint = self.vpc.add_gateway_endpoint("S3Endpoint",
           service=ec2.GatewayVpcEndpointAwsService.S3,
           subnets=[ec2.SubnetSelection(subnets=self.vpc.private_subnets)]
          )
        
        # Uncomment following section if eks cluster is in private subnet with no NAT Gateway
             
        # vpc_interface_endpoints = {         
        #     'ec2': ec2.InterfaceVpcEndpointAwsService.EC2,
        #     'ec2-messages': ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES,
        #     'ssm': ec2.InterfaceVpcEndpointAwsService.SSM,
        #     'ssm-messages': ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
        #     'cloudformation': ec2.InterfaceVpcEndpointAwsService.CLOUDFORMATION,
        #     'cloudwatch-logs': ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
        #     'cloudwatch-monitoring': ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_MONITORING,
        #     'sts': ec2.InterfaceVpcEndpointAwsService.STS,
        #     'ecr-api': ec2.InterfaceVpcEndpointAwsService.ECR,
        #     'ecr-dkr': ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
        #     'load-balancing': ec2.InterfaceVpcEndpointAwsService.ELASTIC_LOAD_BALANCING,
        # }

        # for name, interface_service in vpc_interface_endpoints.items():
        #     self.vpc.add_interface_endpoint(f"{name}",
        #      service=interface_service,
        #      private_dns_enabled=True,
        #      subnets=ec2.SubnetSelection(subnets=self.vpc.private_subnets)
        #   )


        master_role = _iam.Role(
            self,
            "EksMasterRole",
            role_name="eks-admin-role",
            assumed_by=_iam.CompositePrincipal(
                _iam.ServicePrincipal("ec2.amazonaws.com"),
                _iam.ArnPrincipal(f"arn:aws:iam::{Aws.ACCOUNT_ID}:user/Derrick")
            ),
            managed_policies=policy_statements.eks_master_statement()               
        )
           
        cluster_role = _iam.Role(
            self,
            "EKSClusterRole",
            role_name="eks-cluster-role",
            assumed_by=_iam.ServicePrincipal(service="eks.amazonaws.com"),
            managed_policies=policy_statements.eks_cluster_statement()
        )
        

        worker_role = _iam.Role(
            self, "EKSWorkerRole", 
            role_name='eks-worker-role',
            assumed_by=_iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=policy_statements.eks_worker_statement()  
        )
        worker_role.attach_inline_policy(
            _iam.Policy(
                self, 
                "worker-role-policy",
                policy_name="amp-iamproxy-ingest-policy",
                statements=policy_statements.alb_loadbalancer_statement()
                )
            )

        cluster_sg = ec2.SecurityGroup(
            self, "EKSClusterSG",
            vpc=self.vpc,
            allow_all_outbound=True,
            security_group_name=f"{clustername}-sg"
        )
        cluster_sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.all_traffic()) 
        Tags.of(cluster_sg).add("karpenter.sh/discovery", clustername)


        self.eks_cluster = eks.Cluster(
            self,
            "EKSCluster",
            kubectl_layer=KubectlV29Layer(self, "kubectl"),
            version = eks.KubernetesVersion.V1_29,
            cluster_name = clustername,
            masters_role=master_role,
            role=cluster_role,
            vpc=self.vpc,
            default_capacity=0,
            security_group=cluster_sg,
            # tags={"karpenter.sh/discovery": f"{cluster_config['cluster_name']}"},
        )

        coredns_addon = eks.CfnAddon(
            self,
            "coredns-addon",
            addon_name = "coredns",
            cluster_name = clustername,
            addon_version = "v1.11.1-eksbuild.9",
            resolve_conflicts="OVERWRITE",
        )
        coredns_addon.node.add_dependency(self.eks_cluster)

        kube_proxy_addon = eks.CfnAddon(
            self,
            "kube-proxy-addon",
            addon_name = "kube-proxy",
            cluster_name = clustername,
            addon_version = "v1.29.3-eksbuild.2",
            resolve_conflicts="OVERWRITE"
        )
        kube_proxy_addon.node.add_dependency(self.eks_cluster)

        iam_oic = _iam.OpenIdConnectProvider(
            self, 'myoidc',
            url=self.eks_cluster.cluster_open_id_connect_issuer_url,
            client_ids=['sts.amazonaws.com'],
            thumbprints=[thumbprint]
        )

        oic_conf = eks.CfnIdentityProviderConfig(
            self,
            "identity-provider-config",
            cluster_name = clustername,
            oidc = eks.CfnIdentityProviderConfig.OidcIdentityProviderConfigProperty(
                issuer_url = f"https://{iam_oic.open_id_connect_provider_issuer}",
                client_id = "sts.amazonaws.com"),
            type="oidc"
            )
        oic_conf.node.add_dependency(iam_oic)

        self.issuer = iam_oic.open_id_connect_provider_issuer

        vpc_cni_principal = _iam.FederatedPrincipal(federated=f"arn:aws:iam::{Aws.ACCOUNT_ID}:oidc-provider/{iam_oic.open_id_connect_provider_issuer}",
            assume_role_action="sts:AssumeRoleWithWebIdentity").with_conditions({
            "StringEquals": string_equals("kube-system", "aws-node", iam_oic.open_id_connect_provider_issuer)
        })

        vpc_cni_addon_role = _iam.Role(
            self,
            'cni-addon-role',
            assumed_by=vpc_cni_principal,
            role_name='CniAddonRole',
            managed_policies=[_iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKS_CNI_Policy")]         
        )

        vpc_cni_addon = eks.CfnAddon(
            self,
            "vpc-cni-addon",
            addon_name = "vpc-cni",
            service_account_role_arn=vpc_cni_addon_role.role_arn,
            cluster_name = clustername,
            addon_version = "v1.18.1-eksbuild.3",
            resolve_conflicts="OVERWRITE",
            configuration_values=json.dumps(
                {"env":{"ENABLE_PREFIX_DELEGATION":"true",
                        "ENABLE_POD_ENI":"true",
                        "POD_SECURITY_GROUP_ENFORCING_MODE":"standard"},
                        "enableNetworkPolicy": "true"})
        )
        vpc_cni_addon.node.add_dependency(self.eks_cluster)

        ebs_principal = _iam.FederatedPrincipal(
            federated=f"arn:aws:iam::{Aws.ACCOUNT_ID}:oidc-provider/{iam_oic.open_id_connect_provider_issuer}",
            assume_role_action="sts:AssumeRoleWithWebIdentity").with_conditions({
            "StringEquals": string_equals("kube-system", "ebs-csi-controller-sa", iam_oic.open_id_connect_provider_issuer)
          }
        )

        ebs_csi_addon_role = _iam.Role(
            self,
            'ebs-csi-addon-role',
            assumed_by=ebs_principal,
            role_name='EbsCsiAddonRole',
            managed_policies=[
                _iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonEBSCSIDriverPolicy")
                ]             
        )

        aws_ebs_csi_driver_addon = eks.CfnAddon(
            self,
            "ebs-csi-driver-addon",
            addon_name = "aws-ebs-csi-driver",
            cluster_name = clustername,
            addon_version = "v1.30.0-eksbuild.1",
            resolve_conflicts="OVERWRITE",
            service_account_role_arn = ebs_csi_addon_role.role_arn
        )
         # aws_ebs_csi_driver_addon.node.add_dependency(self.eks_cluster)

        
        self.pod_identity_principal = _iam.SessionTagsPrincipal(principal=_iam.ServicePrincipal("pods.eks.amazonaws.com"))

        self.pod_identity_role = _iam.Role(
            self,
            "pod-identity-role",
            role_name='PodIdentyAddonRole',
            # assumed_by=_iam.ServicePrincipal("pods.eks.amazonaws.com"),
            assumed_by=self.pod_identity_principal,
            managed_policies=[_iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSClusterPolicy")],
            inline_policies={
                'PodIdentityPolicy':
                    _iam.PolicyDocument(statements=[
                        _iam.PolicyStatement(
                            actions=['s3:GetObject'], 
                            effect=_iam.Effect.ALLOW,
                            resources=['arn:aws:s3:::bucket4084']
                            ),
                    ]),
            },
        )


        self.pod_identity_agent_addon = eks.CfnAddon(
            self,
            "eks-pod-identity-agent",
            addon_name = "eks-pod-identity-agent",
            cluster_name = clustername,
            addon_version = "v1.2.0-eksbuild.1",
            resolve_conflicts="OVERWRITE",
            service_account_role_arn = self.pod_identity_role.role_arn,
            configuration_values=json.dumps(
                {
                  "agent": {
                      "additionalArgs": {"-b": "169.254.170.23"}
                    }
                }
            )
        )
        self.pod_identity_agent_addon.node.add_dependency(self.eks_cluster)

        self.svc_acct = self.eks_cluster.add_manifest("pod-identity-sa", {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": "pod-identity-sa",
                "namespace": "kube-system",
                "annotations": {
                    "eks.amazonaws.com/role-arn": self.pod_identity_role.role_arn
                }
            }
        })
        self.svc_acct.node.add_dependency(self.pod_identity_role)

        cfn_pod_identity_association = eks.CfnPodIdentityAssociation(self, "MyCfnPodIdentityAssociation",
            cluster_name=clustername,
            namespace="kube-system",
            role_arn=self.pod_identity_role.role_arn,
            service_account="pod-identity-sa",
        )
        cfn_pod_identity_association.node.add_dependency(self.pod_identity_agent_addon)

        

        super_user = _iam.User.from_user_arn(
            self,
            'Derrick',
            user_arn=f"arn:aws:iam::{Aws.ACCOUNT_ID}:user/Derrick"
        )

        self.eks_cluster.aws_auth.add_user_mapping(
            user=super_user,
            groups=["system:masters"],
            username=super_user.user_arn,
        )

        core_ng = self.eks_cluster.add_nodegroup_capacity(
            id="MainNodeGroup",
            desired_size=2,
            ami_type=eks.NodegroupAmiType.AL2_X86_64,
            instance_types=[ec2.InstanceType("m5.xlarge")],
            max_size=10,
            min_size=2,
            nodegroup_name='main-node-group',
            node_role=worker_role,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            labels={'node-type': 'core-group'},
            tags={'k8s.io/cluster-autoscaler/enabled': 'true',
                  # str(CfnJson(self, "as-enabler", value=f"k8s.io/cluster-autoscaler/{clustername}")): str(CfnJson(self, "as-value", value=f"{clustername}"))
                  f"k8s.io/cluster-autoscaler/{clustername}": f"{clustername}"
                },
            # taints=[eks.TaintSpec(effect=eks.TaintEffect.NO_SCHEDULE, key="node-pool", value="main-node-group")]
        )

        def create_nodegroup(id: str, name: str, az: int, instance_types: list, 
                          node_type: str, max_size: int) -> eks.Nodegroup:
            ng_id = id
            ng_az = az
            ng_inst_types = instance_types
            ng_node_type = node_type
            ng_max_size = max_size
            ng_name = name
            
            ng = self.eks_cluster.add_nodegroup_capacity(
            id=ng_id,
            desired_size=0,
            ami_type=eks.NodegroupAmiType.AL2_X86_64,
            instance_types=ng_inst_types,
            max_size=ng_max_size,
            min_size=0,
            nodegroup_name=ng_name,
            node_role=worker_role,
            subnets=ec2.SubnetSelection(subnets=[self.vpc.private_subnets[ng_az]]),
            labels={'node-type': ng_node_type},
            tags={'k8s.io/cluster-autoscaler/enabled': 'true',
                  'k8s.io/cluster-autoscaler/EKSSpark': 'EKSSpark',
                  'k8s.io/cluster-autoscaler/node-template/label/node-type': ng_node_type,
                  'k8s.io/cluster-autoscaler/node-template/autoscaling-options/scaledownunneededtime': '2m0s',
                  f'k8s.io/cluster-autoscaler/node-template/taint/{ng_node_type}': 'true:NoSchedule'},
            taints=[eks.TaintSpec(effect=eks.TaintEffect.NO_SCHEDULE, 
                                  key=ng_node_type, 
                                  value="true")]
            )
            return ng


        # low_driver = [ec2.InstanceType("m5.large"), ec2.InstanceType("m6a.large")]
        # low_executor = [ec2.InstanceType("m5.xlarge"), ec2.InstanceType("m5a.xlarge"), ec2.InstanceType("m6a.xlarge")]
        # high_driver = [ec2.InstanceType("c5.large"), ec2.InstanceType("c5a.large"), ec2.InstanceType("c6a.large")]
        # high_executor = [ec2.InstanceType("c5.xlarge"), ec2.InstanceType("c5a.xlarge"), ec2.InstanceType("c6a.xlarge")]

        # driver_az0 = create_nodegroup('SparkDriverAz0', 'spark-driver-az0', 0, low_driver, 'az0-low-cpu-driver', 10)
        # executor_az0 = create_nodegroup('SparkExecutorAz0', 'spark-executor-az0', 0, low_executor, 'az0-low-cpu-executor', 50)
        # driver_az1 = create_nodegroup('SparkDriverAz1', 'spark-driver-az1', 1, high_driver, 'az1-high-cpu-driver', 10)
        # executor_az1 = create_nodegroup('SparkExecutorAz1', 'spark-executor-az1', 1, high_executor, 'az1-high-cpu-executor', 50)

     
        
        cas_principal = _iam.FederatedPrincipal(federated=f"arn:aws:iam::{Aws.ACCOUNT_ID}:oidc-provider/{iam_oic.open_id_connect_provider_issuer}",
            assume_role_action="sts:AssumeRoleWithWebIdentity").with_conditions({
            "StringEquals": string_equals("kube-system", "cluster-autoscaler", iam_oic.open_id_connect_provider_issuer)
        })

        
        cas_role = _iam.Role(self, 'cas-role', assumed_by=cas_principal, role_name='AmazonCASRole')
        
        cas_role.attach_inline_policy(
            _iam.Policy(self, "cas-inline-policy",
                policy_name="cas-inline-policy",
                statements=policy_statements.cas_policy_statetement()
            )
        )

        cas_config = os.path.abspath(f"./configs/auto-scaler.yaml")
        cas_yaml = read_multiple_blocks_of_yaml(cas_config)
        for i in range(len(cas_yaml)):
            cas_manifest = self.eks_cluster.add_manifest(f"cas-config-{i}", cas_yaml[i])










        def string_equals_noaud(name_space, sa_name, oidc_prov):
            string = CfnJson(
                self, f'JsonCondition{sa_name}',
                value={
                    f'{oidc_prov}:sub': f'system:serviceaccount:{name_space}:{sa_name}'
                }
            )
            return string
        
        
        def string_equals(name_space, sa_name, oidc_prov):
            string = CfnJson(
                self, f'JsonCondition{sa_name}',
                value={
                    f'{oidc_prov}:sub': f'system:serviceaccount:{name_space}:{sa_name}',
                    f'{oidc_prov}:aud': 'sts.amazonaws.com'
                }
            )
            return string    



        # Prometheus ingest metric Role to ingext metrics to Prometheus Workspace
        prom_metrics_ingest_principal = _iam.FederatedPrincipal(federated=f"arn:aws:iam::{Aws.ACCOUNT_ID}:oidc-provider/{self.issuer}",
                    assume_role_action="sts:AssumeRoleWithWebIdentity").with_conditions({
                    "StringEquals": string_equals_noaud("monitoring", "amp-iamproxy-ingest-service-account", f"{self.issuer}")
                })
        prom_metrics_ingest_role = _iam.Role(
            self,
            'amp-iamproxy-ingest-role',
            assumed_by=prom_metrics_ingest_principal,
            role_name="amp-iamproxy-ingest-role"       
        )
        prom_metrics_ingest_role.attach_inline_policy(
            _iam.Policy(
                self, 
                "amp-iamproxy-ingest-policy",
                policy_name="amp-iamproxy-ingest-policy",
                statements=policy_statements.amp_iamproxy_ingest_statement()
                )
            )
        
        # Prometheus logroup and workspace creation
        prometheus_loggroup = logs.LogGroup(
            self, 
            "prometheus-wrkspc-loggroup",
            log_group_name=f"/Prometheus/wrkspclogs",
            retention= logs.RetentionDays.ONE_DAY,
            removal_policy=RemovalPolicy.DESTROY
        )
        prometheus_workspc = aps.CfnWorkspace(
            self, 
            "prometheus-wrkspc",
            alias=f"wrkspc-{clustername}",
            logging_configuration=aps.CfnWorkspace.LoggingConfigurationProperty(
                log_group_arn=prometheus_loggroup.log_group_arn
                ),           
           )
        prometheus_workspc.node.add_dependency(prometheus_loggroup)


        # Helm Chart to install the Prometheus on the cluster
        prometheus_helm = self.eks_cluster.add_helm_chart(
            "prometheus",
            chart="prometheus",
            release="prometheus",
            repository="https://prometheus-community.github.io/helm-charts",
            namespace="monitoring",
            create_namespace=True,
            values=PrometheusValues().get_prom_values(prom_metrics_ingest_role.role_arn, Aws.REGION, prometheus_workspc.attr_workspace_id),
            wait=True
            )
        prometheus_helm.node.add_dependency(prometheus_workspc)

