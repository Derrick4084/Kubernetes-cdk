import aws_cdk as core
import aws_cdk.assertions as assertions

from kubernetes.kubernetes_stack import KubernetesStack

# example tests. To run these tests, uncomment this file along with the example
# resource in kubernetes/kubernetes_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = KubernetesStack(app, "kubernetes")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
