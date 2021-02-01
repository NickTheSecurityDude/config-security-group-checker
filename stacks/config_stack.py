##############################################################
#
# config_stack.py
#
# Resources:
#   SG Checker Config Rule
#
##############################################################

from aws_cdk import (
  aws_config as config,
  aws_lambda as lambda_,
  core
)

class ConfigStack(core.Stack):

  def __init__(self, scope: core.Construct, construct_id: str, config_sg_checker_function: lambda_.IFunction, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    # custom rule to check for security groups too open
    config.CustomRule(self,"SG Checker Config Rule",
      config_rule_name="security-group-checker",
      lambda_function=config_sg_checker_function,
      configuration_changes=True,
      periodic=True,
      maximum_execution_frequency=config.MaximumExecutionFrequency.TWENTY_FOUR_HOURS,
      rule_scope=config.RuleScope.from_resources([
        config.ResourceType.EC2_SECURITY_GROUP
      ]),
      input_parameters={"sg_whitelist":"[\"sg-12345678\"]"}
    )

    # ec2-security-group-attached-to-eni
    config.ManagedRule(self,"Unattached SG",
      config_rule_name="unattached-security-groups",
      identifier="EC2_SECURITY_GROUP_ATTACHED_TO_ENI",
      rule_scope=config.RuleScope.from_resources([
        config.ResourceType.EC2_SECURITY_GROUP
      ])
    )