##############################################################
#
# lambda_stack.py
#
# Resources:
#  1 lambda functions (code in /lambda folder (from_asset))
#
##############################################################

from aws_cdk import (
  aws_iam as iam,
  aws_lambda as lambda_,
  core
)

class LambdaStack(core.Stack):

  def __init__(self, scope: core.Construct, construct_id: str, config_sg_open_lambda_role: iam.IRole, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    # get acct id for policies
    #acct_id=env['account']

    # create the Lambda function
    self._sg_checker_func=lambda_.Function(self,"Security Group Checker Function",
      code=lambda_.Code.from_asset("lambda/sg_checker.zip"),
      handler="sg_checker.lambda_handler",
      runtime=lambda_.Runtime.PYTHON_3_8,
      role=config_sg_open_lambda_role,
    )

  # Exports
  @property
  def sg_checker_func(self) -> lambda_.IFunction:
    return self._sg_checker_func  


