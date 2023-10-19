import boto3
import logging
import os
import cfnresponse
from botocore.config import Config
from botocore.exceptions import ClientError
import logging

detective_master_account=os.environ['DETECTIVE_MASTER_ACCOUNT']
role_to_assume=os.environ['ROLE_TO_ASSUME']
excluded_accounts=os.environ['EXCLUDED_ACCOUNTS']

logger = logging.getLogger()

config=Config(
    retries={
        'max_attempts':10,
        'mode':'standard'
    }
)
org_client=boto3.client('organizations')

def assume_role(aws_account_id, role_to_assume):
    sts_client=boto3.client('sts')
    response=sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{aws_account_id}:role/{role_to_assume}',
        RoleSessionName='EnableSecurityHub'
    )
    sts_session=boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )
    print(f"Assumed session for Account ID: {aws_account_id}.")
    return sts_session

def get_control_tower_regions():
    cloudformation_client=boto3.client('cloudformation')
    control_tower_regions=set()
    try:
        stack_instances=cloudformation_client.list_stack_instances(
            StackSetName="AWSControlTowerBP-BASELINE-CONFIG"
        )
        for stack in stack_instances['Summaries']:
            control_tower_regions.add(stack['Region'])
    except ClientError as error:
        print(error)
    print(f"Control Tower Regions: {list(control_tower_regions)}")
    return list(control_tower_regions)

def get_all_accounts():
    all_accounts=[]
    active_accounts=[]
    token_tracker={}
    while True:
        member_accounts=org_client.list_accounts(
            **token_tracker
        )
        all_accounts.extend(member_accounts['Accounts'])
        if 'NextToken' in member_accounts:
            token_tracker['NextToken'] = member_accounts['NextToken']
        else:
            break
    for account in all_accounts:
        if account['Status'] == 'ACTIVE':
            active_accounts.append(account)
    return active_accounts

def enable_detective_master(detective_master_account_session, region):
    detective_client=boto3.client('detective', region_name=region)
    detective_admin_client=detective_master_account_session.client('detective', region_name=region)
    try:
        detective_client.enable_organization_admin_account(
            AccountId=detective_master_account
        )
    except ClientError as error:
        print(f"Delegated Administration for Amazon detective has already been configured in {region}.")
        
    
def enable_detective_member(accounts, region):
    details=[]
    for account in accounts:
        if account['Id'] != detective_master_account and account['Id'] not in excluded_accounts:
            member_session=assume_role(account['Id'], role_to_assume)
            member_client=member_session.client('detective', region_name=region)
            details.append(
                {
                    'accountId': account['Id'],
                    'email': account['Email']
                }
            )
            try:
                graph_arn = member_client.create_graph()['GraphArn']
                response=member_client.create_members(
                    GraphArn=graph_arn,
                    Message='Automatically generated invitation',
                    Accounts=[
                        {
                            'AccountId': account['Id'],
                            'EmailAddress': account['Email']
                        },
                    ]
                )
                print(f"Amazon Detective has been enabled in Account ID: {account['Id']} in {region}.")
            except ClientError as error:
                print(f"Amazon Detective has already been enabled in Account ID: {account['Id']} in {region}.")

def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i+n]


def lambda_handler(event, context):
    detective_regions=boto3.Session().get_available_regions('detective')
    control_tower_regions=get_control_tower_regions()
    detective_master_account_session=assume_role(detective_master_account, role_to_assume)
    accounts=get_all_accounts()
    if 'RequestType' in event:
        if (event['RequestType'] == 'Create' or event['RequestType'] == 'Update'):
            try: 
                org_client.enable_aws_service_access(
                    ServicePrincipal='detective.amazonaws.com'
                )
                for region in control_tower_regions:
                    if region in detective_regions:
                        enable_detective_master(detective_master_account_session, region)
                        print(f"Admin Account delegated in {detective_master_account}")
                        enable_detective_member(accounts, region)
                        print(f"AWS Detective Enabled")
                cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
            except ClientError as error:
                print(error)
                cfnresponse.send(event, context, cfnresponse.FAILED, error) 
        elif event['RequestType'] == 'Delete':
            try:
                for region in control_tower_regions:
                    if region in detective_regions:
                        detective_client=boto3.client('detective', region_name=region)
                        try:
                            detective_client.disable_organization_admin_account(
                                AccountId=detective_master_account
                            )
                        except ClientError as error:
                            print(f"Delegated Administration for Amazon Detective has been disabled in {region}.")
                cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
            except ClientError as error:
                print(error)
                cfnresponse.send(event, context, cfnresponse.FAILED, error)
        else:
            try: 
                org_client.enable_aws_service_access(
                    ServicePrincipal='detective.amazonaws.com'
                )
                for region in control_tower_regions:
                    if region in detective_regions:
                        enable_detective_master(detective_master_account_session, region)
                        enable_detective_member(accounts, region)
            except ClientError as error:
                print(f"AWS Service Access has already been configured for Amazon Detective.") 