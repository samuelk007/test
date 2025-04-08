import boto3
import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

secretsmanager = boto3.client('secretsmanager')
iam = boto3.client('iam')

def lambda_handler(event, context):
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    secret_meta = secretsmanager.describe_secret(SecretId=arn)
    if token not in secret_meta['VersionIdsToStages']:
        raise ValueError("Secret version %s not found." % token)

    if "AWSCURRENT" in secret_meta['VersionIdsToStages'][token]:
        logger.info("Version already current.")
        return
    elif "AWSPENDING" not in secret_meta['VersionIdsToStages'][token]:
        raise ValueError("Secret version %s not marked as AWSPENDING." % token)

    if step == 'createSecret':
        create_secret(arn, token)
    elif step == 'setSecret':
        pass  # No action needed for IAM
    elif step == 'testSecret':
        test_secret(arn, token)
    elif step == 'finishSecret':
        finish_secret(arn, token)
    else:
        raise ValueError("Invalid step: %s" % step)

def create_secret(arn, token):
    try:
        secretsmanager.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("createSecret: Secret already exists.")
        return
    except secretsmanager.exceptions.ResourceNotFoundException:
        pass

    current = json.loads(secretsmanager.get_secret_value(SecretId=arn, VersionStage='AWSCURRENT')['SecretString'])
    username = current['username']

    # Create new access key
    new_key = iam.create_access_key(UserName=username)['AccessKey']
    new_secret = {
        "username": username,
        "accessKeyId": new_key['AccessKeyId'],
        "secretAccessKey": new_key['SecretAccessKey']
    }

    # Save to Secrets Manager
    secretsmanager.put_secret_value(
        SecretId=arn,
        ClientRequestToken=token,
        SecretString=json.dumps(new_secret),
        VersionStages=['AWSPENDING']
    )
    logger.info("createSecret: Created and stored new IAM keys.")

def test_secret(arn, token):
    # Optionally validate the keys
    pending = json.loads(secretsmanager.get_secret_value(SecretId=arn, VersionId=token, VersionStage='AWSPENDING')['SecretString'])

    try:
        session = boto3.Session(
            aws_access_key_id=pending['accessKeyId'],
            aws_secret_access_key=pending['secretAccessKey']
        )
        sts = session.client('sts')
        sts.get_caller_identity()
        logger.info("testSecret: IAM credentials are valid.")
    except Exception as e:
        raise ValueError("testSecret: Invalid IAM credentials - %s" % str(e))

def finish_secret(arn, token):
    secret_meta = secretsmanager.describe_secret(SecretId=arn)
    current_version = [k for k, v in secret_meta['VersionIdsToStages'].items() if "AWSCURRENT" in v][0]

    current = json.loads(secretsmanager.get_secret_value(SecretId=arn, VersionId=current_version)['SecretString'])
    pending = json.loads(secretsmanager.get_secret_value(SecretId=arn, VersionId=token)['SecretString'])

    # Delete old access key
    iam.delete_access_key(
        UserName=current['username'],
        AccessKeyId=current['accessKeyId']
    )
    logger.info("finishSecret: Deleted old access key.")

    # Promote new key
    secretsmanager.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version
    )
    logger.info("finishSecret: Promoted new secret to AWSCURRENT.")
