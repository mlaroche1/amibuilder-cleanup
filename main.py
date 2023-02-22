import boto3
import datetime

def get_aws_session(role_name: str) -> boto3.session.Session:
    # Create an STS client
    sts_client = boto3.client('sts')

    # Call the assume_role method of the STSConnection object and pass the role
    # ARN and a role session name.
    assumed_role_object = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{get_account_id()}:role/{role_name}",
        RoleSessionName="AssumeRoleforAmiCleanupLambdaStepFunction"
    )
    
    # From the response that contains the assumed role, get the temporary
    # credentials that can be used to make subsequent API calls
    credentials = assumed_role_object['Credentials']

    # Use the temporary credentials that AssumeRole returns to make a
    # connection.
    session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
    )
    return session

def get_account_id() -> str:
    return boto3.client('sts').get_caller_identity().get('Account')

def get_ami_builder_images(session: boto3.session.Session) -> list:
    #Returns a list of AMI IDs created by AMIBuilder associated with the sharedservices AWS account
    ami_ids = []
    ec2_client = session.client('ec2')
    images = ec2_client.describe_images(Owners=['373950440124'])
    for image in images['Images']:
        if 'mvp' in image['ImageLocation']:
            ami_ids.append(image['ImageId'])
    return ami_ids

def get_ami_in_use(session: boto3.session.Session) -> list:
    #Returns a list of AMI IDs in use by EC2 instances or ASG instances
    images = []
    ec2_client = session.client('ec2')
    ec2 = ec2_client.describe_instances()
    for instance in ec2['Reservations']:
        if (instance['Instances'][0]['State']['Name']) == "running" or "stopped":
            images.append(instance['Instances'][0]['ImageId'])
    return images

def execute_clean_ami_date(session: boto3.session.Session, ami: str) -> datetime.datetime:
    #Returns the creation date of an AMI
    try:
        ec2_client = session.client('ec2')
        response = ec2_client.describe_images(ImageIds=[ami])
        for images in response['Images']:
            ami_created = datetime.datetime.strptime(images['CreationDate'], "%Y-%m-%dT%H:%M:%S.%fZ")
            return ami_created
    except Exception as error:
        pass

def get_ami_date_evaluation(creation_date: datetime.datetime) -> bool:
    #Returns True if an AMI is older than 90 days
    try:
        if (creation_date) < (datetime.datetime.now() - datetime.timedelta(days=90)):
            return True # True is an AMI older than 90 days
    except Exception as error:
        pass

def execute_ami_deregister(session: boto3.session.Session, ami: str) -> None:
    #Deregisters an AMI
    try:
        ec2_client = session.client('ec2')
        response = ec2_client.deregister_image(ImageId=ami)
        print(response)
    except Exception as error:
        pass

def execute_add_ami_to_dynamodb(session: boto3.session.Session, ami: str) -> None:
    #Adds an AMI to the AMI DynamoDB table
    try:
        dynamodb = session.resource('dynamodb')
        table = dynamodb.Table('amibuilder-images-in-use')
        response = table.put_item(
            Item={
                'ami_id': ami,
            }
        )
        print(response)
    except Exception as error:
        pass

def main():
    session = get_aws_session('tps-amicleanerlambda-iam-role')
    for ami in get_ami_builder_images(session):
        if ami in set(get_ami_in_use(session)):
            pass
            # execute_add_ami_to_dynamodb(session, ami)
        else:
            date = execute_clean_ami_date(session, ami)
            if get_ami_date_evaluation(date) == True:
                print(f"{ami} : Not in use + Older than 90 days")
                # execute_ami_deregister(session, ami)
            else:
                print (f"{ami} : In use + Not older than 90 days")
                # catch

if __name__ == "__main__":
    main()
