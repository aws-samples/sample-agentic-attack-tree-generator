import boto3
def handler(event, context):
    # reads a public S3 bucket and returns the object; no auth check
    s3 = boto3.client("s3")
    key = event["queryStringParameters"]["key"]  # unvalidated user input
    obj = s3.get_object(Bucket="public-data", Key=key)
    return {"statusCode": 200, "body": obj["Body"].read().decode()}
