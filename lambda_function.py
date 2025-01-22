import boto3
import gzip
import json
import os
from botocore.exceptions import ClientError

# Initialize AWS clients
logs_client = boto3.client("logs")
s3_client = boto3.client("s3")

# Environment variable
LOG_GROUP_NAME = os.environ["LOG_GROUP_NAME"]


def lambda_handler(event, context):
    """
    Handler for S3 events to process CloudTrail logs and send them to CloudWatch Logs.
    """
    try:
        # Loop through each record in the S3 event
        for record in event["Records"]:
            # Get bucket name and object key
            bucket_name = record["s3"]["bucket"]["name"]
            object_key = record["s3"]["object"]["key"]

            # Download the log file
            response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
            compressed_data = response["Body"].read()

            # Decompress the gzip file
            decompressed_data = gzip.decompress(compressed_data)

            # Parse the JSON log
            log_events = json.loads(decompressed_data.decode("utf-8"))

            # Process each log event
            for log_event in log_events.get("Records", []):
                log_message = json.dumps(log_event)

                # Send log event to CloudWatch Logs
                send_to_cloudwatch(log_message)

        return {"statusCode": 200, "body": "Log processing complete."}

    except Exception as e:
        print(f"Error processing logs: {e}")
        return {"statusCode": 500, "body": f"Error processing logs: {e}"}


def send_to_cloudwatch(log_message):
    """
    Send a single log message to CloudWatch Logs.
    """
    try:
        log_stream_name = "CloudTrailLogStream"

        # Check if log stream exists, create it if it doesn't
        try:
            logs_client.describe_log_streams(
                logGroupName=LOG_GROUP_NAME, logStreamNamePrefix=log_stream_name
            )
        except logs_client.exceptions.ResourceNotFoundException:
            logs_client.create_log_stream(
                logGroupName=LOG_GROUP_NAME, logStreamName=log_stream_name
            )

        # Send log message
        response = logs_client.put_log_events(
            logGroupName=LOG_GROUP_NAME,
            logStreamName=log_stream_name,
            logEvents=[
                {"timestamp": int(context.aws_request_id), "message": log_message}
            ],
        )

        print(f"Log sent to CloudWatch: {response}")

    except ClientError as e:
        print(f"Error sending log to CloudWatch: {e}")
