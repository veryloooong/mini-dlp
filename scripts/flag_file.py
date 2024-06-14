import boto3
import os
import json
import hmac
import hashlib
import logging

nf_signing_secret = os.getenv("NIGHTFALL_SIGNING_SECRET")

def handler(event, context):
  cloudwatch = boto3.client('cloudwatch')
  dynamodb = boto3.client('dynamodb')
  s3 = boto3.client('s3')

  # set up logging
  logging.basicConfig(level=logging.INFO)

  body = event['body']

  if body:
    payload = json.loads(event['body'])
    if 'challenge' in payload:
      return {
        'statusCode': 200,
        'headers': {
          'Content-Type': 'text/plain'
        },
        'body': payload['challenge']
      }
    else:
      try:
        signature = event['headers']['x-nightfall-signature']
        nonce = event['headers']['x-nightfall-timestamp']

        body_text = json.dumps(payload, separators=(",", ":"))

        computed_signature = hmac.new(
          nf_signing_secret.encode('utf-8'),
          msg=f'{nonce}:{body_text}'.encode('utf-8'),
          digestmod=hashlib.sha256
        ).hexdigest().lower()

        if computed_signature == signature:
          upload_id = payload['uploadID']
          findings_present = payload['findingsPresent']
          if findings_present:
            # logging.warn(f"Sensitive data found in upload {upload_id}")

            entry = dynamodb.get_item(
              TableName=os.getenv("DYNAMODB_TABLE_NAME"),
              Key={
                'UploadID': {
                  'S': upload_id
                }
              }
            )

            cloudwatch.put_metric_data(
              Namespace='DLP',
              MetricData=[
                {
                  'MetricName': 'TimesFlagged',
                  'Value': 1,
                  'Unit': 'Count',
                  'Dimensions': [
                    {
                      'Name': 'Bucket',
                      'Value': entry['Item']['Bucket']['S']
                    }
                  ]
                }
              ]
            )

            if 'Item' in entry:
              bucket = entry['Item']['Bucket']['S']
              key = entry['Item']['Key']['S']
              print({
                "msg": f"Sensitive data found in file {key}, upload ID {upload_id}",
                "file": key,
                "id": upload_id,
                "event": "file_detect"
              })

              s3.put_object_tagging(
                Bucket=bucket,
                Key=key,
                Tagging={
                  'TagSet': [
                    {
                      'Key': 'sensitive-data',
                      'Value': 'True'
                    },
                    {
                      'Key': 'nightfall-id',
                      'Value': upload_id
                    }
                  ]
                }
              )
          
          return {
            'statusCode': 200,
            'body': "payload received"
          }

        else:
          return {
            'statusCode': 401,
            'body': "invalid signature"
          }

      except KeyError:
        return {
          'statusCode': 400,
          'body': "missing headers"
        }

  return {
    'statusCode': 400,
    'body': "wrong payload"
  }

