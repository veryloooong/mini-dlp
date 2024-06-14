import boto3
import json
import os
import hmac
import hashlib

nf_signing_secret = os.getenv("NIGHTFALL_SIGNING_SECRET")

def lambda_handler(event, context):
  cloudwatch = boto3.client('cloudwatch')

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
            print({
              'msg': 'Sensitive data found inside EC2 instance',
              'event': 'file_detected_ec2',
              'upload_id': upload_id,
            })

            cloudwatch.put_metric_data(
              Namespace='DLP',
              MetricData=[
                {
                  'MetricName': 'TimesFoundSensitiveData',
                  'Dimensions': [
                    {
                      'Name': 'EC2Instance',
                      'Value': 'Public VM'
                    }
                  ],
                  'Value': 1,
                  'Unit': 'Count'
                }
              ]
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

