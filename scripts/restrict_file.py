import boto3
import requests
import logging

def handler(event, context):
  s3_client = boto3.client('s3')
  cloudwatch = boto3.client('cloudwatch')

  logging.basicConfig(level=logging.WARN)

  get_context = event['getObjectContext']
  request_route = get_context['outputRoute']
  request_token = get_context['outputToken']
  s3_url = get_context['inputS3Url']
  s3_file = requests.get(s3_url)

  supporting_arn = event['configuration']['supportingAccessPointArn']
  object_url = event['userRequest']['url']

  if object_url.startswith('https://'):
    object_key = object_url.split('amazonaws.com/')[-1]
  else:
    object_key = object_url[1:]

  if '?' in object_key:
    object_key = object_key.split('?')[0]

  response = s3_client.get_object_tagging(
    Bucket=supporting_arn,
    Key=object_key
  )

  if 'TagSet' in response:
    for tag in response['TagSet']:
      if tag['Key'] == 'sensitive-data':
        cloudwatch.put_metric_data(
          Namespace='DLP',
          MetricData=[
            {
              'MetricName': 'TimesAccessControlled',
              'Value': 1,
              'Unit': 'Count',
              'Dimensions': [
                {
                  'Name': 'ObjectLambdaAccessPoint',
                  'Value': 'dlp-access-control',
                },
              ]
            },
          ]
        )

        print({
          "msg": f"Blocked access to sensitive data in file {object_key}",
          "file": object_key,
          "event": "file_block"
        })

        s3_client.write_get_object_response(
          RequestRoute=request_route,
          RequestToken=request_token,
          StatusCode=403,
          ErrorCode="AccessDenied",
          ErrorMessage="Access Denied",
        )
        return {
          "status_code": 403,
        }

  s3_client.write_get_object_response(
    RequestRoute=request_route,
    RequestToken=request_token,
    Body=s3_file.content,
  )

  return {
    "status_code": 200,
  }
