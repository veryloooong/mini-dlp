import boto3
from nightfall import Nightfall, RedactionConfig, MaskConfig
import os
import requests

def get_object_key(event):
  object_url = event['userRequest']['url']

  if object_url.startswith('https://'):
    object_key = object_url.split('amazonaws.com/')[-1]
  else:
    object_key = object_url[1:]

  if '?' in object_key:
    object_key = object_key.split('?')[0]

  return object_key


def lambda_handler(event, context):
  s3_client = boto3.client('s3')
  cloudwatch_client = boto3.client('cloudwatch')

  get_context = event['getObjectContext']
  request_route = get_context['outputRoute']
  request_token = get_context['outputToken']
  s3_url = get_context['inputS3Url']
  nf_client = Nightfall(
    key=os.getenv('NIGHTFALL_API_KEY')
  )

  try:
    s3_file = requests.get(s3_url).content.decode()
    detection_rules = os.getenv('NIGHTFALL_DETECTION_RULES').split(',')
    redaction_config = RedactionConfig(
      remove_finding=True,
      mask_config=MaskConfig(
        masking_char='*',
        chars_to_ignore=['@', '.']
      )
    )
    findings, redacted = nf_client.scan_text(
      texts=[s3_file],
      detection_rule_uuids=detection_rules,
      default_redaction_config=redaction_config
    )

    object_key = get_object_key(event)

    print({
      "msg": f"Filtered sensitive data in file {object_key}",
      "file": object_key,
      "event": "file_filter"
    })

    cloudwatch_client.put_metric_data(
      Namespace='DLP',
      MetricData=[
        {
          'MetricName': 'TimesFiltered',
          'Dimensions': [
            {
              'Name': 'ObjectLambdaAccessPoint',
              'Value': 'dlp-filter-info'
            }
          ],
          'Value': 1,
          'Unit': 'Count'
        }
      ]
    )

    if redacted[0]:
      s3_client.write_get_object_response(
        RequestRoute=request_route,
        RequestToken=request_token,
        StatusCode=200,
        Body=redacted[0],
        ContentType='text/plain'
      )
    else:
      s3_client.write_get_object_response(
        RequestRoute=request_route,
        RequestToken=request_token,
        StatusCode=200,
        Body=s3_file,
        ContentType='text/plain'
      )
    
    return {
      "status_code": 200,
    }

  except Exception as e:
    s3_client.write_get_object_response(
      RequestRoute=request_route,
      RequestToken=request_token,
      StatusCode=400,
      ErrorCode="Unsupported",
      ErrorMessage="This access point only supports filtering text files",
    )

    return {
      "status_code": 415,
    }

  # detection_rule = DetectionRule(
  #   detectors=[detector]
  # )
