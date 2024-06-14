import boto3
from nightfall import Nightfall
import os
import logging

nf_upload_api = 'https://api.nightfall.ai/v3/upload'
nf_chunk_api = 'https://api.nightfall.ai/v3/upload/{0}'
nf_finish_api = 'https://api.nightfall.ai/v3/upload/{0}/finish'
nf_scan_api = 'https://api.nightfall.ai/v3/upload/{0}/scan'

def lambda_function(event, context):
  # Open S3 client
  s3_client = boto3.client('s3')
  # Open DynamoDB client
  dynamodb = boto3.client('dynamodb')
  cloudwatch = boto3.client('cloudwatch')
  # Logging

  # Initialize the Nightfall SDK
  nightfall = Nightfall(
    key=os.getenv('NIGHTFALL_API_KEY'),
  )

  nf_session = nightfall.session

  bucket: str = event['Records'][0]['s3']['bucket']['name']
  key: str = event['Records'][0]['s3']['object']['key']

  response = s3_client.get_object(Bucket=bucket, Key=key)
  binary_data: bytes = response['Body'].read() # Read the file from S3, this is a bytes object

  # Call the Nightfall SDK to scan the file
  json_data = {
    "fileSizeBytes": len(binary_data)
  }

  response = nf_session.post(nf_upload_api, json=json_data)
  if response.status_code != 200:
    raise Exception('Failed to upload file to Nightfall')
  
  result = response.json()
  upload_id = result['id']
  chunk_size = result['chunkSize']

  # Split the file into chunks and upload each chunk
  def read_chunks(fp: bytes, chunk_size):
    ix = 0
    while True:
      chunk = fp[ix * chunk_size:(ix + 1) * chunk_size]
      if not chunk:
        break
      yield ix, chunk
      ix += 1

  def upload_chunks(id, data, headers):
    response = nf_session.patch(url=nf_chunk_api.format(id), data=data, headers=headers)
    return response
  
  for ix, chunk in read_chunks(binary_data, chunk_size):
    headers = {"X-UPLOAD-OFFSET": str(ix * chunk_size)}
    response = upload_chunks(upload_id, chunk, headers)
    if response.status_code != 204:
      raise Exception('Failed to upload chunk to Nightfall')
    
  # Finish the upload
  response = nf_session.post(nf_finish_api.format(upload_id))
  if response.status_code != 200:
    raise Exception('Failed to finish upload to Nightfall')
  
  json_data = {"policyUUID": os.getenv('NIGHTFALL_POLICY_UUID')}
  response = nf_session.post(url=nf_scan_api.format(upload_id), json=json_data)
  if response.status_code != 200:
    raise Exception('Failed to scan file with Nightfall')
  
  parsed_response = response.json()

  upload_id = parsed_response['id']

  # Write the id as a tag to the object in S3
  s3_client.put_object_tagging(
    Bucket=bucket,
    Key=key,
    Tagging={
      'TagSet': [
        {
          'Key': 'nightfall-id',
          'Value': upload_id
        }
      ]
    }
  )

  # Write the id to the DynamoDB table
  dynamodb.put_item(
    TableName=os.getenv('DYNAMODB_TABLE_NAME'),
    Item={
      'UploadID': {'S': upload_id},
      'Bucket': {'S': bucket},
      'Key': {'S': key}
    }
  )

  cloudwatch.put_metric_data(
    Namespace='DLP',
    MetricData=[
      {
        'MetricName': 'TimesScanned',
        'Value': 1,
        'Unit': 'Count',
        'Dimensions': [
          {
            'Name': 'Bucket',
            'Value': bucket
          }
        ]
      }
    ]
  )

  # logging.info(f"File {key} queued for scanning with id {final_id}")
  print({
    "msg": f"File {key} queued for scanning with id {upload_id}",
    "file": key,
    "id": upload_id,
    "event": "file_upload"
  })