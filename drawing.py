from diagrams import Diagram, Cluster
from diagrams.custom import Custom
from diagrams.aws.compute import EC2, Lambda
from diagrams.aws.storage import SimpleStorageServiceS3Bucket
from diagrams.aws.management import Cloudwatch
from diagrams.aws.mobile import APIGateway

with Diagram("Upload pipeline", show=False):
  upload_file = Custom("File upload", "./images/file-icon.png")
  s3_bucket = SimpleStorageServiceS3Bucket("S3 bucket")
  cw = Cloudwatch("Cloudwatch logs & metrics")
  apigw = APIGateway("API Endpoint")

  with Cluster("Lambda functions"):
    function_1 = Lambda("Process upload")
    function_2 = Lambda("Process findings")

  nf = Custom("Nightfall API", "./images/nightfall.png")
  
  function_1 >> nf >> apigw >> function_2 >> cw
  upload_file >> s3_bucket
  s3_bucket >> function_1
  function_2 >> s3_bucket

with Diagram("Download pipeline", show=False):
  s3_bucket = SimpleStorageServiceS3Bucket("S3 bucket")
  download_file = Custom("File download", "./images/file-icon.png")

  with Cluster("Object Lambda"):
    function_1 = Lambda("No restrict")
    function_2 = Lambda("Redact")
    function_3 = Lambda("Restrict")
    # nf = Custom("Nightfall API", "./images/nightfall.png")
    functions = [function_1, function_2, function_3]

  with Cluster("Users"):
    user_1 = Custom("User 1", "./images/user.png")
    user_2 = Custom("User 2", "./images/user.png")
    user_3 = Custom("User 3", "./images/user.png")
    users = [user_1, user_2, user_3]

  s3_bucket >> download_file >> functions
  function_1 >> user_1
  function_2 >> user_2
  function_3 >> user_3

  cw = Cloudwatch("Cloudwatch logs & metrics")
  functions >> cw

with Diagram("EC2 pipeline", show=False):
  with Cluster("EC2"):
    ec2 = EC2("EC2 instance")
    file = Custom("File", "./images/file-icon.png")
    ec2 >> file
    monitoring = Custom("Monitoring daemon", "./images/monitor.png")
    file >> monitoring

  nf = Custom("Nightfall API", "./images/nightfall.png")
  apigw = APIGateway("API Endpoint")
  cw = Cloudwatch("Cloudwatch logs & metrics")
  monitoring >> nf >> apigw >> cw

