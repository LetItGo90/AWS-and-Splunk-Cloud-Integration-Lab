# AWS-and-Splunk-Cloud-Integration-Lab
This lab demonstrates ingesting AWS CloudTrail logs into Splunk Cloud using the Splunk Add-on for AWS and visualizing key security activity in a custom dashboard.
Deployed with Terraform:
    Created isolated VPC with public subnet
    Deployed EC2 instance as an Atomic Red Team host
    Enabled CloudTrail with S3 backend for log storage
    Enabled GuardDuty with sample findings
    Configured VPC Flow Logs to CloudWatch
    
Splunk Integration:
    Configured Splunk Add-on for AWS to ingest CloudTrail logs from S3 via SQS notifications
    Built a custom Splunk Dashboard Studio view showing:
        CloudTrail Events Over Time – log volume trends
        Top Event Sources – most common AWS services generating events
        Top Users – AWS IAM principals with most activity

Example SPL:

index=aws_cloudtrail | timechart count by source
index=aws_cloudtrail | top limit=10 source
index=aws_cloudtrail | top limit=10 userIdentity.arn
<img width="2063" height="991" alt="image" src="https://github.com/user-attachments/assets/77c9ce9c-39b0-473c-b43a-f5d413e0ea81" />
