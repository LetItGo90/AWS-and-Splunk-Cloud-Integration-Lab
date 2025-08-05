Terraform Deployment – AWS + Splunk Integration Lab

This Terraform configuration automates deployment of an AWS environment for integrating AWS logging services with Splunk Cloud.
What It Deploys:

    Networking

        VPC with a public subnet and internet gateway

        Route table association for internet access

    Logging & Monitoring

        CloudTrail with S3 backend for log storage

        S3 bucket policy granting CloudTrail write permissions

        VPC Flow Logs to CloudWatch

        GuardDuty with sample findings

    Security & Access

        IAM roles for EC2, VPC Flow Logs, and Splunk ingestion

        Security group for SSH access (restricted to your IP)

    Compute

        EC2 instance (Ubuntu) for Atomic Red Team testing

        User data script to install prerequisites and clone Atomic Red Team repo

    Event Processing

        S3 and SQS configuration for forwarding CloudTrail logs to Splunk

        Optional EventBridge rule for GuardDuty automation
