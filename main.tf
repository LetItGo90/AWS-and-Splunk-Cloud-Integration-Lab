provider "aws" {
  region = "us-east-1"
}

##################
# Random ID & Account Info
##################
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

data "aws_caller_identity" "current" {}

##################
# VPC + Subnet
##################
resource "aws_vpc" "lab_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "splunk-lab-vpc" }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.lab_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1a"
  tags = { Name = "splunk-lab-public-subnet" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.lab_vpc.id
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.lab_vpc.id
}

resource "aws_route" "public_internet_access" {
  route_table_id         = aws_route_table.public_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

##################
# CloudTrail
##################
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "splunk-lab-cloudtrail-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck",
        Effect    = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" },
        Action    = "s3:GetBucketAcl",
        Resource  = aws_s3_bucket.cloudtrail_bucket.arn
      },
      {
        Sid       = "AWSCloudTrailWrite",
        Effect    = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" },
        Action    = "s3:PutObject",
        Resource  = "${aws_s3_bucket.cloudtrail_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

##################
# GuardDuty
##################
resource "aws_guardduty_detector" "gd" {
  enable = true
}

resource "null_resource" "guardduty_samples" {
  depends_on = [aws_guardduty_detector.gd]
  provisioner "local-exec" {
    command = <<EOT
      aws guardduty create-sample-findings \
        --detector-id ${aws_guardduty_detector.gd.id} \
        --finding-types Backdoor:EC2/Spambot UnauthorizedAccess:EC2/MaliciousIPCaller.Custom
    EOT
  }
}

##################
# VPC Flow Logs
##################
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flow-logs"
  retention_in_days = 14
}

resource "aws_iam_role" "flow_logs_role" {
  name = "splunk-lab-flowlogs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "vpc-flow-logs.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs_policy" {
  role = aws_iam_role.flow_logs_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"],
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "vpc_flow" {
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn         = aws_iam_role.flow_logs_role.arn
  vpc_id               = aws_vpc.lab_vpc.id
  traffic_type         = "ALL"
}

##################
# EC2 Instance (Atomic Red Team Host)
##################
resource "aws_security_group" "ec2_sg" {
  name   = "splunk-lab-ec2-sg"
  vpc_id = aws_vpc.lab_vpc.id

  ingress {
    description = "Allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["143.59.107.6/32"] # your IP
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "ec2_role" {
  name = "splunk-lab-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cloudwatch_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "splunk-lab-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

resource "aws_instance" "atomic_ec2" {
  ami                         = "ami-0fc5d935ebf8bc3bc" # Ubuntu 22.04 us-east-1
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public_subnet.id
  vpc_security_group_ids      = [aws_security_group.ec2_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = true
  key_name                    = "Soarlab"

  user_data = <<-EOF
    #!/bin/bash
    apt-get update -y
    apt-get install -y unzip curl git python3-pip
    pip3 install invoke
    git clone https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team
    chmod +x /opt/atomic-red-team/atomics
    echo "Atomic Red Team ready."
  EOF

  tags = {
    Name = "splunk-lab-ec2"
  }
}

##################
# GuardDuty → EventBridge → SQS for Splunk
##################
resource "aws_sqs_queue" "guardduty_queue" {
  name = "splunk-guardduty-queue"
}

resource "aws_sqs_queue_policy" "guardduty_sqs_policy" {
  queue_url = aws_sqs_queue.guardduty_queue.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AllowEventBridgeToSendMessages",
        Effect    = "Allow",
        Principal = { Service = "events.amazonaws.com" },
        Action    = "SQS:SendMessage",
        Resource  = aws_sqs_queue.guardduty_queue.arn
      },
      {
        Sid       = "AllowSplunkIngestToRead",
        Effect    = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/splunk-ingest"
        },
        Action = [
          "SQS:ReceiveMessage",
          "SQS:DeleteMessage",
          "SQS:GetQueueAttributes",
          "SQS:ListQueues"
        ],
        Resource = aws_sqs_queue.guardduty_queue.arn
      }
    ]
  })
}

resource "aws_cloudwatch_event_rule" "guardduty_findings_rule" {
  name        = "GuardDutyFindingsToSQS"
  description = "Sends GuardDuty findings to SQS for Splunk ingestion"
  event_pattern = jsonencode({
    "source"      = ["aws.guardduty"],
    "detail-type" = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty_to_sqs" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings_rule.name
  target_id = "SendToSQS"
  arn       = aws_sqs_queue.guardduty_queue.arn
}
