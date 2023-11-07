provider "aws" {
  region  = "us-west-2"
  access_key = "YOUR_AWS_ACCESS_KEY"
  secret_key = "YOUR_AWS_SECRET_KEY"
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

# Subnets Configuration
resource "aws_subnet" "public_subnet_1" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone = "us-west-2a"
}

resource "aws_subnet" "public_subnet_2" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.2.0/24"
  map_public_ip_on_launch = true
  availability_zone = "us-west-2b"
}

resource "aws_subnet" "private_subnet_1" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.3.0/24"
  availability_zone = "us-west-2a"
}

resource "aws_subnet" "private_subnet_2" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.4.0/24"
  availability_zone = "us-west-2b"
}

resource "aws_subnet" "db_subnet_1" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.5.0/24"
  availability_zone = "us-west-2a"
}

resource "aws_subnet" "db_subnet_2" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.6.0/24"
  availability_zone = "us-west-2b"
}

# Security Groups Configuration
resource "aws_security_group" "public_sg" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "private_sg" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_security_group.public_sg.id]
  }
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    security_groups = [aws_security_group.public_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db_sg" {
  vpc_id = aws_vpc.main.id
  description = "Allow traffic from private subnets"

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = [aws_security_group.private_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_subnet_group" "rds_subnet_group" {
  name       = "main-rds-subnet-group"
  subnet_ids = [aws_subnet.db_subnet_1.id, aws_subnet.db_subnet_2.id]

  tags = {
    Name = "Main RDS Subnet Group"
  }
}

resource "aws_db_parameter_group" "custom_mysql" {
  name   = "custom-mysql5-7"
  family = "mysql"
  parameter {
    name  = "test"
    value = "0"
  }
}

resource "aws_db_instance" "main" {
  allocated_storage       = 50
  storage_type            = "gp2"
  engine                  = "mysql"
  engine_version          = "5.7"
  instance_class          = "db.t2.micro"
  name                    = "mydb"
  username                = "DB_USER"
  password                = "DB_PASS" #Store in a secrets manager in production
  parameter_group_name    = "aws_db_parameter_group.custom_mysql.name"
  skip_final_snapshot     = true
  vpc_security_group_ids  = [aws_security_group.db_sg.id]
  db_subnet_group_name    = aws_db_subnet_group.rds_subnet_group.name
  multi_az                = true
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.rds_encryption.arn
  deletion_protection     = true
}

output "db_endpoint" {
  value = aws_db_instance.mysql_db.endpoint
}

# Network ACLs Configuration
resource "aws_network_acl" "public_subnet_1_acl" {
  vpc_id = aws_vpc.main.id

  egress {
    protocol   = "-1"
    rule_no    = 111
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 112
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 113
    action     = "allow"
    cidr_block = "10.0.0.0/8"
    from_port  = 22
    to_port    = 22
  }
}

resource "aws_network_acl_association" "public_subnet_1_assoc" {
  subnet_id      = aws_subnet.public_subnet_1.id
  network_acl_id = aws_network_acl.public_subnet_1_acl.id
}

resource "aws_network_acl" "public_subnet_2_acl" {
  vpc_id = aws_vpc.main.id

  egress {
    protocol   = "-1"
    rule_no    = 114
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 115
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 116
    action     = "allow"
    cidr_block = "10.0.0.0/8"
    from_port  = 22
    to_port    = 22
  }
}

resource "aws_network_acl_association" "public_subnet_2_assoc" {
  subnet_id      = aws_subnet.public_subnet_2.id
  network_acl_id = aws_network_acl.public_subnet_2_acl.id
}

resource "aws_network_acl" "private_subnet_1_acl" {
  vpc_id = aws_vpc.main.id

  egress {
    protocol   = "-1"
    rule_no    = 117
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 118
    action     = "allow"
    cidr_block = aws_subnet.public_subnet_1.cidr_block
    from_port  = 443
    to_port    = 443
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 119
    action     = "allow"
    cidr_block = aws_subnet.public_subnet_1.cidr_block
    from_port  = 22
    to_port    = 22
  }
}

resource "aws_network_acl_association" "private_subnet_1_assoc" {
  subnet_id      = aws_subnet.private_subnet_1.id
  network_acl_id = aws_network_acl.private_subnet_1_acl.id
}

resource "aws_network_acl" "private_subnet_2_acl" {
  vpc_id = aws_vpc.main.id

  egress {
    protocol   = "-1"
    rule_no    = 120
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 121
    action     = "allow"
    cidr_block = aws_subnet.public_subnet_2.cidr_block
    from_port  = 443
    to_port    = 443
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 122
    action     = "allow"
    cidr_block = aws_subnet.public_subnet_2.cidr_block
    from_port  = 22
    to_port    = 22
  }
}

resource "aws_network_acl_association" "private_subnet_2_assoc" {
  subnet_id      = aws_subnet.private_subnet_2.id
  network_acl_id = aws_network_acl.private_subnet_2_acl.id
}

resource "aws_network_acl" "db_subnet_1_acl" {
  vpc_id = aws_vpc.main.id

  egress {
    protocol   = "-1"
    rule_no    = 123
    action     = "allow"
    cidr_block = "10.0.0.0/8"
    from_port  = 0
    to_port    = 0
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 124
    action     = "allow"
    cidr_block = aws_subnet.private_subnet_1.cidr_block
    from_port  = 3306
    to_port    = 3306
  }
}

resource "aws_network_acl_association" "db_subnet_1_assoc" {
  subnet_id      = aws_subnet.db_subnet_1.id
  network_acl_id = aws_network_acl.db_subnet_1_acl.id
}

resource "aws_network_acl" "db_subnet_2_acl" {
  vpc_id = aws_vpc.main.id

  egress {
    protocol   = "-1"
    rule_no    = 125
    action     = "allow"
    cidr_block = "10.0.0.0/8"
    from_port  = 0
    to_port    = 0
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 126
    action     = "allow"
    cidr_block = aws_subnet.private_subnet_2.cidr_block
    from_port  = 3306
    to_port    = 3306
  }
}

resource "aws_network_acl_association" "db_subnet_2_assoc" {
  subnet_id      = aws_subnet.db_subnet_2.id
  network_acl_id = aws_network_acl.db_subnet_2_acl.id
}

# ALB Configuration
resource "aws_lb" "main" {
  name               = "main-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.public_sg.id]
  subnets            = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id]

  enable_deletion_protection = true
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.front_end.arn
  }
}

resource "aws_lb_target_group" "front_end" {
  name     = "front-end-tg"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.main.id
}

# EC2 & ASG Configuration

# Launch Configuration
resource "aws_launch_configuration" "asg_config" {
  name_prefix = "EC2_Config"
  image_id      = "AMI-ID"
  instance_type = "t2.micro"

  security_groups = [aws_security_group.private_sg.id]

  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "asg" {
  launch_configuration = aws_launch_configuration.asg_config.name
  min_size             = 2
  max_size             = 4
  desired_capacity     = 2
  vpc_zone_identifier  = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]

  tag {
    key                 = "Name"
    value               = "terraform-asg"
    propagate_at_launch = true
  }
}

# Bastion Configuration
resource "aws_instance" "bastion" {
  ami             = "AMI-ID"
  instance_type   = "t2.micro"
  subnet_id       = aws_subnet.public_subnet_2.id
  key_name        = "AWS_KEY_NAME"

  vpc_security_group_ids = [aws_security_group.public_sg.id]

  tags = {
    Name = "Bastion"
  }
}

# WAF Configuration
resource "aws_wafv2_web_acl" "example" {
  name        = "AWS_WAF"
  scope       = "REGIONAL"
  description = "List of a managed rule."

  default_action {
    allow {}
  }
}

resource "aws_wafv2_web_acl_association" "aws_waf_ex" {
  web_acl_arn = aws_wafv2_web_acl.aws_waf_ex.arn
  resource_arn = aws_lb.main.arn
}

# KMS Configuration
resource "aws_kms_key" "rds_encryption" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 14
  enable_key_rotation     = true
}

resource "aws_iam_role" "ec2_role" {
  name = "ec2_role"

  assume_role_policy = jsonencode({
    Version = "2023-11-05",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Effect = "Allow",
        Sid    = ""
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_profile"
  role = aws_iam_role.ec2_role.name
}

resource "aws_iam_role_policy_attachment" "ec2_s3_access" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
  role       = aws_iam_role.ec2_role.name
}

# Cloudtrail

resource "aws_cloudtrail" "aws_ct_default" {
  name                          = "aws_ct_default"
  s3_bucket_name                = "S3_BUCKET_NAME"
  enable_log_file_validation    = true
  is_multi_region_trail         = true
}

# Cloudwatch Alarm

resource "aws_cloudwatch_metric_alarm" "aws_cloudwatch" {
  alarm_name          = "aws_cloudwatch_alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric checks ec2 cpu utilization"
  alarm_actions       = [] 
}