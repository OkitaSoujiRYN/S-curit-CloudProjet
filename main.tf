provider "aws" {
  region = "eu-west-3"
}
# Variables
variable "ami_id" {
  default = "ami-0f38b927e6597da05" # AMI valide pour Amazon Linux 2 (eu-west-3)
}
variable "key_name" {
  default = "Ryan-Key-Pair" # Nom de la clé SSH
}
variable "vpc_id" {
  default = "vpc-0c4fe92283ca24fef" # VPC ID
}
variable "public_subnet_1" {
  default = "subnet-0d17e836021c347f5" # Subnet public 1
}
variable "public_subnet_2" {
  default = "subnet-0c0cbde2704f616b8" # Subnet public 2
}
variable "public_subnet_id" {
  default = "subnet-0d17e836021c347f5" # Subnet public pour la NAT Gateway
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "Projet-AWS-Ryan"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "IGW-Projet"
  }
}

# Public Subnets
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "eu-west-3a"
  map_public_ip_on_launch = true

  tags = {
    Name = "PublicSubnet1"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "eu-west-3b"
  map_public_ip_on_launch = true

  tags = {
    Name = "PublicSubnet2"
  }
}

# Private Subnets
resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "eu-west-3a"

  tags = {
    Name = "PrivateSubnet1"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "eu-west-3b"

  tags = {
    Name = "PrivateSubnet2"
  }
}


variable "private_subnet_ids" {
  default = [
    "subnet-0ad63ada7d15a6eb1", # Subnet privé 1
    "subnet-07858f34dba921cf4"  # Subnet privé 2
  ]
}

# IAM Role for EC2 to access S3
resource "aws_iam_role" "ec2_role" {
  name = "ec2-s3-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = { Service = "ec2.amazonaws.com" },
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

# Policy for EC2 Role to access S3
resource "aws_iam_policy" "ec2_s3_policy" {
  name = "ec2-s3-policy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["s3:GetObject", "s3:ListBucket"],
        Resource = ["arn:aws:s3:::your-bucket-name/*"]
      }
    ]
  })
}

# Attach policy to the IAM Role
resource "aws_iam_role_policy_attachment" "ec2_s3_policy_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.ec2_s3_policy.arn
}

# Declare the IAM Instance Profile
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2-instance-profile"
  role = aws_iam_role.ec2_role.name
}
# NAT Gateway

resource "aws_eip" "nat_public1" {
  domain = "vpc"
  tags = {
    Name = "NATGatewayProjet1"
  }
}

resource "aws_nat_gateway" "nat_public1" {
  allocation_id     = aws_eip.nat_public1.id
  subnet_id         = aws_subnet.public_a.id
  connectivity_type = "public"
  tags = {
    Name = "NATGatewayProjet1"
  }
}

resource "aws_eip" "nat_public2" {
  domain = "vpc"
  tags = {
    Name = "NATGatewayProjet2"
  }
}

resource "aws_nat_gateway" "nat_public2" {
  allocation_id     = aws_eip.nat_public2.id
  subnet_id         = aws_subnet.public_b.id
  connectivity_type = "public"
  tags = {
    Name = "NATGatewayProjet2"
  }
}

# Route Tables ----------------------

# Public Route Table 1
resource "aws_route_table" "RouteTableProjet_Public_1" {
  vpc_id = aws_vpc.main.id

  # Allow public subnets to access the internet
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "RouteTableProjet_Public_1"
  }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.RouteTableProjet_Public_1.id
}

# Public Route Table 2
resource "aws_route_table" "RouteTableProjet_Public_2" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "RouteTableProjet_Public_2"
  }
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.RouteTableProjet_Public_2.id
}

# Private Route Table 1
resource "aws_route_table" "RouteTableProjet_Privé_1" {
  vpc_id = aws_vpc.main.id

  # Route traffic through the NAT Gateway in AZ1
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_public1.id
  }

  tags = {
    Name = "RouteTableProjet_Privé_1"
  }
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.RouteTableProjet_Privé_1.id
}

# Private Route Table 2
resource "aws_route_table" "RouteTableProjet_Privé_2" {
  vpc_id = aws_vpc.main.id

  # Route traffic through the NAT Gateway in AZ2
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_public2.id
  }

  tags = {
    Name = "RouteTableProjet_Privé_2"
  }
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.RouteTableProjet_Privé_2.id
}

# Security Group pour le Bastion Host
resource "aws_security_group" "bastion_sg" {
  name        = "BastionHostSG"
  description = "Security group for Bastion Host"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Limitez à votre IP publique pour plus de sécurité
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "BastionSecurityGroup"
  }
}
resource "aws_iam_account_password_policy" "password_policy" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 15
  password_reuse_prevention      = 2
}
resource "aws_instance" "bastion" {
  ami                         = var.ami_id
  instance_type               = "t2.micro"
  subnet_id                   = var.public_subnet_1
  vpc_security_group_ids      = [aws_security_group.bastion_sg.id]
  associate_public_ip_address = true
  key_name                    = var.key_name

  iam_instance_profile = aws_iam_instance_profile.ec2_ssm_s3_instance_profile.name

  user_data = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y amazon-ssm-agent
    systemctl enable amazon-ssm-agent
    systemctl start amazon-ssm-agent
  EOF

  tags = {
    Name = "BastionHost"
  }
}

# IAM Role pour activer le SSM Agent
resource "aws_iam_role" "bastion_ssm_role" {
  name = "BastionSSMRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = { Service = "ec2.amazonaws.com" },
        Action    = "sts:AssumeRole"
      }
    ]
  })
}
resource "aws_iam_policy" "mfa_policy" {
  name        = "RequireMFA"
  description = "Policy to enforce MFA for sensitive actions"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "DenyNonMFAAccess",
        Effect   = "Deny",
        Action   = "*",
        Resource = "*",
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" : "false"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role" "ec2_s3_role" {
  name = "ec2-s3-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = { Service = "ec2.amazonaws.com" },
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

# IAM Role pour SSM et S3
# IAM Role pour SSM et S3
resource "aws_iam_role" "ec2_ssm_s3_role" {
  name = "ec2-ssm-s3-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = { Service = "ec2.amazonaws.com" },
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

# Policy personnalisée pour l'accès S3
resource "aws_iam_policy" "ssm_s3_access_policy" {
  name = "SSM_S3_AccessPolicy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        Resource = [
          "arn:aws:s3:::your-bucket-name",  # Remplacez par votre bucket S3
          "arn:aws:s3:::your-bucket-name/*" # Remplacez par vos objets S3
        ]
      }
    ]
  })
}

# Attacher la policy officielle AmazonSSMManagedInstanceCore
resource "aws_iam_role_policy_attachment" "ssm_managed_policy_attachment" {
  role       = aws_iam_role.ec2_ssm_s3_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Attacher la policy personnalisée pour S3
resource "aws_iam_role_policy_attachment" "ssm_s3_policy_attachment" {
  role       = aws_iam_role.ec2_ssm_s3_role.name
  policy_arn = aws_iam_policy.ssm_s3_access_policy.arn
}

# Instance Profile pour associer le rôle aux instances
resource "aws_iam_instance_profile" "ec2_ssm_s3_instance_profile" {
  name = "ec2-ssm-s3-instance-profile"
  role = aws_iam_role.ec2_ssm_s3_role.name
}

# Security Group for Web Traffic
resource "aws_security_group" "web_traffic_sg" {
  name        = "Web-Traffic-SG"
  description = "Allow HTTP and HTTPS traffic for web servers"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # HTTP from anywhere
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # HTTPS from anywhere
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Web-Traffic-SG"
  }
}

# Security Group for Load Balancer
resource "aws_security_group" "load_balancer_sg" {
  name        = "LoadBalancer-SG"
  description = "Allow HTTP and HTTPS traffic for Load Balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "LoadBalancer-SG"
  }
}

# Application Load Balancer
resource "aws_lb" "app_lb" {
  name               = "app-load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.load_balancer_sg.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]

  enable_deletion_protection = false

  tags = {
    Name = "ApplicationLoadBalancer"
  }
}

# Target Group for Application
resource "aws_lb_target_group" "app_target_group" {
  name     = "app-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/index.html"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 2
  }

  tags = {
    Name = "AppTargetGroup"
  }
}

# Listener for Load Balancer
resource "aws_lb_listener" "app_lb_listener" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_target_group.arn
  }

  tags = {
    Name = "AppLoadBalancerListener"
  }
}

# Launch Template for Application Servers
resource "aws_launch_template" "app_server_template" {
  name_prefix = "app-server-"
  description = "Launch Template for Application Server instances"

  image_id      = var.ami_id
  instance_type = "t2.micro"
  key_name      = var.key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_ssm_s3_instance_profile.name
  }

  vpc_security_group_ids = [aws_security_group.web_traffic_sg.id]

  user_data = base64encode(<<EOT
#!/bin/bash
yum update -y
yum install -y httpd amazon-ssm-agent
systemctl start httpd
systemctl enable httpd
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent
echo "<html><body><h1>Welcome to the Application Server in $(curl http://169.254.169.254/latest/meta-data/placement/availability-zone)</h1></body></html>" > /var/www/html/index.html
EOT
  )

  tags = {
    Name = "AppServerLaunchTemplate"
  }
}

resource "aws_autoscaling_group" "app_server_asg" {
  desired_capacity    = 2
  max_size            = 2
  min_size            = 2
  vpc_zone_identifier = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  launch_template {
    id      = aws_launch_template.app_server_template.id
    version = "$Latest"
  }

  target_group_arns = [aws_lb_target_group.app_target_group.arn]
  health_check_type = "EC2"

  tag {
    key                 = "Name"
    value               = "AppServerASG"
    propagate_at_launch = true
  }
}

# Variables
variable "web_instance_ids" {
  default = ["i-0b28da6b87462246e", "i-002691cfb8c700405"] # IDs des instances EC2
}

# SNS Topic pour notifications des alarmes
resource "aws_sns_topic" "alerts" {
  name = "cloudwatch-alerts"
  tags = {
    Name = "CloudWatchAlerts"
  }
}

# Souscrire une adresse e-mail au SNS Topic
resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = "ryan.sebbane@efrei.net" # Remplacez par votre email
}

# Alarme pour utilisation CPU élevée
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "HighCPUUsage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80 # Seuil de 80% d'utilisation CPU

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  dimensions = {
    InstanceId = var.web_instance_ids[0]
  }
}

# Alarme pour faible utilisation CPU
resource "aws_cloudwatch_metric_alarm" "low_cpu" {
  alarm_name          = "LowCPUUsage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 10 # Seuil de 10% d'utilisation CPU

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  dimensions = {
    InstanceId = var.web_instance_ids[0]
  }
}

# Alarme pour utilisation mémoire élevée
resource "aws_cloudwatch_metric_alarm" "high_memory" {
  alarm_name          = "HighMemoryUsage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "mem_used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 80 # Seuil de 80% d'utilisation mémoire

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  dimensions = {
    InstanceId = var.web_instance_ids[0]
  }
}

# Alarme pour nombre de requêtes HTTP 4xx
resource "aws_cloudwatch_metric_alarm" "http_4xx" {
  alarm_name          = "HighHTTP4xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_Target_4XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 100 # Plus de 100 erreurs 4xx

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = "app/my-load-balancer/50dc6c495c0c9188"
  }
}

# Alarme pour nombre de requêtes HTTP 5xx
resource "aws_cloudwatch_metric_alarm" "http_5xx" {
  alarm_name          = "HighHTTP5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 50 # Plus de 50 erreurs 5xx

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = "app/my-load-balancer/50dc6c495c0c9188"
  }
}

# Alarme pour volume disque utilisé
resource "aws_cloudwatch_metric_alarm" "high_disk_usage" {
  alarm_name          = "HighDiskUsage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "disk_used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 90 # Plus de 90% d'utilisation disque

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  dimensions = {
    InstanceId = var.web_instance_ids[0]
  }
}

# Alarme pour trafic réseau entrant élevé
resource "aws_cloudwatch_metric_alarm" "high_network_in" {
  alarm_name          = "HighNetworkIn"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "NetworkIn"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Sum"
  threshold           = 100000000 # Plus de 100 MB reçus

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  dimensions = {
    InstanceId = var.web_instance_ids[0]
  }
}

# Alarme pour trafic réseau sortant élevé
resource "aws_cloudwatch_metric_alarm" "high_network_out" {
  alarm_name          = "HighNetworkOut"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "NetworkOut"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Sum"
  threshold           = 100000000 # Plus de 100 MB envoyés

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  dimensions = {
    InstanceId = var.web_instance_ids[0]
  }
}

# Alarme pour état de l'instance (arrêt inattendu)
resource "aws_cloudwatch_metric_alarm" "instance_status_check" {
  alarm_name          = "InstanceStatusCheckFailed"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "StatusCheckFailed_Instance"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Maximum"
  threshold           = 1

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  dimensions = {
    InstanceId = var.web_instance_ids[0]
  }
}


# SNS Topic pour notifications
resource "aws_sns_topic" "security_alerts" {
  name = "security-alerts"
  tags = {
    Name = "SecurityAlerts"
  }
}

# Souscrire une adresse e-mail pour recevoir les alertes de sécurité
resource "aws_sns_topic_subscription" "security_email_alerts" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = "ryan.sebbane@efrei.net" # Remplacez par votre email
}

# Ajouter un VPC Endpoint pour S3
resource "aws_vpc_endpoint" "s3_endpoint" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.eu-west-3.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.RouteTableProjet_Privé_1.id, aws_route_table.RouteTableProjet_Privé_2.id] # IDs corrects
  tags = {
    Name = "S3-VPC-Endpoint"
  }
}


# Mise à jour de la politique du bucket S3 pour restreindre l'accès au VPC Endpoint
resource "aws_s3_bucket_policy" "bucket_policy" {
  bucket = "awsprojetwebsite" # Nom de votre bucket S3

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AllowAccessFromVPCEndpoint",
        Effect    = "Allow",
        Principal = "*",
        Action    = "s3:*",
        Resource = [
          "arn:aws:s3:::awsprojetwebsite",
          "arn:aws:s3:::awsprojetwebsite/*"
        ],
        Condition = {
          StringEquals = {
            "aws:SourceVpce" : aws_vpc_endpoint.s3_endpoint.id
          }
        }
      },
      {
        Sid       = "DenyAccessFromOutsideVPCEndpoint",
        Effect    = "Deny",
        Principal = "*",
        Action    = "s3:*",
        Resource = [
          "arn:aws:s3:::awsprojetwebsite",
          "arn:aws:s3:::awsprojetwebsite/*"
        ],
        Condition = {
          Bool : {
            "aws:SourceVpce" : "false"
          }
        }
      }
    ]
  })
}

# Alarme 1 : Tentatives de connexion SSH échouées
resource "aws_cloudwatch_metric_alarm" "failed_ssh_attempts" {
  alarm_name          = "FailedSSHAttempts"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "auth-fail"
  namespace           = "Custom/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 5 # Plus de 5 tentatives échouées en 5 minutes

  alarm_actions = [aws_sns_topic.security_alerts.arn]
  ok_actions    = [aws_sns_topic.security_alerts.arn]
}

# Alarme 2 : Activité inhabituelle dans les groupes de sécurité
resource "aws_cloudwatch_metric_alarm" "security_group_changes" {
  alarm_name          = "SecurityGroupChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ChangeSecurityGroup"
  namespace           = "AWS/CloudTrail"
  period              = 60
  statistic           = "Sum"
  threshold           = 1 # Une modification détectée

  alarm_actions = [aws_sns_topic.security_alerts.arn]
  ok_actions    = [aws_sns_topic.security_alerts.arn]
}

# Alarme 3 : Suppression de logs CloudTrail
resource "aws_cloudwatch_metric_alarm" "cloudtrail_log_deletion" {
  alarm_name          = "CloudTrailLogDeletion"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "DeleteTrail"
  namespace           = "AWS/CloudTrail"
  period              = 300
  statistic           = "Sum"
  threshold           = 1 # Toute tentative de suppression de logs

  alarm_actions = [aws_sns_topic.security_alerts.arn]
  ok_actions    = [aws_sns_topic.security_alerts.arn]
}

# Alarme 4 : Appels API non autorisés
resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  alarm_name          = "UnauthorizedAPICalls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedOperation"
  namespace           = "AWS/CloudTrail"
  period              = 60
  statistic           = "Sum"
  threshold           = 1 # Une tentative non autorisée

  alarm_actions = [aws_sns_topic.security_alerts.arn]
  ok_actions    = [aws_sns_topic.security_alerts.arn]
}

# Alarme 5 : Utilisation de clés API root
resource "aws_cloudwatch_metric_alarm" "root_api_calls" {
  alarm_name          = "RootAPICalls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "AWS/CloudTrail"
  period              = 60
  statistic           = "Sum"
  threshold           = 1 # Toute utilisation de la clé root

  alarm_actions = [aws_sns_topic.security_alerts.arn]
  ok_actions    = [aws_sns_topic.security_alerts.arn]
}

# Alarme 6 : Activité réseau inhabituelle (Entrant)
resource "aws_cloudwatch_metric_alarm" "unusual_incoming_traffic" {
  alarm_name          = "UnusualIncomingTraffic"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "NetworkIn"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 100000000 # Plus de 100 MB reçus

  alarm_actions = [aws_sns_topic.security_alerts.arn]
  ok_actions    = [aws_sns_topic.security_alerts.arn]

  dimensions = {
    InstanceId = "i-0b28da6b87462246e" # Remplacez par l'ID de votre instance
  }
}

# Alarme 7 : Activité réseau inhabituelle (Sortant)
resource "aws_cloudwatch_metric_alarm" "unusual_outgoing_traffic" {
  alarm_name          = "UnusualOutgoingTraffic"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "NetworkOut"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 100000000 # Plus de 100 MB envoyés

  alarm_actions = [aws_sns_topic.security_alerts.arn]
  ok_actions    = [aws_sns_topic.security_alerts.arn]

  dimensions = {
    InstanceId = "i-002691cfb8c700405" # Remplacez par l'ID de votre instance
  }
}

# Alarme 8 : Modifications IAM suspectes
resource "aws_cloudwatch_metric_alarm" "iam_policy_changes" {
  alarm_name          = "IAMPolicyChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "PolicyChange"
  namespace           = "AWS/CloudTrail"
  period              = 60
  statistic           = "Sum"
  threshold           = 1 # Toute modification d'une politique IAM

  alarm_actions = [aws_sns_topic.security_alerts.arn]
  ok_actions    = [aws_sns_topic.security_alerts.arn]
}

# Alarme 9 : Création ou suppression de rôles IAM
resource "aws_cloudwatch_metric_alarm" "iam_role_changes" {
  alarm_name          = "IAMRoleChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RoleChange"
  namespace           = "AWS/CloudTrail"
  period              = 60
  statistic           = "Sum"
  threshold           = 1 # Toute création ou suppression de rôle IAM

  alarm_actions = [aws_sns_topic.security_alerts.arn]
  ok_actions    = [aws_sns_topic.security_alerts.arn]
}

# IAM Policies
resource "aws_iam_policy" "enforce_mfa" {
  name        = "EnforceMFA"
  description = "Require MFA for sensitive actions"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "DenyAllActionsWithoutMFA",
        Effect   = "Deny",
        Action   = "*",
        Resource = "*",
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" : "false"
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "s3_limited_access" {
  name        = "S3LimitedAccess"
  description = "Allows limited access to S3 resources"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:ListBucket",
          "s3:GetObject"
        ],
        Resource = [
          "arn:aws:s3:::example-bucket-name",
          "arn:aws:s3:::example-bucket-name/*"
        ]
      }
    ]
  })
}

resource "aws_lambda_permission" "s3_invoke_permission" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ingest_logs.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.cloudtrail_logs.arn
}





resource "aws_iam_policy" "deny_root_api_calls" {
  name        = "DenyRootAPICalls"
  description = "Deny API calls from the root account"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "DenyRootAccountUsage",
        Effect   = "Deny",
        Action   = "*",
        Resource = "*",
        Condition = {
          StringEquals = {
            "aws:PrincipalType" : "Account"
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "iam_restricted_access" {
  name        = "IAMRestrictedAccess"
  description = "Restrict IAM actions"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "iam:Get*",
          "iam:List*",
          "iam:PassRole"
        ],
        Resource = "*"
      },
      {
        Effect = "Deny",
        Action = [
          "iam:Delete*",
          "iam:Update*",
          "iam:Create*",
          "iam:Attach*",
          "iam:Detach*"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "cloudtrail_monitoring" {
  name        = "CloudTrailMonitoring"
  description = "Allow access to CloudTrail logs"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:LookupEvents"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "vpc_endpoint_enforcement" {
  name        = "EnforceVPCEndpoints"
  description = "Force the use of VPC endpoints for S3 access"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "DenyDirectInternetAccess",
        Effect   = "Deny",
        Action   = "s3:*",
        Resource = "*",
        Condition = {
          StringNotEqualsIfExists = {
            "aws:SourceVpce" : "vpce-12345678" # Remplacez par l'ID de votre endpoint VPC
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "security_group_monitoring" {
  name        = "MonitorSecurityGroupChanges"
  description = "Monitor and log security group changes"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress"
        ],
        Resource = "*"
      },
      {
        Effect = "Deny",
        Action = [
          "ec2:DeleteSecurityGroup",
          "ec2:CreateSecurityGroup"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "backup_and_logging" {
  name        = "BackupAndLogging"
  description = "Allow backup and logging to S3 and CloudWatch"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "prevent_resource_deletion" {
  name        = "PreventResourceDeletion"
  description = "Prevent deletion of critical resources"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Deny",
        Action = [
          "ec2:DeleteVpc",
          "ec2:DeleteSubnet",
          "ec2:DeleteRouteTable",
          "s3:DeleteBucket"
        ],
        Resource = "*"
      }
    ]
  })
}


# 1. S3 Bucket pour les logs CloudTrail



# 2. Politique IAM pour permettre à CloudTrail d'écrire dans le bucket S3
resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Autoriser CloudTrail à écrire dans le bucket
      {
        Sid    = "AllowCloudTrailWrite",
        Effect = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action   = "s3:PutObject",
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" : "bucket-owner-full-control"
          }
        }
      },
      # Autoriser CloudTrail à lire les permissions du bucket
      {
        Sid    = "AllowCloudTrailReadBucketAcl",
        Effect = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action   = "s3:GetBucketAcl",
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}"
      }
    ]
  })
}



# 4. Rôle IAM pour Lambda (lecture des logs S3 et écriture dans CloudWatch Logs)
resource "aws_iam_role" "lambda_role" {
  name = "lambda-cloudtrail-ingest-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Permissions IAM pour Lambda
resource "aws_iam_policy" "lambda_policy" {
  name = "lambda-cloudtrail-policy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# 5. Fonction Lambda pour lire les logs depuis S3 et les envoyer dans CloudWatch Logs
resource "aws_lambda_function" "ingest_logs" {
  function_name = "cloudtrail-s3-to-cloudwatch"
  role          = aws_iam_role.lambda_role.arn
  runtime       = "python3.8"
  handler       = "lambda_function.lambda_handler"
  filename      = "lambda_function.zip" # Chargez votre code Lambda ici

  source_code_hash = filebase64sha256("lambda_function.zip")

  environment {
    variables = {
      LOG_GROUP_NAME = "CloudTrailLogs"
    }
  }

  tags = {
    Name = "CloudTrailLambdaIngest"
  }
}

# 6. Ajouter une notification S3 pour déclencher la fonction Lambda
resource "aws_s3_bucket_notification" "cloudtrail_logs_notification" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.ingest_logs.arn
    events              = ["s3:ObjectCreated:*"]
  }
}

# 7. Créer un groupe de logs dans CloudWatch Logs
resource "aws_cloudwatch_log_group" "cloudtrail_log_group" {
  name              = "/aws/cloudtrail/logs"
  retention_in_days = 30

  tags = {
    Name = "CloudTrailLogGroup"
  }
}

# 8. Créer des filtres de métriques pour surveiller les logs
resource "aws_cloudwatch_log_metric_filter" "unauthorized_operation_filter" {
  name           = "UnauthorizedOperationFilter"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_log_group.name
  pattern        = "{ ($.errorCode = \"UnauthorizedOperation\") || ($.errorCode = \"AccessDenied\") }"

  metric_transformation {
    name      = "UnauthorizedOperationCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

# 9. Créer une alarme CloudWatch pour les opérations non autorisées
resource "aws_cloudwatch_metric_alarm" "unauthorized_operation_alarm" {
  alarm_name          = "UnauthorizedOperationAlarm"
  metric_name         = aws_cloudwatch_log_metric_filter.unauthorized_operation_filter.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.unauthorized_operation_filter.metric_transformation[0].namespace
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"

  alarm_description = "Détecte les erreurs UnauthorizedOperation ou AccessDenied"
  alarm_actions     = [aws_sns_topic.alerts.arn]
}


resource "aws_iam_role" "some_role" {
  name = "some_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "SomeRole"
  }
}

# Groupe admins
resource "aws_iam_group" "admins" {
  name = "admins"
}
resource "aws_iam_group" "read_only" {
  name = "read-only"
}

resource "aws_iam_group" "developers" {
  name = "developers"
}


# Attach Policies to Roles or Groups
resource "aws_iam_role_policy_attachment" "enforce_mfa_attachment" {
  role       = aws_iam_role.some_role.name
  policy_arn = aws_iam_policy.enforce_mfa.arn
}

resource "aws_iam_group_policy_attachment" "backup_policy_attachment" {
  group      = aws_iam_group.admins.name
  policy_arn = aws_iam_policy.backup_and_logging.arn
}

resource "aws_iam_group_policy_attachment" "cloudtrail_policy_attachment" {
  group      = aws_iam_group.admins.name
  policy_arn = aws_iam_policy.cloudtrail_monitoring.arn
}

resource "aws_iam_group_policy_attachment" "security_group_monitoring_attachment" {
  group      = aws_iam_group.admins.name
  policy_arn = aws_iam_policy.security_group_monitoring.arn
}

resource "aws_iam_group_policy_attachment" "s3_limited_access_attachment" {
  group      = aws_iam_group.read_only.name
  policy_arn = aws_iam_policy.s3_limited_access.arn
}

resource "aws_iam_group_policy_attachment" "deny_root_api_calls_attachment" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.deny_root_api_calls.arn
}


#----------------------------------------------------Cloudtrailk bucket S3----------------------------------------------------#
# Générer un suffixe aléatoire pour rendre le nom unique
resource "random_id" "bucket_suffix" {
  byte_length = 8
}

# Bucket S3 pour collecter les logs de CloudTrail
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "cloudtrail-logs-${random_id.bucket_suffix.hex}"
  acl           = "private"
  force_destroy = true

  # Encryption configuration
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = {
    Name = "CloudTrailLogsBucket"
  }
}

# Versioning for S3 Bucket
resource "aws_s3_bucket_versioning" "cloudtrail_logs_versioning" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Bloquer tout accès public au bucket S3
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs_access_block" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Politique S3 pour autoriser uniquement CloudTrail à écrire dans le bucket
resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AWSCloudTrailWrite",
        Effect = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action   = "s3:PutObject",
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" : "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailReadBucketAcl",
        Effect = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action   = "s3:GetBucketAcl",
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}"
      },
      {
        Sid       = "AllowVPCEndpointAccess",
        Effect    = "Allow",
        Principal = "*",
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        Resource = [
          "${aws_s3_bucket.cloudtrail_logs.arn}",
          "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        ],
        Condition = {
          StringEquals = {
            "aws:SourceVpce" : "${aws_vpc_endpoint.s3_endpoint.id}"
          }
        }
      },
      {
        Sid       = "DenyNonVPCEndpointAccess",
        Effect    = "Deny",
        Principal = "*",
        Action    = "s3:*",
        Resource = [
          "${aws_s3_bucket.cloudtrail_logs.arn}",
          "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        ],
        Condition = {
          Bool : {
            "aws:SourceVpce" : "false"
          }
        }
      }
    ]
  })
}



# Configurer CloudTrail pour écrire les logs dans le bucket S3
resource "aws_cloudtrail" "main" {
  name                          = "cloudtrail-main"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::${aws_s3_bucket.cloudtrail_logs.bucket}/"]
    }
  }

  tags = {
    Name = "CloudTrailMain"
  }
}
# Groupe de logs CloudWatch pour VPC Flow Logs
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/flow-logs"
  retention_in_days = 30 # Conserve les logs pendant 30 jours

  tags = {
    Name = "VPC-Flow-Logs"
  }
}

# IAM Role pour VPC Flow Logs
resource "aws_iam_role" "vpc_flow_logs_role" {
  name = "vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "VPC-Flow-Logs-Role"
  }
}

# Attacher une politique pour autoriser les logs VPC à être envoyés vers CloudWatch Logs
resource "aws_iam_policy" "vpc_flow_logs_policy" {
  name        = "VPCFlowLogsPolicy"
  description = "Policy for VPC Flow Logs to write to CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ],
        Resource = aws_cloudwatch_log_group.vpc_flow_logs.arn
      }
    ]
  })
}

# Attachement de la policy au rôle IAM
resource "aws_iam_role_policy_attachment" "vpc_flow_logs_role_attachment" {
  role       = aws_iam_role.vpc_flow_logs_role.name
  policy_arn = aws_iam_policy.vpc_flow_logs_policy.arn
}

# VPC Flow Log attaché au VPC
resource "aws_flow_log" "vpc_flow_logs" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL" # Capture du trafic entrant et sortant
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.vpc_flow_logs.arn
  iam_role_arn         = aws_iam_role.vpc_flow_logs_role.arn

  tags = {
    Name = "VPC-Flow-Logs"
  }
}
