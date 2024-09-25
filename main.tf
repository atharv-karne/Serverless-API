
#Creating VPC
resource "aws_vpc" "serverless_vpc" {
  cidr_block           = var.cidr_block
  enable_dns_hostnames = true
  tags = {
    Name = "${var.customname}-vpc"
  }
}

#Defining all availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

#Creating multiple private sunets 
resource "aws_subnet" "private-subnets" {
  count             = var.private_subnets
  vpc_id            = aws_vpc.serverless_vpc.id
  cidr_block        = cidrsubnet(var.cidr_block, 4, count.index + 1)
  availability_zone = element(data.aws_availability_zones.available.names, count.index)

  tags = {
    Name = "${aws_vpc.serverless_vpc.id}-PrivateSubnet-${count.index + 1}"
  }
}

#Creating S3 endpoint
resource "aws_vpc_endpoint" "s3-endpoint" {
  vpc_id          = aws_vpc.serverless_vpc.id
  service_name    = "com.amazonaws.${var.region}.s3"
  route_table_ids = [aws_route_table.private_route_table.id]

  tags = {
    Name = "${aws_vpc.serverless_vpc.id}-S3-endpoint"
  }
}


#Creating lambda security group to allow outbound traffic inside vpc
resource "aws_security_group" "lambda_sg" {
  name        = "${var.customname}-lambda-sg"
  vpc_id      = aws_vpc.serverless_vpc.id
  description = "Security group for lambda function"
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] 
  }
  tags = {
    Name = "${var.customname}-lambda-sg"
  }
}




#Creating securityt group for another endpoint which is for secrets manager and which will be of type interface
resource "aws_security_group" "secrets_manager_sg" {
  name        = "${var.customname}-sm-endpoint-sg"
  vpc_id      = aws_vpc.serverless_vpc.id
  description = "Security group for secrets manager endpoint"
  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.lambda_sg.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.customname}-sm-sg"
  }
}


#Creating security group for database allowing inbound from lambda sg
resource "aws_security_group" "aurora_db_sg" {
  name        = "${var.customname}-aurora-db-sg"
  vpc_id      = aws_vpc.serverless_vpc.id
  description = "Security group for aurora db"
  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.lambda_sg.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${var.customname}-aurora-db-sg"
  }
}



#Creatin vpc endpoint for secrets manager
resource "aws_vpc_endpoint" "secrets_manager_endpoint" {
  vpc_id              = aws_vpc.serverless_vpc.id
  service_name        = "com.amazonaws.${var.region}.secretsmanager"
  vpc_endpoint_type = "Interface"
  security_group_ids  = [aws_security_group.secrets_manager_sg.id]
  private_dns_enabled = true
  subnet_ids = [for i, subnet in aws_subnet.private-subnets : subnet.id if i < length(data.aws_availability_zones.available.names)]


  tags = {
    Name = "${aws_vpc.serverless_vpc.id}-SecretsManager-endpoint"
  }
}


#Creating route table
resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.serverless_vpc.id

  tags = {
    Name = "${var.customname}-private-route-table"
  }
}


#Associating route table with private subnets
resource "aws_route_table_association" "private_route_table_subnet_association" {
  count          = var.private_subnets
  subnet_id      = aws_subnet.private-subnets[count.index].id
  route_table_id = aws_route_table.private_route_table.id
}


#Creating subnet group for aurora
resource "aws_db_subnet_group" "private_subnet_db_group" {
  name       = "${var.customname}-private-subnet-db-group"
  subnet_ids = [for sbnt in aws_subnet.private-subnets : sbnt.id]
}


#Creating kms key for aurora
resource "aws_kms_key" "aurora_key" {
  description = "Key for aurora encryption"
}


#Creating Rds Aurora cluster
resource "aws_rds_cluster" "aurora_cluster" {
  cluster_identifier            = "serverless-cluster"
  engine                        = "aurora-mysql"
  engine_mode                   = "provisioned"
  engine_version                = "8.0.mysql_aurora.3.04.0"
  database_name                 = "WebAppDB"
  db_subnet_group_name          = aws_db_subnet_group.private_subnet_db_group.name
  vpc_security_group_ids        = [aws_security_group.aurora_db_sg.id]
  master_username               = "admin"
  manage_master_user_password   = true
  storage_encrypted             = true
  master_user_secret_kms_key_id = aws_kms_key.aurora_key.key_id
  skip_final_snapshot           = true

  serverlessv2_scaling_configuration {
    max_capacity = 1
    min_capacity = 0.5
  }
}

#Creating aurora instance
resource "aws_rds_cluster_instance" "aurora_instances" {
  cluster_identifier = aws_rds_cluster.aurora_cluster.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.aurora_cluster.engine
  engine_version     = aws_rds_cluster.aurora_cluster.engine_version

}


#Creating private bucket for code
resource "aws_s3_bucket" "s3_bucket" {
  bucket        = "${var.customname}-custom-serverless-bucket"
  force_destroy = true

}

#Defining policy for bucket
resource "aws_s3_bucket_public_access_block" "s3_block_access" {
  bucket                  = aws_s3_bucket.s3_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#Applying encryption to the bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "s3_bucket_encryption" {
  bucket = aws_s3_bucket.s3_bucket.bucket
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}


#Policy for s3 bucket to allow get, put and delete objects
resource "aws_iam_policy" "s3_bucket_policy" {
  name        = "${var.customname}-s3-bucket-policy"
  description = "Policy for accessing s3 bucket"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "${aws_s3_bucket.s3_bucket.arn}",
          "${aws_s3_bucket.s3_bucket.arn}/*"
        ]
      }
    ]
  })
}


#Getting user identity
data "aws_caller_identity" "current" {}

#Creating policy to allow aurora connect by lambda
resource "aws_iam_policy" "aurora_policy" {
  name        = "${var.customname}-aurora-policy"
  description = "Policy for allowing aurora connect"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "rds-db:connect"
        ]
        Resource = [
          "arn:aws:rds:${var.region}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_rds_cluster.aurora_cluster.id}/${aws_rds_cluster.aurora_cluster.master_username}"
        ]
      }
    ]
  })
}

#Creating policy to allow lambda to access secrets manager value and lms key
resource "aws_iam_policy" "lambda_secrets_manager_key_policy" {
  name        = "${var.customname}-lambda-secrets-manager-policy"
  description = "Policy for allowing lambda to access secrets manager value and kms key"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
        ]
        Resource = aws_rds_cluster.aurora_cluster.master_user_secret[0].secret_arn

      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
        ]
        Resource = aws_rds_cluster.aurora_cluster.master_user_secret[0].kms_key_id

      }
    ]
  })
}

#Creating policy for lambda role to allow eni config
resource "aws_iam_policy" "lambda_eni_policy" {
  name        = "${var.customname}-lambda-eni-policy"
  description = "Policy for allowing lambda to create eni"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "*"
      }
    ]
  })
}


#Create IAM role for lambda
resource "aws_iam_role" "lambda_iam_role" {
  name = "${var.customname}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}


#Attach policies to lambda role

#First basic execution role
resource "aws_iam_policy_attachment" "lambda_basic_policy_attachment" {
  name       = "${var.customname}-lambda-basic-policy-attachment"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  roles      = [aws_iam_role.lambda_iam_role.name]
}

#All permissions
resource "aws_iam_policy_attachment" "lambda_role_policies_attachment" {
  name = "${var.customname}-lambda-role-policies-attachment"
  for_each = {
    "s3" : aws_iam_policy.s3_bucket_policy.arn,
    "aurora" : aws_iam_policy.aurora_policy.arn,
    "secrets" : aws_iam_policy.lambda_secrets_manager_key_policy.arn,
    "eni" : aws_iam_policy.lambda_eni_policy.arn
  }

  policy_arn = each.value
  roles      = [aws_iam_role.lambda_iam_role.name]
}


#Creating lambda

resource "aws_lambda_function" "api_lambda" {
  filename      = var.artifact_location
  function_name = "serverless-api"
  role          = aws_iam_role.lambda_iam_role.arn
  handler       = "index.handler"
  runtime       = "nodejs16.x"

  vpc_config {
    subnet_ids         = [for sbnt in aws_subnet.private-subnets : sbnt.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  environment {
    variables = {
      ENVIRONMENT = "lambda"
      S3_BUCKET   = aws_s3_bucket.s3_bucket.id
      REGION      = var.region
      HOST        = aws_rds_cluster.aurora_cluster.endpoint
      DATABASE    = aws_rds_cluster.aurora_cluster.database_name
      SECRET_ID   = aws_rds_cluster.aurora_cluster.master_user_secret[0].secret_arn
    }
  }

  timeout = 30
}


#Creating lambda permission to be invoked by api gateway
resource "aws_lambda_permission" "api_lambda_permission" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.api_gateway.execution_arn}/*/*"
}

resource "aws_api_gateway_rest_api" "api_gateway" {
  name        = "Inventory-Management-API"
  description = "Inventory Management API"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_resource" "healthz" {
  rest_api_id = aws_api_gateway_rest_api.api_gateway.id
  parent_id   = aws_api_gateway_rest_api.api_gateway.root_resource_id
  path_part   = "healthz"
}

resource "aws_api_gateway_resource" "post_user" {
  rest_api_id = aws_api_gateway_rest_api.api_gateway.id
  parent_id   = aws_api_gateway_rest_api.api_gateway.root_resource_id
  path_part   = "user"
}

resource "aws_api_gateway_resource" "user" {
  rest_api_id = aws_api_gateway_rest_api.api_gateway.id
  parent_id   = aws_api_gateway_resource.post_user.id
  path_part   = "{userId+}"
}

resource "aws_api_gateway_method" "healthz" {
  rest_api_id   = aws_api_gateway_rest_api.api_gateway.id
  resource_id   = aws_api_gateway_resource.healthz.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_method" "post_user" {
  rest_api_id   = aws_api_gateway_rest_api.api_gateway.id
  resource_id   = aws_api_gateway_resource.post_user.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "healthz_integration" {
  rest_api_id             = aws_api_gateway_rest_api.api_gateway.id
  resource_id             = aws_api_gateway_resource.healthz.id
  http_method             = aws_api_gateway_method.healthz.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.api_lambda.invoke_arn
}

resource "aws_api_gateway_integration" "post_user_integration" {
  rest_api_id             = aws_api_gateway_rest_api.api_gateway.id
  resource_id             = aws_api_gateway_resource.post_user.id
  http_method             = aws_api_gateway_method.post_user.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.api_lambda.invoke_arn
}

resource "aws_api_gateway_deployment" "my_api_gateway_deployment" {
  rest_api_id = aws_api_gateway_rest_api.api_gateway.id
  stage_name  = var.api_stage
  triggers = {
    redeployment = sha1(jsonencode(aws_api_gateway_rest_api.api_gateway.body))
  }

  lifecycle {
    create_before_destroy = true
  }
}

data "aws_acm_certificate" "ssl_certificate" {
  domain   = var.domain
  statuses = ["ISSUED"]
}

resource "aws_api_gateway_domain_name" "domain" {
  domain_name              = var.domain
  regional_certificate_arn = data.aws_acm_certificate.ssl_certificate.arn

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

data "aws_route53_zone" "zone" {
  name = var.domain
}

resource "aws_route53_record" "a_record" {
  name    = aws_api_gateway_domain_name.domain.domain_name
  type    = "A"
  zone_id = data.aws_route53_zone.zone.id

  alias {
    evaluate_target_health = true
    name                   = aws_api_gateway_domain_name.domain.regional_domain_name
    zone_id                = aws_api_gateway_domain_name.domain.regional_zone_id
  }
}

resource "aws_api_gateway_base_path_mapping" "path_mapping" {
  api_id      = aws_api_gateway_rest_api.api_gateway.id
  stage_name  = aws_api_gateway_deployment.my_api_gateway_deployment.stage_name
  domain_name = aws_api_gateway_domain_name.domain.domain_name
}
