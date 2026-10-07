# Optional live deployment. Supply existing VPC/subnets, TLS certificate, image
# digests, and Secrets Manager configuration before setting deploy_application.
data "aws_subnet" "public" {
  for_each = var.deploy_application ? toset(var.public_subnet_ids) : toset([])
  id       = each.value
}
resource "aws_cloudwatch_log_group" "app" {
  count             = var.deploy_application ? 1 : 0
  name              = "/secureaccess/application"
  retention_in_days = 30
}
resource "aws_ecs_cluster" "app" {
  count = var.deploy_application ? 1 : 0
  name  = "secureaccess"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}
resource "aws_iam_role" "task_execution" {
  count              = var.deploy_application ? 1 : 0
  name               = "SecureAccessTaskExecution"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}
resource "aws_iam_role_policy_attachment" "task_execution" {
  count      = var.deploy_application ? 1 : 0
  role       = aws_iam_role.task_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
resource "aws_iam_role_policy" "task_secrets" {
  count  = var.deploy_application ? 1 : 0
  role   = aws_iam_role.task_execution[0].id
  policy = jsonencode({ Version = "2012-10-17", Statement = concat([{ Effect = "Allow", Action = "secretsmanager:GetSecretValue", Resource = var.application_secret_arn }], var.kms_secret_key_arn != "" ? [{ Effect = "Allow", Action = "kms:Decrypt", Resource = var.kms_secret_key_arn }] : []) })
}
resource "aws_security_group" "alb" {
  count  = var.deploy_application ? 1 : 0
  name   = "secureaccess-alb"
  vpc_id = var.vpc_id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "tasks" {
  count  = var.deploy_application ? 1 : 0
  name   = "secureaccess-tasks"
  vpc_id = var.vpc_id
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb[0].id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_lb" "app" {
  count                      = var.deploy_application ? 1 : 0
  name                       = "secureaccess"
  load_balancer_type         = "application"
  subnets                    = var.public_subnet_ids
  security_groups            = [aws_security_group.alb[0].id]
  enable_deletion_protection = true
}
resource "aws_lb_target_group" "app" {
  count       = var.deploy_application ? 1 : 0
  name        = "secureaccess"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id
  health_check {
    path = "/api/ready"
  }
}
resource "aws_lb_listener" "https" {
  count             = var.deploy_application ? 1 : 0
  load_balancer_arn = aws_lb.app[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app[0].arn
  }
}
resource "aws_ecs_task_definition" "app" {
  count                    = var.deploy_application ? 1 : 0
  family                   = "secureaccess"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.task_execution[0].arn
  task_role_arn            = aws_iam_role.jit_orchestrator.arn
  container_definitions = jsonencode([
    { name = "backend", image = var.backend_image, essential = true, portMappings = [{ containerPort = 8000 }], environment = [
      { name = "APP_ENV", value = "production" }, { name = "DEMO_MODE", value = "false" }, { name = "COOKIE_SECURE", value = "true" }, { name = "AWS_REGION", value = var.aws_region }, { name = "PUBLIC_URL", value = var.public_url }, { name = "ALLOWED_ORIGINS", value = jsonencode([var.public_url]) }, { name = "AUDIT_DYNAMODB_TABLE", value = aws_dynamodb_table.jit_audit_logs.name },
      { name = "AWS_ORCHESTRATOR_ARN", value = aws_iam_role.jit_orchestrator.arn },
      { name = "TRUSTED_PROXY_CIDRS", value = jsonencode(concat(["127.0.0.1/32"], [for id in var.public_subnet_ids : data.aws_subnet.public[id].cidr_block])) },
      { name = "TICKET_VERIFICATION_REQUIRED", value = tostring(var.ticket_verification_required) }
    ], secrets = [for key in concat(["SECRET_KEY", "ENCRYPTION_KEY", "AUDIT_HMAC_KEY", "DATABASE_URL", "AWS_EXTERNAL_ID", "AWS_ACCOUNTS_JSON"], var.optional_secret_keys) : { name = key, valueFrom = "${var.application_secret_arn}:${key}::" }], healthCheck = { command = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/ready')\""], interval = 30, timeout = 5, retries = 3, startPeriod = 30 }, logConfiguration = { logDriver = "awslogs", options = { "awslogs-group" = aws_cloudwatch_log_group.app[0].name, "awslogs-region" = var.aws_region, "awslogs-stream-prefix" = "backend" } } },
    { name = "frontend", image = var.frontend_image, essential = true, environment = [{ name = "BACKEND_HOST", value = "127.0.0.1" }], portMappings = [{ containerPort = 8080 }], dependsOn = [{ containerName = "backend", condition = "HEALTHY" }], logConfiguration = { logDriver = "awslogs", options = { "awslogs-group" = aws_cloudwatch_log_group.app[0].name, "awslogs-region" = var.aws_region, "awslogs-stream-prefix" = "frontend" } } }
  ])
  lifecycle {
    precondition {
      condition     = var.vpc_id != "" && length(var.public_subnet_ids) >= 2 && length(var.private_subnet_ids) >= 2 && var.certificate_arn != "" && var.application_secret_arn != "" && startswith(var.public_url, "https://") && var.backend_image != "" && var.frontend_image != ""
      error_message = "Application deployment requires VPC/subnets, TLS, HTTPS URL, images, and a Secrets Manager configuration."

    }

  }
}
resource "aws_ecs_service" "app" {
  count           = var.deploy_application ? 1 : 0
  name            = "secureaccess"
  cluster         = aws_ecs_cluster.app[0].id
  task_definition = aws_ecs_task_definition.app[0].arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.tasks[0].id]
    assign_public_ip = false
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.app[0].arn
    container_name   = "frontend"
    container_port   = 8080
  }
  depends_on = [aws_lb_listener.https, aws_iam_role_policy_attachment.task_execution, aws_iam_role_policy.task_secrets]
}
