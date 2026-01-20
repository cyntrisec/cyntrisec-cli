# Cyntrisec Read-Only IAM Role
# Usage: cyntrisec scan --role-arn <output.role_arn>

resource "aws_iam_role" "cyntrisecreadonly" {
  name = "CyntrisecReadOnly"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::123456789012:root"
            },
            "Action": "sts:AssumeRole"
        }
    ]
})

  tags = {
    Purpose   = "Cyntrisec"
    ManagedBy = "terraform"
    ReadOnly  = "true"
  }
}

resource "aws_iam_role_policy" "cyntrisecreadonly_policy" {
  name   = "CyntrisecReadOnlyPolicy"
  role   = aws_iam_role.cyntrisecreadonly.id
  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CyntrisecReadOnly",
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "iam:Get*",
                "iam:List*",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketLocation",
                "s3:ListBucket",
                "s3:ListAllMyBuckets",
                "lambda:GetFunction",
                "lambda:GetFunctionConfiguration",
                "lambda:GetPolicy",
                "lambda:ListFunctions",
                "rds:Describe*",
                "elasticloadbalancing:Describe*",
                "route53:List*",
                "route53:Get*",
                "cloudfront:Get*",
                "cloudfront:List*",
                "apigateway:GET",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
})
}

output "role_arn" {
  value = aws_iam_role.cyntrisecreadonly.arn
}
