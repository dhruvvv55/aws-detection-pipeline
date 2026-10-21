locals {
  trail_name = "${var.project_name}-trail"
  # Built by hand so the bucket policy can reference the trail before it exists
  trail_arn = "arn:aws:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"
}

# ---------- Log bucket ----------

resource "aws_s3_bucket" "trail" {
  #checkov:skip=CKV_AWS_145:SSE-S3 (AES256) is enabled; a KMS CMK adds cost and key policy work for no gain in a single-account lab
  #checkov:skip=CKV_AWS_144:Cross-region replication is out of scope for a single-region lab; logs are integrity-protected by CloudTrail log file validation
  #checkov:skip=CKV_AWS_18:Access logging would need a second log bucket; this bucket is private, ACLs are disabled, and only CloudTrail can write to it
  #checkov:skip=CKV2_AWS_62:Detection runs off EventBridge, not S3 object events, so bucket notifications have no consumer
  # Bucket names are global across all AWS accounts, so suffix with account ID
  bucket        = "${var.project_name}-cloudtrail-${local.account_id}"
  force_destroy = true # lets terraform destroy remove it even with logs inside
}

# Versioning protects log objects from being overwritten or deleted
resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    object_ownership = "BucketOwnerEnforced" # disables ACLs entirely
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = var.log_retention_days
    }
    # Versioning keeps old copies, so expire those on the same schedule
    noncurrent_version_expiration {
      noncurrent_days = var.log_retention_days
    }
    # Clean up half-finished uploads so they don't sit around costing money
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.trail]
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    # Only our trail can use this bucket (confused deputy protection)
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.trail.arn,
      "${aws_s3_bucket.trail.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json

  # Applying a policy while the public access block is still being written can race
  depends_on = [aws_s3_bucket_public_access_block.trail]
}

# ---------- Trail ----------

resource "aws_cloudtrail" "main" {
  #checkov:skip=CKV_AWS_35:Logs are encrypted at rest with SSE-S3; a KMS CMK is extra cost and key policy work for a single-account lab
  #checkov:skip=CKV_AWS_252:Delivery notifications are not needed; findings alert through the project's own SNS topic
  #checkov:skip=CKV2_AWS_10:Detection consumes CloudTrail through EventBridge, so a CloudWatch Logs copy would only duplicate cost
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true # record activity in every region, not just ours
  include_global_service_events = true # IAM, STS, etc. (delivered to us-east-1)
  enable_log_file_validation    = true # signed digests prove logs weren't altered

  # CloudTrail checks bucket permissions at creation time, so the policy must exist first
  depends_on = [aws_s3_bucket_policy.trail]
}
