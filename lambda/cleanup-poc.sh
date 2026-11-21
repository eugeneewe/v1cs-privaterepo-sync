#!/usr/bin/env bash
# Remove resources created by deploy-poc.sh in a local POC account.
#
# This script deletes the CloudFormation stack, the three ECR repositories
# created at Lambda runtime (including their images), and the Lambda log group.
# It intentionally does NOT delete the SAM-managed S3 artifacts bucket because
# that bucket can be shared by other SAM deployments in the account.

set -euo pipefail

REGION="${AWS_REGION:-ap-southeast-1}"
STACK_NAME="${STACK_NAME:-TrendMicro-v1cs-privaterepo}"
SKIP_CONFIRM="${SKIP_CONFIRM:-false}"
REPOSITORIES=(
  "trendmicro/container-security/cloud-falco"
  "trendmicro/container-security/cloud-scout"
  "trendmicro/container-security/cloud-pdig"
)

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

[[ "$REGION" == "ap-southeast-1" ]] || fail "This POC cleanup is restricted to ap-southeast-1 (received: $REGION)."
[[ "$STACK_NAME" == "TrendMicro-v1cs-privaterepo" || "$STACK_NAME" == TrendMicro-v1cs-privaterepo-* ]] \
  || fail "Safety control: STACK_NAME must be TrendMicro-v1cs-privaterepo or start with TrendMicro-v1cs-privaterepo-."

require_command aws

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text --region "$REGION")" \
  || fail "Unable to identify the active AWS account. Check your AWS credentials."
CALLER_ARN="$(aws sts get-caller-identity --query Arn --output text --region "$REGION")"
ARTIFACT_BUCKET="${ARTIFACT_BUCKET:-eugene-tenet-publicsharings3}"
ARTIFACT_PREFIX="v1cs-privaterepo-sync/${ACCOUNT_ID}/${STACK_NAME}"

FUNCTION_NAME="$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='SyncFunctionName'].OutputValue" \
  --output text 2>/dev/null || true)"

if [[ -z "$FUNCTION_NAME" || "$FUNCTION_NAME" == "None" ]]; then
  fail "Stack '$STACK_NAME' was not found, or does not contain SyncFunctionName. Nothing was deleted."
fi

echo "V1CS image-sync POC cleanup"
echo "  Account:     $ACCOUNT_ID"
echo "  Principal:   $CALLER_ARN"
echo "  Region:      $REGION"
echo "  Stack:       $STACK_NAME"
echo "  Function:    $FUNCTION_NAME"
echo "  Artifacts:   s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/"
echo
echo "This permanently deletes:"
echo "  1. CloudFormation stack resources (Lambda, Scheduler, IAM roles, optional alarm)"
echo "  2. All images and the three POC private ECR repositories"
echo "  3. The Lambda CloudWatch log group"
echo
echo "This deletes only this POC's artifact prefix in S3; the bucket and all other contents are retained."
echo "CloudWatch metric history is retained."

if [[ "$SKIP_CONFIRM" != "true" ]]; then
  read -r -p "Type DELETE-POC to permanently delete these resources: " REPLY
  [[ "$REPLY" == "DELETE-POC" ]] || {
    echo "Cleanup cancelled."
    exit 0
  }
fi

echo "Deleting CloudFormation stack..."
aws cloudformation delete-stack --stack-name "$STACK_NAME" --region "$REGION"
aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" --region "$REGION"
echo "CloudFormation stack deleted."

for repository in "${REPOSITORIES[@]}"; do
  if aws ecr describe-repositories --repository-names "$repository" --region "$REGION" >/dev/null 2>&1; then
    echo "Deleting ECR repository and all images: $repository"
    aws ecr delete-repository --repository-name "$repository" --force --region "$REGION"
  else
    echo "ECR repository not found; skipping: $repository"
  fi
done

LOG_GROUP="/aws/lambda/$FUNCTION_NAME"
if aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP" --region "$REGION" \
  --query "logGroups[?logGroupName=='$LOG_GROUP'].logGroupName" --output text | grep -qx "$LOG_GROUP"; then
  echo "Deleting CloudWatch log group: $LOG_GROUP"
  aws logs delete-log-group --log-group-name "$LOG_GROUP" --region "$REGION"
else
  echo "CloudWatch log group not found; skipping: $LOG_GROUP"
fi

if aws s3api head-bucket --bucket "$ARTIFACT_BUCKET" --region "$REGION" 2>/dev/null; then
  echo "Deleting POC artifact prefix: s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/"
  aws s3 rm "s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX" --recursive --region "$REGION"
else
  echo "Artifact bucket not accessible; skipping artifact cleanup: $ARTIFACT_BUCKET"
fi

echo
echo "POC cleanup completed."
