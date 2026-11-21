#!/usr/bin/env bash
# Deploy a local proof of concept of the V1CS image-sync Lambda using only
# AWS CLI CloudFormation commands. No AWS SAM CLI is required.
#
# Mode: no VPC attachment. Lambda uses AWS-managed internet egress, so this
# script neither creates nor modifies a VPC, IGW, NAT gateway, proxy, or VPC
# endpoint. Use only in a non-production POC AWS account.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REGION="${AWS_REGION:-ap-southeast-1}"
STACK_NAME="${STACK_NAME:-TrendMicro-v1cs-privaterepo}"
KEEP_COUNT="${KEEP_COUNT:-4}"
ENABLE_PRUNE="${ENABLE_PRUNE:-false}"
SNS_TOPIC_ARN="${SNS_TOPIC_ARN:-}"
SCHEDULE_STATE="${SCHEDULE_STATE:-DISABLED}"
SCHEDULE_EXPRESSION="${SCHEDULE_EXPRESSION:-cron(0 2 ? * SUN *)}"
SCHEDULE_TIMEZONE="${SCHEDULE_TIMEZONE:-Asia/Singapore}"
SKIP_CONFIRM="${SKIP_CONFIRM:-false}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

[[ "$REGION" == "ap-southeast-1" ]] || fail "This POC is restricted to ap-southeast-1 (received: $REGION)."
[[ "$KEEP_COUNT" =~ ^[1-9][0-9]*$ && "$KEEP_COUNT" -le 10 ]] || fail "KEEP_COUNT must be an integer from 1 to 10."
[[ "$ENABLE_PRUNE" == "false" ]] || fail "POC safety control: ENABLE_PRUNE must remain false."
[[ "$SCHEDULE_STATE" == "ENABLED" || "$SCHEDULE_STATE" == "DISABLED" ]] || fail "SCHEDULE_STATE must be ENABLED or DISABLED."

require_command aws
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text --region "$REGION")" \
  || fail "Unable to identify the active AWS account. Check your AWS credentials."
CALLER_ARN="$(aws sts get-caller-identity --query Arn --output text --region "$REGION")"
ARTIFACT_BUCKET="${ARTIFACT_BUCKET:-eugene-tenet-publicsharings3}"
ARTIFACT_PREFIX="v1cs-privaterepo-sync/${ACCOUNT_ID}/${STACK_NAME}"

echo "V1CS image-sync local POC"
echo "  Account:     $ACCOUNT_ID"
echo "  Principal:   $CALLER_ARN"
echo "  Region:      $REGION"
echo "  Stack:       $STACK_NAME"
echo "  Network:     Lambda without VpcConfig (AWS-managed egress)"
echo "  Images:      cloud-falco, cloud-scout, cloud-pdig"
echo "  Retention:   latest $KEEP_COUNT numeric versions; pruning disabled"
echo "  Schedule:    $SCHEDULE_STATE"
echo "  Expression:  $SCHEDULE_EXPRESSION ($SCHEDULE_TIMEZONE)"
echo "  Artifacts:   s3://$ARTIFACT_BUCKET/$ARTIFACT_PREFIX/"
echo
echo "This packages the Lambda locally with AWS CLI, then creates or updates Lambda, EventBridge Scheduler, IAM roles, private ECR repositories, and CloudWatch resources."
echo "It does not create or modify VPC, IGW, NAT, proxy, or VPC endpoints."

if [[ "$SKIP_CONFIRM" != "true" ]]; then
  read -r -p "Type DEPLOY to continue: " REPLY
  [[ "$REPLY" == "DEPLOY" ]] || {
    echo "Deployment cancelled."
    exit 0
  }
fi

cd "$SCRIPT_DIR"
PACKAGE_DIR="$(mktemp -d)"
PACKAGED_TEMPLATE="$PACKAGE_DIR/packaged-template.yaml"
trap 'rm -rf "$PACKAGE_DIR"' EXIT

aws s3api head-bucket --bucket "$ARTIFACT_BUCKET" --region "$REGION" 2>/dev/null \
  || fail "Cannot access artifact bucket '$ARTIFACT_BUCKET'. Confirm the bucket exists and your principal has S3 read/write access."

echo "Packaging Lambda artifact with AWS CLI CloudFormation..."
aws cloudformation package \
  --template-file template.yaml \
  --s3-bucket "$ARTIFACT_BUCKET" \
  --s3-prefix "$ARTIFACT_PREFIX" \
  --output-template-file "$PACKAGED_TEMPLATE" \
  --region "$REGION"

PARAMETERS=(
  "PrivateRegion=$REGION"
  "ImageTagsKeepCount=$KEEP_COUNT"
  "EnablePrune=false"
  "ScheduleState=$SCHEDULE_STATE"
  "ScheduleCron=$SCHEDULE_EXPRESSION"
  "ScheduleTimeZone=$SCHEDULE_TIMEZONE"
  "ProxyUrl="
  "VpcSubnetIds="
  "VpcSecurityGroupIds="
  "SnsTopicArn=$SNS_TOPIC_ARN"
)

aws cloudformation deploy \
  --template-file "$PACKAGED_TEMPLATE" \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --capabilities CAPABILITY_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides "${PARAMETERS[@]}" \
  --tags "owner=trendmicro" "purpose=V1CS self-manage repo sync" "Deployment=local-poc"

FUNCTION_NAME="$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='SyncFunctionName'].OutputValue" \
  --output text)"
echo
echo "Deployment completed."
echo "Run a controlled first sync with:"
echo "  aws lambda invoke --function-name $FUNCTION_NAME --region $REGION response.json"
echo "Then inspect response.json and CloudWatch logs. To enable the weekly schedule after acceptance, re-run with:"
echo "  SCHEDULE_STATE=ENABLED bash deploy-poc.sh"
