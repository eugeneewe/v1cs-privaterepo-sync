#!/usr/bin/env bash
# Package a console-ready CloudFormation release into the approved public S3
# bucket. This script does not change bucket policy, ACLs, or public-access
# settings: the bucket owner must preconfigure anonymous read access to the
# release prefix before customer use.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REGION="${AWS_REGION:-ap-southeast-1}"
RELEASE_BUCKET="${RELEASE_BUCKET:-eugene-tenet-publicsharings3}"
RELEASE_VERSION="${RELEASE_VERSION:-$(date -u +%Y%m%dT%H%M%SZ)}"
RELEASE_PREFIX="v1cs-privaterepo-sync/releases/${RELEASE_VERSION}"
PUBLIC_TEMPLATE_URL="https://${RELEASE_BUCKET}.s3.${REGION}.amazonaws.com/${RELEASE_PREFIX}/template.yaml"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

[[ "$REGION" == "ap-southeast-1" ]] || fail "Release is restricted to ap-southeast-1 (received: $REGION)."
[[ "$RELEASE_VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ ]] \
  || fail "RELEASE_VERSION may contain only letters, numbers, period, underscore, and hyphen (maximum 80 characters)."

require_command aws
require_command curl

aws sts get-caller-identity --region "$REGION" >/dev/null \
  || fail "Unable to identify the active AWS account. Check your AWS credentials."
aws s3api head-bucket --bucket "$RELEASE_BUCKET" --region "$REGION" 2>/dev/null \
  || fail "Cannot access release bucket '$RELEASE_BUCKET'."

echo "Creating V1CS private-repository sync release"
echo "  Region:  $REGION"
echo "  Bucket:  $RELEASE_BUCKET"
echo "  Version: $RELEASE_VERSION"
echo "  Prefix:  s3://$RELEASE_BUCKET/$RELEASE_PREFIX/"

cd "$SCRIPT_DIR"
RELEASE_TMPDIR="$(mktemp -d)"
PACKAGED_TEMPLATE="$RELEASE_TMPDIR/template.yaml"
trap 'rm -rf "$RELEASE_TMPDIR"' EXIT

# `package` uploads the local Lambda directory and rewrites CodeUri into an
# S3 object reference in the output template. The returned template can be
# launched directly from the CloudFormation Console by URL.
aws cloudformation package \
  --template-file template.yaml \
  --s3-bucket "$RELEASE_BUCKET" \
  --s3-prefix "$RELEASE_PREFIX/artifacts" \
  --metadata "owner=trendmicro,purpose=V1CS self-manage repo sync" \
  --output-template-file "$PACKAGED_TEMPLATE" \
  --region "$REGION"

aws s3 cp "$PACKAGED_TEMPLATE" "s3://$RELEASE_BUCKET/$RELEASE_PREFIX/template.yaml" \
  --content-type "application/x-yaml" \
  --metadata "owner=trendmicro,purpose=V1CS self-manage repo sync" \
  --region "$REGION"

# The same anonymous access required by CloudFormation must succeed for this
# URL. A 200 response confirms the template is publicly retrievable.
HTTP_STATUS="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$PUBLIC_TEMPLATE_URL")"
if [[ "$HTTP_STATUS" != "200" ]]; then
  fail "Release uploaded, but anonymous access to the template returned HTTP $HTTP_STATUS. Configure public read access for s3://$RELEASE_BUCKET/$RELEASE_PREFIX/ before sharing this URL."
fi

ARTIFACT_KEYS="$(aws s3api list-objects-v2 \
  --bucket "$RELEASE_BUCKET" \
  --prefix "$RELEASE_PREFIX/artifacts/" \
  --query 'Contents[].Key' \
  --output text \
  --region "$REGION")"
[[ -n "$ARTIFACT_KEYS" && "$ARTIFACT_KEYS" != "None" ]] \
  || fail "No packaged Lambda artifact was found under s3://$RELEASE_BUCKET/$RELEASE_PREFIX/artifacts/."

for artifact_key in $ARTIFACT_KEYS; do
  artifact_url="https://${RELEASE_BUCKET}.s3.${REGION}.amazonaws.com/${artifact_key}"
  HTTP_STATUS="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$artifact_url")"
  [[ "$HTTP_STATUS" == "200" ]] \
    || fail "Release uploaded, but anonymous access to Lambda artifact '$artifact_key' returned HTTP $HTTP_STATUS. Configure public read access for s3://$RELEASE_BUCKET/$RELEASE_PREFIX/ before sharing this URL."
done

echo
echo "Release completed; the template and Lambda artifact are anonymously retrievable:"
echo "  $PUBLIC_TEMPLATE_URL"
echo
echo "[CUSTOMER] CloudFormation Console: Create stack > With new resources > Upload a template file / Amazon S3 URL > paste this URL."
echo "Acknowledge CAPABILITY_IAM, then supply the customer-account parameters."
