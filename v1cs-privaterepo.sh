#!/usr/bin/env bash
set -euo pipefail

##############################################################################
# 0. CONFIG — edit these before running
##############################################################################
PRIVATE_REGION="ap-southeast-1"                     # region of your private ECR
# PRIVATE_ACCOUNT_ID comes from whatever credentials this CloudShell session
# is using right now — run this FROM the target account (e.g. [CUSTOMER] UAT
# 478443392009), not from a different account's CloudShell/profile.
PRIVATE_ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
PRIVATE_REGISTRY="${PRIVATE_ACCOUNT_ID}.dkr.ecr.${PRIVATE_REGION}.amazonaws.com"

PUBLIC_NAMESPACE="trendmicro/container-security"    # gallery path
PUBLIC_REGISTRY="public.ecr.aws/${PUBLIC_NAMESPACE}"
# These are the actual published names — NOT "falco"/"scout"/"pdig". Verified
# against gallery.ecr.aws and against a live [CUSTOMER] task definition pinned by
# digest; "cloud-scout" etc. are genuinely separate images, not a rename.
IMAGES=(cloud-falco cloud-scout cloud-pdig)

# MIRROR_MODE:
#   latest   -> mirror only the highest numeric version found upstream
#               (all flavors of it, e.g. "3.5.1" AND "3.5.1-ubi" if both exist)
#   all      -> mirror every version tag found (still skips cosign .sig tags)
#   override -> only mirror the exact tags listed in TAGS_OVERRIDE below
MIRROR_MODE="override"
declare -A TAGS_OVERRIDE=(
  [cloud-falco]="2.2.6"
  [cloud-scout]="2.2.6"
  [cloud-pdig]="2.2.6"
)

# Prefix for the private repo name. Set to PUBLIC_NAMESPACE so the private
# path mirrors the public one exactly, e.g. trendmicro/container-security/falco
DST_PREFIX="${PUBLIC_NAMESPACE}"

##############################################################################
# 1. Pre-flight checks — install crane if it isn't already on PATH
##############################################################################
if ! command -v crane >/dev/null 2>&1; then
  echo "==> crane not found, installing to ~/bin"
  mkdir -p "$HOME/bin"
  curl -sSL https://github.com/google/go-containerregistry/releases/latest/download/go-containerregistry_Linux_x86_64.tar.gz \
    | tar -xz -C "$HOME/bin" crane
  export PATH="$HOME/bin:$PATH"
fi
command -v crane >/dev/null 2>&1 || { echo "crane install failed"; exit 1; }
command -v curl  >/dev/null 2>&1 || { echo "curl not found"; exit 1; }
command -v jq    >/dev/null 2>&1 || { echo "jq not found"; exit 1; }

##############################################################################
# 2. Auth — public gallery is always us-east-1, private repo is your region
##############################################################################
echo "==> Authenticating to public ECR gallery"
crane auth login public.ecr.aws -u AWS \
  -p "$(aws ecr-public get-login-password --region us-east-1)"

echo "==> Authenticating to private ECR (${PRIVATE_REGION})"
crane auth login "$PRIVATE_REGISTRY" -u AWS \
  -p "$(aws ecr get-login-password --region "$PRIVATE_REGION")"

##############################################################################
# 3. Mirror each image
##############################################################################
for IMAGE in "${IMAGES[@]}"; do
  SRC_REPO="${PUBLIC_REGISTRY}/${IMAGE}"
  DST_REPO_NAME="${DST_PREFIX}/${IMAGE}"
  DST_REPO="${PRIVATE_REGISTRY}/${DST_REPO_NAME}"

  echo ""
  echo "### ${IMAGE} ###"

  # 3a. Create the private repo if it doesn't exist yet
  if ! aws ecr describe-repositories --region "$PRIVATE_REGION" \
        --repository-names "$DST_REPO_NAME" >/dev/null 2>&1; then
    echo "==> Creating private repo ${DST_REPO_NAME}"
    aws ecr create-repository \
      --region "$PRIVATE_REGION" \
      --repository-name "$DST_REPO_NAME" \
      --image-tag-mutability IMMUTABLE \
      --image-scanning-configuration scanOnPush=true >/dev/null
  fi

  # 3b. Work out which tags to sync
  #
  # Note: `aws ecr-public describe-images` only lists images in YOUR OWN
  # account's public registry — there's no cross-account query for someone
  # else's gallery repo (like trendmicro's). To list tags on a public repo
  # you don't own, use the anonymous Docker Registry v2 tags/list endpoint
  # instead; no AWS credentials involved, since the repo is public.
  case "$MIRROR_MODE" in
    latest|all)
      PUBLIC_TOKEN=$(curl -fsSL "https://public.ecr.aws/token/" | jq -r '.token')
      ALL_TAGS=$(curl -fsSL -H "Authorization: Bearer ${PUBLIC_TOKEN}" \
        "https://public.ecr.aws/v2/${PUBLIC_NAMESPACE}/${IMAGE}/tags/list" \
        | jq -r '.tags[]?' \
        | grep -Ev '^sha256-' \
        | grep -E '^[0-9]+(\.[0-9]+)*(-[A-Za-z0-9]+)*$' || true)

      if [ "$MIRROR_MODE" = "all" ]; then
        TAGS="$ALL_TAGS"
      else
        # Numeric-aware sort (not lexicographic — "3.5.1" must beat "1.0.0")
        # to find the true highest version, then match that version EXACTLY —
        # this deliberately excludes flavor-suffixed tags like "3.5.1-ubi".
        # Change the grep below to "^${LATEST_VERSION}([-.]|$)" if you want
        # those flavors mirrored too.
        LATEST_VERSION=$(echo "$ALL_TAGS" \
          | sed -E 's/^([0-9]+(\.[0-9]+)*).*/\1/' \
          | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n -u \
          | tail -1)
        TAGS=$(echo "$ALL_TAGS" | grep -E "^${LATEST_VERSION}$" || true)
      fi
      ;;
    override)
      TAGS="${TAGS_OVERRIDE[$IMAGE]}"
      ;;
    *)
      echo "Unknown MIRROR_MODE: $MIRROR_MODE" >&2
      exit 1
      ;;
  esac

  if [ -z "$TAGS" ]; then
    echo "    !! no tags found for ${IMAGE}, skipping"
    continue
  fi

  # 3c. Copy each tag, then verify the digest matches
  for TAG in $TAGS; do
    SRC_DIGEST=$(crane digest "${SRC_REPO}:${TAG}")

    if EXISTING_DIGEST=$(crane digest "${DST_REPO}:${TAG}" 2>/dev/null); then
      if [ "$EXISTING_DIGEST" = "$SRC_DIGEST" ]; then
        echo "==> ${IMAGE}:${TAG} already mirrored, digest matches — skipping"
        continue
      else
        echo "    !! ${IMAGE}:${TAG} exists in the private repo but its digest"
        echo "       does NOT match upstream. Since the repo is IMMUTABLE this"
        echo "       tag can't be overwritten — delete it manually if you want"
        echo "       to re-mirror:"
        echo "         aws ecr batch-delete-image --region ${PRIVATE_REGION} \\"
        echo "           --repository-name ${DST_REPO_NAME} --image-ids imageTag=${TAG}"
        echo "       upstream: ${SRC_DIGEST}"
        echo "       private:  ${EXISTING_DIGEST}"
        continue
      fi
    fi

    echo "==> Mirroring ${IMAGE}:${TAG}"
    crane copy "${SRC_REPO}:${TAG}" "${DST_REPO}:${TAG}"

    DST_DIGEST=$(crane digest "${DST_REPO}:${TAG}")
    if [ "$SRC_DIGEST" = "$DST_DIGEST" ]; then
      echo "    OK  digest matches: ${SRC_DIGEST}"
    else
      echo "    !!  DIGEST MISMATCH"
      echo "        src: ${SRC_DIGEST}"
      echo "        dst: ${DST_DIGEST}"
    fi
  done
done

echo ""
echo "==> Done."