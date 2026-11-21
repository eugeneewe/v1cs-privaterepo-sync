# v1cs-privaterepo-sync

Weekly automation to mirror **Trend Micro Vision One Container Security** ECS
Fargate sidecar images from the public Amazon ECR Gallery into a private ECR
registry inside an airgapped AWS environment.

## Problem

[CLOUD_ENV] AWS blocks public ECR (`public.ecr.aws`) for VPC-attached
resources. ECS Fargate task definitions must pull sidecar images from private
ECR. Without automation, every Trend Micro release requires a manual
CloudShell mirroring run.

## Solution

A weekly EventBridge Scheduler → Lambda pipeline mirrors the four ECS sidecar
images digest-exact into private ECR (immutable, versioned tags), keeping the
latest N versions. The Lambda runs **without VPC attachment** (Mode B) — the
same AWS-managed direct egress path CloudShell uses — so no proxy or VPC
endpoints are needed.

## Synced images

| Image | Type | Latest tag |
|---|---|---|
| `cloud-falco` | OCI multi-arch (amd64 + arm64) | 2.2.6 |
| `cloud-scout` | OCI multi-arch (amd64 + arm64) | 2.2.6 |
| `cloud-pdig` | OCI multi-arch (amd64 + arm64) | 2.2.6 |
| `cloud-scan-job` | OCI multi-arch (amd64 + arm64) | 2.2.15 |

Source: `public.ecr.aws/trendmicro/container-security/{image}`
Destination: `{account}.dkr.ecr.ap-southeast-1.amazonaws.com/trendmicro/container-security/{image}`

> `aws-security-manager` is **not** synced here. It is a Lambda Container
> Image managed by Trend Micro's own CodeBuild pipeline inside the official
> `Vision-One-Cloud-Account-Management` stack.

## Repository layout

```
lambda/
  template.yaml                     CloudFormation/SAM stack (deploy this)
  runtime/v1cs-sync-lambda.py       Lambda handler (Python 3.14, stdlib only)
  CUSTOMER_CONSOLE_DEPLOYMENT.md    Step-by-step console deployment guide
  release-public-template.sh        Package + publish a versioned release to S3
  deploy-poc.sh                     Internal POC deploy (AWS CLI only)
  cleanup-poc.sh                    POC teardown
  s3-public-release-bucket-policy.json  S3 public read policy for release bucket
v1cs-privaterepo.sh                 Manual bootstrap / fallback mirroring script
diagram/                            Architecture diagrams
```

## Deployment

Deploys via the CloudFormation Console using a versioned public S3 template
URL. No AWS CLI or SAM CLI required in the target account.

See [`lambda/CUSTOMER_CONSOLE_DEPLOYMENT.md`](lambda/CUSTOMER_CONSOLE_DEPLOYMENT.md)
for the full step-by-step guide.

**Current release:** `2026.11.21`
```
https://eugene-tenet-publicsharings3.s3.ap-southeast-1.amazonaws.com/v1cs-privaterepo-sync/releases/2026.11.21/template.yaml
```

## Publishing a new release

From the `lambda/` directory on a workstation with AWS CLI and credentials:

```bash
RELEASE_VERSION=2026.11.21 bash ./release-public-template.sh
```

## Stack parameters (key)

| Parameter | Default | Notes |
|---|---|---|
| `PrivateRegion` | — | `ap-southeast-1` |
| `ImageTagsKeepCount` | `4` | Latest N pure-numeric tags to retain |
| `EnablePrune` | `true` | Delete tags outside the keep window |
| `ScheduleState` | `DISABLED` | Enable after first manual sync is validated |
| `SnsTopicArn` | _(empty)_ | Optional success/failure notifications |

## Architecture

```
EventBridge Scheduler (weekly, 02:00 SGT)
        │
        ▼
  Lambda (no VPC, AWS-managed egress)
        │  pulls manifests + blobs
        ▼
  public.ecr.aws/trendmicro/container-security/{image}
        │  pushes digest-exact
        ▼
  private ECR: trendmicro/container-security/{image}
        │
        ▼
  CloudWatch metrics + optional SNS notification
```
