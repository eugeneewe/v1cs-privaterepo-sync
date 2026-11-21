# [CUSTOMER] CloudFormation Console Deployment

This release is designed for [CUSTOMER] operators who deploy through the AWS
CloudFormation Console, without AWS CLI or AWS SAM CLI.

Synced images (ECS Fargate sidecars): `cloud-falco`, `cloud-scout`, `cloud-pdig`,
`cloud-scan-job` — all from `public.ecr.aws/trendmicro/container-security`.

> **`aws-security-manager` is not synced here.** It is a Lambda Container Image
> managed by Trend Micro's own CodeBuild pipeline inside the official
> `Vision-One-Cloud-Account-Management` stack. Trend Micro's CodeBuild copies it
> to the account's `trendmicro-container-security-aws-security-manager` ECR repo
> automatically on each Vision One update.

## Release contents

The public S3 release location contains two required objects:

1. `template.yaml` — the packaged CloudFormation/SAM template supplied to the
   CloudFormation Console as an HTTPS URL.
2. `artifacts/...` — the packaged Lambda ZIP referenced by the template.

Both objects must remain anonymously readable for the duration of stack create
and future stack updates. They contain implementation code only; do not place
credentials, account IDs, proxy credentials, or customer data in the release.
The Lambda artifact contains only the runtime handler; local POC, cleanup,
release, and documentation files are not deployed to the customer account.

## Console steps (per [CUSTOMER] account)

1. Sign in to the target [CUSTOMER] AWS account and select **ap-southeast-1**.
2. Open **CloudFormation** → **Create stack** → **With new resources**.
3. Select **Amazon S3 URL**, then paste the supplied versioned HTTPS template
   URL.
4. Name the stack `TrendMicro-v1cs-privaterepo`.
5. Supply account-specific parameters:
   - `PrivateRegion`: `ap-southeast-1`.
   - `ImageTagsKeepCount`: set to the desired number of versions to retain per
     image (e.g. `4`). There is no initial-sync timeout risk — see step 8.
   - `EnablePrune`: defaults to `true`; retain this value unless the customer
     explicitly needs to keep numeric tags outside the configured window.
   - `VpcSubnetIds`, `VpcSecurityGroupIds`, and `ProxyUrl`: leave empty for
     the approved no-VPC egress design.
   - `ScheduleState`: begin with `DISABLED` for the pilot; set to `ENABLED`
     after the first manual sync is validated.
   - `ScheduleCron`: `cron(0 2 ? * SUN *)`.
   - `ScheduleTimeZone`: defaults to `Asia/Singapore` (GMT+8), so
     `cron(0 2 ? * SUN *)` runs Sunday at 02:00 SGT.
   - `SnsTopicArn`: optional, account-local ARN.
6. Acknowledge **CAPABILITY_IAM** and create the stack.
7. Verify the resource tags `owner=trendmicro` and
   `purpose=V1CS self-manage repo sync`.
8. **Trigger the first image sync manually**: Go to **Lambda** → open
   `TrendMicro-v1cs-privaterepo-SyncFunction-…` → **Test** → create a test
   event with an empty JSON body `{}` and invoke. The first full sync
   downloads ~490 MiB and may take 5–15 minutes. Monitor progress in
   **CloudWatch Logs**. After it succeeds, validate the private ECR digests
   and then set `ScheduleState` to `ENABLED` via a stack update.

   > **Why manual first sync?** The stack no longer runs an automatic initial
   > sync during creation. This avoids Lambda timeout errors when
   > `ImageTagsKeepCount` is set to 4–5 or more versions across all 4 images.
   > The weekly schedule is idempotent — if a run is interrupted, the next run
   > picks up where it left off.

## Release process (Trend Micro operator)

Run from the `lambda/` directory after the version has passed POC validation:

```bash
RELEASE_VERSION=2026.08.26 ./release-public-template.sh
```

The script packages the Lambda with AWS CLI, uploads a versioned template and
artifact, and confirms that both objects are anonymously retrievable before
displaying the exact URL to share with [CUSTOMER].

## Security boundary

The public release bucket is an explicit customer-approved delivery choice.
Public access must be limited to the versioned release prefix and to read-only
object retrieval. Do not expose bucket listing, write, or delete permissions.

## Public S3 prerequisite

If the bucket has no existing policy, paste the complete document in
`s3-public-release-bucket-policy.json` into the S3 Console. If the bucket
already has a policy, merge the object inside `Statement` from
`s3-public-release-policy-statement.json` into the existing policy's
`Statement` array. Do not replace an existing policy. The statement grants
only anonymous `s3:GetObject` access to `v1cs-privaterepo-sync/releases/*`.

The bucket and account S3 Block Public Access configuration must allow this
public policy. In particular, `BlockPublicPolicy` and `RestrictPublicBuckets`
cannot block the release-prefix policy. Do not disable account-wide controls
without the bucket owner/security team's approval; use a dedicated approved
release bucket if policy requires those controls to remain enabled.
