#!/usr/bin/env python3
import base64
import hashlib
import json
import logging
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --------------------------------------------------------------------------
# Configuration (from Lambda environment variables)
# --------------------------------------------------------------------------
PUBLIC_REGISTRY = os.environ.get("PUBLIC_REGISTRY", "public.ecr.aws")
PUBLIC_NAMESPACE = os.environ.get("PUBLIC_NAMESPACE", "trendmicro/container-security")
IMAGES = [i.strip() for i in os.environ.get("IMAGES", "cloud-falco,cloud-scout,cloud-pdig").split(",") if i.strip()]

KEEP_VERSIONS = int(os.environ.get("KEEP_VERSIONS", "4"))          # latest + (n-3) = 4 by default
ENABLE_PRUNE = os.environ.get("ENABLE_PRUNE", "false").lower() == "true"
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "").strip()

PRIVATE_REGION = os.environ.get("PRIVATE_REGION", "ap-southeast-1")
PRIVATE_ACCOUNT_ID = os.environ.get("PRIVATE_ACCOUNT_ID", "").strip()
if not PRIVATE_ACCOUNT_ID:
    # Fallback only; prefer setting PRIVATE_ACCOUNT_ID at deploy time so the
    # Lambda never needs sts:GetCallerIdentity (avoids needing an STS VPCe).
    PRIVATE_ACCOUNT_ID = boto3.client("sts", region_name=PRIVATE_REGION).get_caller_identity()["Account"]

PRIVATE_REGISTRY = f"{PRIVATE_ACCOUNT_ID}.dkr.ecr.{PRIVATE_REGION}.amazonaws.com"
DST_PREFIX = os.environ.get("DST_PREFIX", PUBLIC_NAMESPACE)  # private path mirrors public path

# Proxy: public.ecr.aws goes THROUGH the [CLOUD_ENV] proxy; everything else
# (private ECR, AWS APIs) goes DIRECT via VPC endpoints.
HTTPS_PROXY = os.environ.get("HTTPS_PROXY", "") or os.environ.get("https_proxy", "")
NO_PROXY = os.environ.get("NO_PROXY", "") or os.environ.get("no_proxy", "")
if PRIVATE_REGISTRY and PRIVATE_REGISTRY not in NO_PROXY:
    NO_PROXY = f"{NO_PROXY},{PRIVATE_REGISTRY}" if NO_PROXY else PRIVATE_REGISTRY

REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "600"))

# Registry media types we accept on manifest GET and must preserve on PUT.
OCI_INDEX_MT = "application/vnd.oci.image.index.v1+json"
DOCKER_INDEX_MT = "application/vnd.docker.distribution.manifest.list.v2+json"
OCI_MANIFEST_MT = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST_MT = "application/vnd.docker.distribution.manifest.v2+json"
MANIFEST_ACCEPT = ", ".join([OCI_INDEX_MT, DOCKER_INDEX_MT, OCI_MANIFEST_MT, DOCKER_MANIFEST_MT])

# Pure numeric version tags only ("2.2.6"). Excludes "2.2.6-spc", "*.sig", "sha256-*".
VERSION_RE = re.compile(r"^\d+(\.\d+)+$")

ECS_CLUSTER_TAG = os.environ.get("ECS_CLUSTER_TAG", "")  # optional free-text tag for metrics/SNS context
RESOURCE_TAGS = [
    {"Key": "owner", "Value": os.environ.get("RESOURCE_TAG_OWNER", "trend micro")},
    {"Key": "purpose", "Value": os.environ.get("RESOURCE_TAG_PURPOSE", "V1CS self-manage repo sync")},
]


# --------------------------------------------------------------------------
# HTTP plumbing (stdlib, proxy-aware)
# --------------------------------------------------------------------------
def _host_of(url: str) -> str:
    return urllib.parse.urlparse(url).netloc.rsplit("@", 1)[-1].split(":")[0]


def _should_bypass_proxy(url: str) -> bool:
    host = _host_of(url)
    if not NO_PROXY:
        return False
    for entry in NO_PROXY.split(","):
        entry = entry.strip().lower()
        if not entry:
            continue
        if entry == "*":
            return True
        if host.lower() == entry or host.lower().endswith(entry if entry.startswith(".") else f".{entry}"):
            return True
    return False


def _opener(url: str):
    """Return an opener with the [CLOUD_ENV] proxy configured, unless this URL
    should go direct (private registry / VPC-endpoint reachable hosts)."""
    if HTTPS_PROXY and not _should_bypass_proxy(url):
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": HTTPS_PROXY, "https": HTTPS_PROXY})
        )
    # Direct (no proxy): private ECR via VPCe, SNS/STS via VPCe, etc.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body=None,
    timeout: int = REQUEST_TIMEOUT,
) -> Tuple[int, dict, bytes]:
    """Simple request returning (status, headers, body-bytes)."""
    opener = _opener(url)
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), e.read()


def _request_stream(url: str, headers: Dict[str, str], dest_path: str) -> Tuple[int, dict, str]:
    """GET a blob, streaming to dest_path; returns (status, headers, sha256-hex of bytes)."""
    digest = hashlib.sha256()
    opener = _opener(url)
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(req, timeout=REQUEST_TIMEOUT) as resp:
            with open(dest_path, "wb") as fh:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    fh.write(chunk)
            return resp.status, dict(resp.headers.items()), digest.hexdigest()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), digest.hexdigest()


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------
def public_token() -> str:
    """Anonymous bearer token for the public gallery (same flow as the bash script)."""
    status, _, body = _request(f"https://{PUBLIC_REGISTRY}/token/", timeout=30)
    if status != 200:
        raise RuntimeError(f"public token endpoint returned {status}")
    return json.loads(body)["token"]


_private_auth_token: Optional[str] = None
_private_auth_token_for_registry: Optional[str] = None


def private_basic_auth() -> str:
    """Basic auth header for the private registry, from ecr:GetAuthorizationToken."""
    global _private_auth_token, _private_auth_token_for_registry
    if _private_auth_token and _private_auth_token_for_registry == PRIVATE_REGISTRY:
        return _private_auth_token
    ecr = boto3.client("ecr", region_name=PRIVATE_REGION)
    data = ecr.get_authorization_token()["authorizationData"][0]
    _private_auth_token = data["authorizationToken"]  # base64("AWS:password")
    _private_auth_token_for_registry = PRIVATE_REGISTRY
    return _private_auth_token


# --------------------------------------------------------------------------
# Public gallery (read) helpers
# --------------------------------------------------------------------------
def list_public_tags(image: str, token: str) -> List[str]:
    url = f"https://{PUBLIC_REGISTRY}/v2/{PUBLIC_NAMESPACE}/{image}/tags/list"
    status, _, body = _request(url, headers={"Authorization": f"Bearer {token}"}, timeout=60)
    if status != 200:
        raise RuntimeError(f"tags/list for {image} returned {status}")
    return json.loads(body).get("tags", [])


def get_public_manifest(image: str, reference: str, token: str) -> Tuple[dict, bytes]:
    """Return (parsed-manifest, raw-bytes) for a tag or digest on the public gallery."""
    url = f"https://{PUBLIC_REGISTRY}/v2/{PUBLIC_NAMESPACE}/{image}/manifests/{urllib.parse.quote(reference, safe='')}"
    status, _, body = _request(url, headers={"Accept": MANIFEST_ACCEPT, "Authorization": f"Bearer {token}"}, timeout=60)
    if status != 200:
        raise RuntimeError(f"manifest {image}:{reference} returned {status}")
    return json.loads(body), body


def download_public_blob(image: str, digest: str, token: str, dest_path: str) -> None:
    url = f"https://{PUBLIC_REGISTRY}/v2/{PUBLIC_NAMESPACE}/{image}/blobs/{urllib.parse.quote(digest, safe='')}"
    status, _, sha = _request_stream(url, {"Authorization": f"Bearer {token}"}, dest_path)
    if status != 200:
        raise RuntimeError(f"blob {digest} for {image} returned {status}")
    expected = digest.removeprefix("sha256:")
    if sha != expected:
        raise RuntimeError(f"blob {digest} for {image}: digest mismatch (got sha256:{sha})")


# --------------------------------------------------------------------------
# Private ECR (write) helpers
# --------------------------------------------------------------------------
def _private_url(path: str) -> str:
    return f"https://{PRIVATE_REGISTRY}{path}"


def _private_headers() -> Dict[str, str]:
    return {"Authorization": f"Basic {private_basic_auth()}"}


def ensure_repository(repo_name: str) -> None:
    """Create the private repo if missing (immutable + scan-on-push, like the bash script)."""
    ecr = boto3.client("ecr", region_name=PRIVATE_REGION)
    try:
        repository = ecr.describe_repositories(repositoryNames=[repo_name])["repositories"][0]
    except ecr.exceptions.RepositoryNotFoundException:
        logger.info("Creating private repository %s", repo_name)
        repository = ecr.create_repository(
            repositoryName=repo_name,
            imageTagMutability="IMMUTABLE",
            imageScanningConfiguration={"scanOnPush": True},
            tags=RESOURCE_TAGS,
        )["repository"]
    # Reconcile tags on repositories created by an earlier POC run as well.
    ecr.tag_resource(resourceArn=repository["repositoryArn"], tags=RESOURCE_TAGS)


def put_manifest(repo_path: str, reference: str, raw: bytes, media_type: str) -> str:
    """PUT a manifest (by digest or tag) into the private registry; returns its digest."""
    url = _private_url(f"/v2/{repo_path}/manifests/{urllib.parse.quote(reference, safe='')}")
    headers = _private_headers()
    headers["Content-Type"] = media_type
    status, resp_headers, body = _request(url, method="PUT", headers=headers, body=raw, timeout=300)
    if status != 201:
        raise RuntimeError(f"PUT manifest {repo_path}:{reference} returned {status}: {body[:300]!r}")
    return resp_headers.get("Docker-Content-Digest", "sha256:" + hashlib.sha256(raw).hexdigest())


def ensure_manifest_tag(repo_path: str, reference: str, raw: bytes,
                        media_type: str, expected_digest: str) -> bool:
    """Ensure `reference` points to an existing manifest; return True if created."""
    url = _private_url(f"/v2/{repo_path}/manifests/{urllib.parse.quote(reference, safe='')}")
    headers = _private_headers()
    headers["Accept"] = MANIFEST_ACCEPT
    status, resp_headers, body = _request(url, method="HEAD", headers=headers, timeout=60)

    if status == 200:
        got = resp_headers.get("Docker-Content-Digest", "")
        if got != expected_digest:
            raise RuntimeError(
                f"tag {repo_path}:{reference} points to {got}, expected {expected_digest}"
            )
        return False

    if status != 404:
        raise RuntimeError(f"checking tag {repo_path}:{reference} returned {status}: {body[:300]!r}")

    got = put_manifest(repo_path, reference, raw, media_type)
    if got != expected_digest:
        raise RuntimeError(
            f"tag {repo_path}:{reference} returned {got}, expected {expected_digest}"
        )
    return True


def upload_blob(repo_path: str, digest: str, src_file: str, src_size: int,
                mount_from_repos: Optional[List[str]] = None) -> bool:
    """
    Upload one blob into the private repo (preserving digest). Returns True
    if a NEW blob was uploaded, False if it was cross-repo mounted or
    already present (fast path).

    Tries, in order:
      1. cross-repo mount from other private repos in the same account
         (falco/pdig share base layers - saves bandwidth/time on re-syncs)
      2. monolithic upload (initiate -> single PUT with full body), which
         ECR supports and keeps memory bounded by streaming from disk
    """
    blobs_base = f"/v2/{repo_path}/blobs/uploads/"
    encoded_digest = urllib.parse.quote(digest, safe="")

    # 1. Cross-repo mount attempt
    if mount_from_repos:
        for src_repo in mount_from_repos:
            url = _private_url(blobs_base) + f"?mount={encoded_digest}&from={urllib.parse.quote(src_repo, safe='')}"
            status, resp_headers, body = _request(url, method="POST", headers=_private_headers(), timeout=120)
            if status == 201:
                got = resp_headers.get("Docker-Content-Digest", "")
                if got and got != digest:
                    raise RuntimeError(f"mount {digest}: got {got}")
                logger.info("  mounted %s from %s", digest, src_repo)
                return False
            if status == 202:
                break  # not mountable from this repo -> upload via returned Location
            if status in (404, 405):
                continue  # source repo missing / mount unsupported -> try next
            # 4xx auth/policy errors on mount -> fall through to plain upload
            break

    # 2. Monolithic upload
    status, resp_headers, body = _request(_private_url(blobs_base), method="POST", headers=_private_headers(), timeout=120)
    if status != 202:
        raise RuntimeError(f"initiate upload {digest} returned {status}: {body[:300]!r}")
    location = resp_headers.get("Location") or resp_headers.get("location")
    if not location:
        raise RuntimeError(f"initiate upload {digest}: no Location header")

    upload_url = location if location.startswith("http") else _private_url(location)
    # Docker Registry v2 completes a monolithic upload by PUTing the bytes to
    # the upload Location *with* the expected layer digest in the query
    # string. ECR rejects the request when layerDigest is absent.
    query_separator = "&" if "?" in upload_url else "?"
    upload_url = f"{upload_url}{query_separator}digest={urllib.parse.quote(digest, safe=':')}"
    headers = _private_headers()
    headers["Content-Type"] = "application/octet-stream"
    headers["Content-Length"] = str(src_size)
    with open(src_file, "rb") as fh:
        status, resp_headers, body = _request(upload_url, method="PUT", headers=headers, body=fh, timeout=900)
    if status != 201:
        raise RuntimeError(f"complete upload {digest} returned {status}: {body[:300]!r}")
    got = resp_headers.get("Docker-Content-Digest", "")
    if got and got != digest:
        raise RuntimeError(f"upload {digest}: ECR returned {got}")
    logger.info("  uploaded %s (%d bytes)", digest, src_size)
    return True


# --------------------------------------------------------------------------
# Version selection
# --------------------------------------------------------------------------
def _sort_key(tag: str) -> List[int]:
    return [int(p) for p in tag.split(".")]


def select_versions(tags: List[str], keep: int) -> List[str]:
    """Top `keep` pure-numeric versions, highest first (e.g. 2.2.6, 2.2.5...)."""
    numeric = sorted({t for t in tags if VERSION_RE.match(t)}, key=_sort_key, reverse=True)
    return numeric[:keep]


# --------------------------------------------------------------------------
# Core mirror
# --------------------------------------------------------------------------
def mirror_image(image: str, token: str, keep: int, mount_repos: List[str]) -> dict:
    """Mirror the top `keep` versions of one image. Returns a report dict."""
    report = {"image": image, "synced": [], "unchanged": [], "pruned": [], "errors": []}

    repo_name = f"{DST_PREFIX}/{image}"
    src_repo = f"{PUBLIC_NAMESPACE}/{image}"
    ensure_repository(repo_name)

    all_tags = list_public_tags(image, token)
    versions = select_versions(all_tags, keep)
    if not versions:
        report["errors"].append("no pure-numeric version tags found upstream")
        return report

    # Which numeric tags are currently in the private repo? (used for idempotency + prune)
    ecr = boto3.client("ecr", region_name=PRIVATE_REGION)
    private_tags: List[str] = []
    try:
        for page in ecr.get_paginator("describe_images").paginate(repositoryName=repo_name):
            private_tags.extend(
                img.get("imageTags", []) for img in page.get("imageDetails", [])
            )
    except ecr.exceptions.RepositoryNotFoundException:
        pass
    private_numeric = {t for tags in private_tags for t in tags if VERSION_RE.match(t)}

    for version in versions:
        try:
            digest = mirror_one_version(image, src_repo, repo_name, version, token, mount_repos)
            if version in private_numeric:
                report["unchanged"].append(version)
            else:
                report["synced"].append(version)
        except Exception as e:  # noqa: BLE001 - keep per-image resilience, surface at the end
            logger.exception("Failed to mirror %s:%s", image, version)
            report["errors"].append(f"{version}: {e}")

    # Optional pruning of numeric tags older than the keep-window.
    if ENABLE_PRUNE:
        keep_set = set(versions)
        stale = sorted(private_numeric - keep_set, key=_sort_key, reverse=True)
        if stale:
            ids = [{"imageTag": t} for t in stale]
            logger.warning("Pruning %s old tags from %s: %s", len(stale), repo_name, stale)
            ecr.batch_delete_image(repositoryName=repo_name, imageIds=ids)
            report["pruned"] = stale
    return report


def mirror_one_version(image: str, src_repo: str, dst_repo: str, version: str,
                       token: str, mount_repos: List[str]) -> str:
    """
    Copy image:version from public gallery to private ECR preserving the
    exact digest. Returns the manifest digest.
    """
    logger.info("Mirroring %s:%s -> %s/%s", src_repo, version, PRIVATE_REGISTRY, dst_repo)

    index, index_raw = get_public_manifest(image, version, token)
    if index.get("mediaType") in (OCI_INDEX_MT, DOCKER_INDEX_MT) or "manifests" in index:
        children = index["manifests"]
        child_digests = [c["digest"] for c in children]

        # Fast-path: if the top-level index is already in the private repo with
        # the same digest, skip blob transfer but still ensure this version tag.
        expected_index_digest = "sha256:" + hashlib.sha256(index_raw).hexdigest()
        probe_url = _private_url(f"/v2/{dst_repo}/manifests/{expected_index_digest}")
        status, resp_headers, _ = _request(probe_url, method="HEAD", headers=_private_headers(), timeout=60)
        if status == 200:
            got = resp_headers.get("Docker-Content-Digest", "")
            if got and got != expected_index_digest:
                raise RuntimeError(f"index digest mismatch: expected {expected_index_digest}, got {got}")
            tag_created = ensure_manifest_tag(
                dst_repo,
                version,
                index_raw,
                index.get("mediaType", OCI_INDEX_MT),
                expected_index_digest,
            )
            logger.info(
                "  index already present (%s) - tag %s %s",
                expected_index_digest,
                version,
                "created" if tag_created else "already present",
            )
            return expected_index_digest

        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. blobs (config + layers) of every child manifest
            all_blobs: Dict[str, Tuple[str, int]] = {}
            child_raw_by_digest: Dict[str, Tuple[bytes, str]] = {}
            for child in children:
                cdigest = child["digest"]
                if cdigest in child_raw_by_digest:
                    continue
                child_manifest, child_raw = get_public_manifest(image, cdigest, token)
                if "manifests" in child_manifest:
                    raise RuntimeError(f"unexpected nested index at {cdigest}")
                child_raw_by_digest[cdigest] = (child_raw, child_manifest.get("mediaType", OCI_MANIFEST_MT))
                for blob_ref in [child_manifest.get("config", {})] + child_manifest.get("layers", []):
                    all_blobs.setdefault(blob_ref["digest"], (blob_ref["digest"], int(blob_ref["size"])))

            for blob_digest, (_, size) in all_blobs.items():
                blob_file = os.path.join(tmpdir, blob_digest.replace(":", "_"))
                download_public_blob(image, blob_digest, token, blob_file)
                upload_blob(dst_repo, blob_digest, blob_file, size, mount_from_repos=mount_repos)
                os.remove(blob_file)

            # 2. child manifests by digest
            for cdigest, (child_raw, ctype) in child_raw_by_digest.items():
                got = put_manifest(dst_repo, cdigest, child_raw, ctype)
                if got != cdigest:
                    raise RuntimeError(f"child manifest digest mismatch: got {got}, expected {cdigest}")

            # 3. index under the version tag
            got = put_manifest(dst_repo, version, index_raw, index.get("mediaType", OCI_INDEX_MT))
            if got != expected_index_digest:
                raise RuntimeError(f"index digest mismatch: got {got}, expected {expected_index_digest}")
        return expected_index_digest

    # Single-platform image (not an index) - still copy config + layers.
    manifest, manifest_raw = index, index_raw
    expected = "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
    probe_url = _private_url(f"/v2/{dst_repo}/manifests/{expected}")
    status, resp_headers, _ = _request(probe_url, method="HEAD", headers=_private_headers(), timeout=60)
    if status == 200:
        tag_created = ensure_manifest_tag(
            dst_repo,
            version,
            manifest_raw,
            manifest.get("mediaType", DOCKER_MANIFEST_MT),
            expected,
        )
        logger.info(
            "  manifest already present (%s) - tag %s %s",
            expected,
            version,
            "created" if tag_created else "already present",
        )
        return expected
    with tempfile.TemporaryDirectory() as tmpdir:
        all_blobs = {}
        for blob_ref in [manifest.get("config", {})] + manifest.get("layers", []):
            all_blobs.setdefault(blob_ref["digest"], (blob_ref["digest"], int(blob_ref["size"])))
        for blob_digest, (_, size) in all_blobs.items():
            blob_file = os.path.join(tmpdir, blob_digest.replace(":", "_"))
            download_public_blob(image, blob_digest, token, blob_file)
            upload_blob(dst_repo, blob_digest, blob_file, size, mount_from_repos=mount_repos)
            os.remove(blob_file)
    got = put_manifest(dst_repo, version, manifest_raw, manifest.get("mediaType", DOCKER_MANIFEST_MT))
    if got != expected:
        raise RuntimeError(f"manifest digest mismatch: got {got}, expected {expected}")
    return expected


# --------------------------------------------------------------------------
# Reporting: CloudWatch metrics + optional SNS
# --------------------------------------------------------------------------
def emit_metrics(reports: List[dict]) -> None:
    synced = sum(len(r["synced"]) for r in reports)
    errors = sum(len(r["errors"]) for r in reports)
    cw = boto3.client("cloudwatch", region_name=PRIVATE_REGION)
    cw.put_metric_data(
        Namespace="V1CS/ContainerSecurity",
        MetricData=[
            {"MetricName": "ImagesSynced", "Value": float(synced), "Unit": "Count"},
            {"MetricName": "SyncErrors", "Value": float(errors), "Unit": "Count"},
        ],
    )


def send_notification(reports: List[dict], status: str) -> None:
    if not SNS_TOPIC_ARN:
        return
    payload = {
        "event": "v1cs-container-security-sync",
        "status": status,
        "account": PRIVATE_ACCOUNT_ID,
        "region": PRIVATE_REGION,
        "ecs_cluster_tag": ECS_CLUSTER_TAG,
        "reports": reports,
    }
    boto3.client("sns", region_name=PRIVATE_REGION).publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[V1CS] Container Security image sync: {status}",
        Message=json.dumps(payload, indent=2),
    )


# --------------------------------------------------------------------------
# Handler
# --------------------------------------------------------------------------
def run_sync() -> dict:
    """Mirror the configured images once and return the operation report."""
    logger.info("Starting V1CS container security image sync (region=%s, images=%s)",
                PRIVATE_REGION, IMAGES)
    token = public_token()
    reports: List[dict] = []

    # Mount sources: private repos of the other images (same account/registry),
    # so shared base layers are cross-repo mounted instead of re-uploaded.
    mount_repos = [f"{DST_PREFIX}/{i}" for i in IMAGES]

    for image in IMAGES:
        report = mirror_image(image, token, KEEP_VERSIONS, [r for r in mount_repos if r != f"{DST_PREFIX}/{image}"])
        reports.append(report)
        logger.info("Image %s: synced=%s unchanged=%s errors=%s",
                    image, report["synced"], report["unchanged"], report["errors"])

    emit_metrics(reports)
    failures = sum(len(r["errors"]) for r in reports)
    new_versions = sum(len(r["synced"]) for r in reports)
    status = "FAILED" if failures else ("UPDATED" if new_versions else "OK")
    send_notification(reports, status)

    if failures:
        raise RuntimeError(f"{failures} image sync error(s): {json.dumps(reports)}")

    return {
        "statusCode": 200,
        "status": status,
        "new_versions": new_versions,
        "reports": reports,
    }


def send_cloudformation_response(event: dict, context, status: str, physical_resource_id: str,
                                 data: Optional[dict] = None, reason: str = "") -> None:
    """Send the required response for a Lambda-backed CloudFormation custom resource."""
    response = {
        "Status": status,
        "Reason": reason or f"See CloudWatch Logs: {getattr(context, 'log_stream_name', 'unknown')}",
        "PhysicalResourceId": physical_resource_id,
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "NoEcho": False,
        "Data": data or {},
    }
    payload = json.dumps(response).encode("utf-8")
    request = urllib.request.Request(
        event["ResponseURL"],
        data=payload,
        method="PUT",
        headers={"content-type": "", "content-length": str(len(payload))},
    )
    with _opener(event["ResponseURL"]).open(request, timeout=30) as result:
        logger.info("CloudFormation custom-resource response sent: HTTP %s", result.status)


def handler(event, context):  # noqa: ANN001, ANN201
    # The custom resource causes one synchronous initial download after stack
    # creation. Stack updates and deletion only acknowledge CloudFormation;
    # the weekly Scheduler remains responsible for recurring checks.
    if event.get("RequestType") in {"Create", "Update", "Delete"} and event.get("ResponseURL"):
        physical_resource_id = event.get("PhysicalResourceId", "v1cs-initial-sync")
        if event["RequestType"] != "Create":
            send_cloudformation_response(event, context, "SUCCESS", physical_resource_id)
            return {"statusCode": 200, "status": "SKIPPED", "request_type": event["RequestType"]}
        try:
            result = run_sync()
        except Exception as exc:  # CloudFormation needs an explicit FAILED response.
            logger.exception("Initial CloudFormation sync failed")
            send_cloudformation_response(
                event,
                context,
                "FAILED",
                physical_resource_id,
                reason=str(exc)[:1024],
            )
            return {"statusCode": 500, "status": "FAILED", "reason": str(exc)}
        send_cloudformation_response(
            event,
            context,
            "SUCCESS",
            physical_resource_id,
            data={"Status": result["status"], "NewVersions": result["new_versions"]},
        )
        return result

    return run_sync()


if __name__ == "__main__":
    # Local smoke test: python3 v1cs-sync-lambda.py (uses whatever AWS creds are
    # available locally; requires outbound access to public.ecr.aws).
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(handler({}, None), indent=2))
