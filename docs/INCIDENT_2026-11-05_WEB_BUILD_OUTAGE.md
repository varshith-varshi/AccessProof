# Incident: production outage during a web release, 2026-11-05

## Summary

Release command `1f845031-ac05-4044-b89f-96741eb1bd83` built the web image directly on production, a `t3.small` with 2 GB of memory. The instance stopped responding, taking the website, API, SSH and the SSM agent down with it. The command later returned `Failed`, response code 1.

Recovery used an EBS snapshot (`snap-006a1e5576a6df5ac`) and an EC2 stop/start. The stop/start changed the public IP from `13.48.3.158` to `13.49.134.199` because production has no Elastic IP. The server recovered, but public DNS at GoDaddy still pointed to the old address, so the outage continued after the host was healthy.

## Causes

1. A resource-heavy `docker build` ran on the live host. Memory exhaustion is the likely cause; it was not proven, because the host's logs from the hang were not reviewed.
2. The `nice`, `ionice` and timeout wrappers added in `03eae05` were not an effective fix. They wrap the `docker` client, while the build runs under `dockerd`, and they set no memory limit.
3. Production has an automatically assigned public IP, so a stop/start breaks DNS.

## Changes

- `docker build` is removed from the web-only release. `ship_production.sh` builds off-host for `linux/amd64` and carries the image inside the checksummed release artifact, through the deployer's existing private S3 path.
- The host loads the image, checks its digest and architecture, and confirms both customer downloads are present.
- The host refuses before switching if public routes are unreachable, under 300 MB of memory is available, or the previous image is missing.
- An ECR registry would give a true immutable pull, but the deployer has no ECR permissions. The S3 path was used so no IAM change or new cost was needed.

## A separate defect found during this work

Testing the rebuilt image before deployment found that `/downloads%2Faccessproof-gateway-connector.zip` skipped the session gate and served the file with a fabricated cookie. The gate compared the raw path. It now compares the decoded, normalized path, and the release checks this path live.

## Recovery procedure

Do this if production stops responding:

1. Check instance status and SSM. Do not start a second release.
2. Take an EBS snapshot before any stop/start.
3. A stop/start changes the public IP unless an Elastic IP is attached. Read the new IP, then update the `app`, `api` and apex A records at GoDaddy. Route 53 does not host this domain.
4. Verify by IP with `curl --resolve` before changing DNS, using GET on `/health/ready` because it does not accept HEAD.
5. Confirm authoritative answers from `ns75` and `ns76`, then public HTTPS.
6. Check Protect after DNS. Guards and Gateways use public DNS, so they stay degraded until the records are corrected.

## Elastic IP recommendation

Use an Elastic IP. It survives stop/start, so this DNS failure cannot recur.

- **Address change:** an existing auto-assigned IP cannot be converted, so association changes the public address once. `app`, `api` and the apex must move at the same moment.
- **Cost:** a separate charge is unlikely to appear, since AWS bills public IPv4 addresses at about $3.60 a month whether or not they are elastic. It would apply only while the address sits unattached.
- **Other effects:** none expected on nginx, TLS or the security group, which use hostnames and ports. The certificate covers names, not addresses. The 600-second TTL limits the cutover window.
- **Rollback:** an Elastic IP can be disassociated, but the instance then gets a new auto-assigned address, not the current one. Rollback therefore means keeping the Elastic IP and correcting DNS.

## Resolution

DNS for `app`, `api` and the apex was corrected to `13.49.134.199` on 2026-11-05, with authoritative answers confirmed on `ns75` and `ns76`.

The off-host release then deployed without a build on the host:

| Item | Value |
|---|---|
| Release ID | `web-r40-onboarding-f966bcaa6830` |
| Commit | `f966bcaa683077cc450b70edcbb81763d8887363` |
| SSM command | `9e115777-5a73-44de-b591-01e22c40a898` (Success) |
| Artifact SHA-256 | `36f309b6ccf3e6a53e105b5d2aeaa53ff4ac5ac11d4d4b7e0016fc2762f262cb` |
| Image ID on host | `sha256:0a41f8853a0f06ad7df3199f71bc6c81d318462f9b6b5c35de9209aa946de970` |
| Host switch | About 21 seconds from release start to verified, with 1,072 MB of memory available at start |
| Rollback | Not needed |

Afterwards the database stayed at `x8c9d0e1f2a3`, and API, worker, database, Redis and nginx kept their containers. Live installer checks refused no-session, fabricated-session and unknown-token requests, returned no file for 14 bypass paths, and allowed a valid session. Full downloads matched both reviewed checksums.
