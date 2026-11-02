# AccessProof r20 EC2 release (SSM)

**Status: prepared and rehearsed, NOT deployed.** The engineering environment had
no valid AWS credentials and no network path to production. See
`docs/ACCESSPROOF_R20_DEPLOYMENT_REPORT.md`.

## What the release changes

| Component | Action |
|---|---|
| DB | Additive migrations `q1a2b3c4d5e6` (certificate signature width) and `r2b3c4d5e6f7` (`gateway_installations`, forced RLS) |
| API | Rebuild (D-01 Ed25519 certificates, D-02 Gateway heartbeat, D-04 crash fix) |
| Worker | Rebuild. Its verification cycle evaluates the activation checklist from `app.py`; production still runs r11 |
| Web | Rebuild ("Gateway live connection" card) |
| db / redis / nginx | **Untouched** |
| Customer Guard / Gateway | Not changed by this deploy (see report) |

## Run it (operator workstation with AWS access to account 102076848988)

```bash
git fetch origin claude/modest-bell-tazupa
```

```bash
git checkout claude/modest-bell-tazupa
```

```bash
bash deploy/ec2-release/ship_via_ssm.sh HEAD
```

The ship script:
1. Verifies the AWS account and that the instance is SSM-online.
2. Builds a `git archive` of the commit and refuses it if it contains secret or archive file types.
3. Uploads it with the scripts to a temporary private SSE-S3 bucket.
4. Has the instance fetch them through 15-minute presigned URLs, so no IAM, security-group or instance changes are needed.
5. Runs `deploy_on_ec2.sh` through `AWS-RunShellScript`.
6. Deletes the bucket.

`deploy_on_ec2.sh` refuses to start unless:
- the checksum matches,
- at least 8 GB of disk is free,
- db, redis and api are healthy, and
- the DB is at `p8c1e2f3a4b5`.

It then:
1. Saves `.env` and the Compose file (0600) to `/home/ubuntu/accessproof-releases/<id>/rollback/`.
2. Takes a `pg_dump` and verifies it with `pg_restore --list`.
3. Builds the images and migrates using the **new API image**. The Compose `migrate` service builds from server source, so it is not used.
4. Recreates api → worker → web with health gates, then runs internal and public checks.
5. On any failure after migration, rolls back automatically.

Manual rollback:

```bash
sudo bash /home/ubuntu/accessproof-releases/<release-id>/rollback_on_ec2.sh <release-id>
```

Run this on the EC2 host (through SSM). It refuses to downgrade if any Ed25519 source certificates exist, because the downgrade would delete them.

## After deployment (manual, separate approvals)

* To enable D-01 certificates later, add
  `ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON: ${ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON:-}`
  to the **server's** api service environment. The server Compose file differs from the
  repo, so the script never overwrites it. Then set the certifier public key in `.env`.
  Until then, Microsoft certification remains false, the same as production today.
* Remove `ACCESSPROOF_SOURCE_CERTIFICATION_HMAC_KEY` from the server `.env` if it is present.
* D-05: decide on a non-superuser database application role so forced RLS is enforced.
