#!/usr/bin/env python3
"""Render the purpose-built SSM Command documents used by the certifier identity.

    python deploy/certifier/build_ssm_documents.py      # writes deploy/certifier/ssm/*.json (commit + review)

They replace ``AWS-RunShellScript`` (unrestricted shell) on production:

* AccessProof-Certifier-ProductionReadOnly: named read-only operations. SQL runs in a
  ``default_transaction_read_only`` session, so the database rejects any write.
* AccessProof-Certifier-ProductionImport: the ONLY write path. Source-certificate
  import, remote-route certificate import, route attestation. Production still
  verifies every signature against the pinned certifier key.
* AccessProof-Certifier-RagHostProbe: the two fixed re-certification probes on the
  staging RAG host.

Every parameter has an ``allowedPattern`` or ``allowedValues`` (enforced by SSM before
anything runs), and every document checks the instance id from IMDSv2 and refuses
to run anywhere but its intended instance. That pins each document to its instance,
which IAM alone cannot express for SendCommand. Embedded code is the repository
code, base64-encoded at render time.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "ssm"
PRODUCTION = "i-0c11427d4d9c1b438"
STAGING = "i-0e6d2256a1e5a6f67"
UUID = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
B64 = r"^[A-Za-z0-9+/=]{0,1000}$"
PAYLOAD_PARTS = 8          # 8 x 1000 base64 chars = 6 KB of JSON max

IMDS_GUARD = r'''set -eu
TOKEN=$(curl -sf -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
SELF=$(curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
[ "$SELF" = "%s" ] || { echo "REFUSED: document pinned to %s (running on $SELF)" >&2; exit 2; }
'''


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def doc(description: str, params: dict, script: str) -> dict:
    return {"schemaVersion": "2.2", "description": description, "parameters": params,
            "mainSteps": [{"action": "aws:runShellScript", "name": "run",
                           "inputs": {"timeoutSeconds": "600", "runCommand": script.splitlines()}}]}


def production_read_only(isc: str) -> dict:
    params = {
        "operation": {"type": "String", "allowedValues": [
            "certificate_status", "identity_bindings", "sync_cursors", "effective_access_allows",
            "guard_revisions", "first_notification", "source_scope", "route_status"]},
        "organizationId": {"type": "String", "default": "00000000-0000-0000-0000-000000000000", "allowedPattern": UUID},
        "sourceId": {"type": "String", "default": "00000000-0000-0000-0000-000000000000", "allowedPattern": UUID},
        "guardId": {"type": "String", "default": "00000000-0000-0000-0000-000000000000", "allowedPattern": UUID},
        "applicationId": {"type": "String", "default": "none", "allowedPattern": r"^[a-z0-9][a-z0-9-]{0,63}$"},
        "resourceName": {"type": "String", "default": "none", "allowedPattern": r"^[A-Za-z0-9_.-]{1,128}$"},
        "sinceEpoch": {"type": "String", "default": "0", "allowedPattern": r"^[0-9]{1,12}$"},
    }
    script = (IMDS_GUARD % (PRODUCTION, PRODUCTION)) + r'''OP='{{ operation }}'; ORG='{{ organizationId }}'; SRC='{{ sourceId }}'; GUARD='{{ guardId }}'
APP='{{ applicationId }}'; RES='{{ resourceName }}'; SINCE='{{ sinceEpoch }}'
cd /home/ubuntu/accessproof
ro() { docker exec accessproof-db-1 psql -U accessproof -d accessproof -qAt -v ON_ERROR_STOP=1 -c "SET default_transaction_read_only = on" -c "$1"; }
case "$OP" in
  certificate_status) ro "select coalesce(extract(epoch from expires_at)::text,'') || '|' || status from source_effective_certifications where organization_id='$ORG' and source_id='$SRC'" ;;
  identity_bindings) ro "select json_agg(json_build_object('employee', s.display_name, 'oidc_subject_oid', m.oidc_subject, 'oid_equals_source_principal', m.oidc_subject = s.provider_subject_id, 'method', m.method, 'status', m.status, 'automatic', m.verified_by_user_id is null, 'account_kind', s.account_kind) order by s.display_name) from guard_identity_mappings m join guard_subjects s on s.id=m.source_subject_id where m.organization_id='$ORG' and s.display_name in ('alice','bob')" ;;
  sync_cursors) ro "select string_agg(sync_kind||':'||status, ',') from provider_sync_cursors where organization_id='$ORG' and source_id='$SRC' and last_error_code is null" ;;
  effective_access_allows) ro "select count(*) from guard_effective_access e join guard_resources r on r.id=e.resource_id join guard_subjects s on s.id=e.subject_id where e.organization_id='$ORG' and e.source_id='$SRC' and s.display_name='alice' and e.decision='allow' and r.metadata_json::json->>'name'='$RES'" ;;
  guard_revisions) ro "select active_authorization_revisions_json from guard_registrations where id='$GUARD'" ;;
  first_notification) ro "select coalesce(min(received_at)::text,'') from provider_event_journal where source_id='$SRC' and provider='microsoft365' and received_at >= to_timestamp($SINCE)" ;;
  source_scope) echo '__ISC__' | base64 -d | docker exec -i -e PYTHONPATH=/app accessproof-api-1 python - scope --organization-id "$ORG" --source-id "$SRC" ;;
  route_status) docker compose -f docker-compose.ec2.yml exec -T api python scripts/remote_route_certificate.py status --organization-id "$ORG" --application-id "$APP" ;;
esac
'''.replace("__ISC__", isc)
    return doc("AccessProof certifier: named READ-ONLY production operations (DB session read-only).", params, script)


def production_import(isc: str) -> dict:
    params = {
        "operation": {"type": "String", "allowedValues": [
            "source_certificate_import", "route_certificate_import", "route_attestation"]},
        "organizationId": {"type": "String", "default": "00000000-0000-0000-0000-000000000000", "allowedPattern": UUID},
        "applicationId": {"type": "String", "default": "none", "allowedPattern": r"^[a-z0-9][a-z0-9-]{0,63}$"},
        **{f"payload{i}": {"type": "String", "default": "", "allowedPattern": B64} for i in range(1, PAYLOAD_PARTS + 1)},
    }
    joined = "".join("{{ payload%d }}" % i for i in range(1, PAYLOAD_PARTS + 1))
    script = (IMDS_GUARD % (PRODUCTION, PRODUCTION)) + r'''OP='{{ operation }}'; ORG='{{ organizationId }}'; APP='{{ applicationId }}'
F=$(mktemp); trap 'rm -f "$F"' EXIT
printf '%s' "__JOINED__" | base64 -d > "$F"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert isinstance(d, dict)' "$F" || { echo "PAYLOAD_NOT_JSON_OBJECT" >&2; exit 3; }
cd /home/ubuntu/accessproof
case "$OP" in
  source_certificate_import)
    docker exec -i accessproof-api-1 sh -c 'cat > /tmp/ap-record.json' < "$F"
    echo '__ISC__' | base64 -d | docker exec -i -e PYTHONPATH=/app accessproof-api-1 python - import --record /tmp/ap-record.json; rc=$?
    docker exec accessproof-api-1 rm -f /tmp/ap-record.json; exit $rc ;;
  route_certificate_import) docker compose -f docker-compose.ec2.yml exec -T api python scripts/remote_route_certificate.py import --organization-id "$ORG" --application-id "$APP" < "$F" ;;
  route_attestation) docker compose -f docker-compose.ec2.yml exec -T api python scripts/remote_route_certificate.py attest --organization-id "$ORG" --application-id "$APP" < "$F" ;;
esac
'''.replace("__ISC__", isc).replace("__JOINED__", joined)
    return doc("AccessProof certifier: the ONLY production write path (certificate imports / route attestation; "
               "production verifies signatures against the pinned certifier key).", params, script)


def rag_host_probe(bypass: str, gw_unsigned: str) -> dict:
    params = {
        "probe": {"type": "String", "allowedValues": ["bypass", "gateway_unsigned"]},
        "targets": {"type": "String", "default": "none:1", "allowedPattern": r"^[A-Za-z0-9.-]{1,64}:[0-9]{1,5}(,[A-Za-z0-9.-]{1,64}:[0-9]{1,5}){0,7}$"},
        "gatewayUrl": {"type": "String", "default": "https://ap-gateway.lab.internal:18443",
                       "allowedPattern": r"^https://[a-z0-9.-]{1,128}:[0-9]{2,5}$"},
    }
    script = (IMDS_GUARD % (STAGING, STAGING)) + r'''PROBE='{{ probe }}'; TARGETS='{{ targets }}'; GW='{{ gatewayUrl }}'
CRED_RE='(OPENAI|ANTHROPIC|AZURE_OPENAI|GEMINI|GOOGLE_API_KEY|COHERE|MISTRAL|GROQ|TOGETHER|HUGGINGFACE|HF_TOKEN|OLLAMA|BEDROCK|VERTEX|LLM_|MODEL_(API|KEY|TOKEN|URL|ENDPOINT|BASE))'
case "$PROBE" in
  bypass) IN=$(python3 -c 'import json,sys;print(json.dumps({"cred_re":sys.argv[1],"targets":[[h,int(p)] for h,p in (t.rsplit(":",1) for t in sys.argv[2].split(","))]}))' "$CRED_RE" "$TARGETS")
          echo "$IN" | python3 -c "$(echo '__BYPASS__' | base64 -d)" ;;
  gateway_unsigned) IN=$(python3 -c 'import json,sys;print(json.dumps({"ca":"/home/ubuntu/ap-remote-rag/ca.pem","gw":sys.argv[1],"paths":["/v1/chat/completions","/v1/snapshots/chat/completions","/v1/cache/authorize","/v1/responses/authorize","/v1/anything"]}))' "$GW")
          echo "$IN" | python3 -c "$(echo '__GWU__' | base64 -d)" ;;
esac
'''.replace("__BYPASS__", bypass).replace("__GWU__", gw_unsigned)
    return doc("AccessProof certifier: fixed re-certification probes on the STAGING RAG host only.", params, script)


def main() -> None:
    spec = importlib.util.spec_from_file_location("rrc_run", ROOT / "scripts/live/remote_route_certification.py")
    src = (ROOT / "scripts/live/remote_route_certification.py").read_text()
    ns: dict = {}
    for name in ("_BYPASS", "_GW_UNSIGNED"):
        start = src.index(f"{name} = r'''") + len(f"{name} = r'''")
        ns[name] = src[start:src.index("'''", start)]
    isc = b64((ROOT / "scripts/issue_source_certificate.py").read_bytes())
    OUT.mkdir(exist_ok=True)
    docs = {"AccessProof-Certifier-ProductionReadOnly": production_read_only(isc),
            "AccessProof-Certifier-ProductionImport": production_import(isc),
            "AccessProof-Certifier-RagHostProbe": rag_host_probe(b64(ns["_BYPASS"].encode()), b64(ns["_GW_UNSIGNED"].encode()))}
    manifest = {}
    for name, d in docs.items():
        raw = json.dumps(d, indent=1).encode()
        (OUT / f"{name}.json").write_bytes(raw)
        manifest[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=1))
    print(json.dumps(manifest, indent=1))
    _ = spec


if __name__ == "__main__":
    main()
