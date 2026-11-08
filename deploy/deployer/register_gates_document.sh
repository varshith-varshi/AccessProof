#!/usr/bin/env bash
# AWS OWNER ONLY (one time). Create the read-only production gates document and
# make sure the deployer policy allows it, so the deployer can run gates A-J with
#   deploy/deployer/ship_production.sh --gates <organization-id> <application-id>
#
# Identity: an explicit NON-ROOT administrator profile (default
# accessproof-infra-admin; override with AP_REGISTRAR_PROFILE). The script never
# falls back to the default profile (the account root on the owner laptop),
# refuses root and the deployer, and checks every permission it needs BEFORE it
# changes anything. If the profile lacks a permission, it stops and names it.
# Least-privilege grant for that profile: deploy/deployer/iam-policy-gates-document-registrar.json
set -Eeuo pipefail
REGION=eu-north-1
ACCOUNT=102076848988
NAME=AccessProof-Deployer-ProductionGates
ROLE=accessproof-production-deployer
PROFILE="${AP_REGISTRAR_PROFILE:-accessproof-infra-admin}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ "$PROFILE" != default && -n "$PROFILE" ]] || { echo 'Refusing the default profile (account root)' >&2; exit 2; }
[[ "$PROFILE" != "$ROLE" ]] || { echo 'Refusing the deployer profile' >&2; exit 2; }
# Only the chosen profile: drop any ambient credentials that could override it.
awsr() { env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_DEFAULT_PROFILE \
             AWS_PROFILE="$PROFILE" aws --region "$REGION" "$@"; }

ARN=$(awsr sts get-caller-identity --query Arn --output text 2>/dev/null) || {
  echo "Profile '$PROFILE' has no valid session. Sign in with: aws login --profile $PROFILE" >&2; exit 2; }
[[ "$ARN" == "arn:aws:"*":$ACCOUNT:"* ]] || { echo "Wrong account: $ARN" >&2; exit 2; }
[[ "$ARN" != *":root" ]] || { echo 'Refusing to use the account root' >&2; exit 2; }
[[ "$ARN" != *"$ROLE"* ]] || { echo 'Refusing the deployer identity' >&2; exit 2; }
echo "Registrar identity: $ARN"

python3 "$HERE/build_ssm_documents.py" >/dev/null
DOC="$HERE/ssm/$NAME.json"
POLICY_FILE="$HERE/iam-policy-production-deployer.json"
missing=()

# Read-only permission probes (no changes yet).
if awsr ssm describe-document --name "$NAME" >/dev/null 2>"${TMPDIR:-/tmp}/ap-gates-probe.$$"; then
  EXISTS=1
elif grep -q 'InvalidDocument' "${TMPDIR:-/tmp}/ap-gates-probe.$$"; then
  EXISTS=0
else
  EXISTS=0; missing+=("ssm:DescribeDocument on document/$NAME")
fi
rm -f "${TMPDIR:-/tmp}/ap-gates-probe.$$"
INLINE=$(awsr iam list-role-policies --role-name "$ROLE" --query 'PolicyNames[0]' --output text 2>/dev/null) \
  || { missing+=("iam:ListRolePolicies on role/$ROLE"); INLINE=""; }
POLICY_OK=0
if [[ -n "$INLINE" && "$INLINE" != None ]]; then
  if CURRENT=$(awsr iam get-role-policy --role-name "$ROLE" --policy-name "$INLINE" --query PolicyDocument --output json 2>/dev/null); then
    python3 - "$CURRENT" <<'PY' && POLICY_OK=1 || true
import json, sys
doc = json.loads(sys.argv[1])
ok = any(s.get("Effect") == "Allow" and "ssm:SendCommand" in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])
         and any(str(r).endswith("document/AccessProof-Deployer-ProductionGates")
                 for r in (s["Resource"] if isinstance(s["Resource"], list) else [s["Resource"]]))
         for s in doc["Statement"])
sys.exit(0 if ok else 1)
PY
  else
    missing+=("iam:GetRolePolicy on role/$ROLE")
  fi
elif [[ "$INLINE" == None ]]; then
  echo "No inline policy on $ROLE; attach $POLICY_FILE manually" >&2; exit 2
fi
if (( ${#missing[@]} )); then
  printf 'Profile %s lacks required permission: %s\n' "$PROFILE" "${missing[@]}" >&2
  echo "Grant $HERE/iam-policy-gates-document-registrar.json to this identity (owner decision), then re-run." >&2
  exit 3
fi

if (( EXISTS )); then
  V=$(awsr ssm update-document --name "$NAME" --content "file://$DOC" --document-format JSON \
      --document-version '$LATEST' --query DocumentDescription.DocumentVersion --output text 2>&1) || {
    if grep -q DuplicateDocumentContent <<<"$V"; then echo "$NAME already up to date"; V=""; else echo "$V" >&2; exit 1; fi; }
  [[ -z "$V" ]] || awsr ssm update-document-default-version --name "$NAME" --document-version "$V" >/dev/null
else
  awsr ssm create-document --name "$NAME" --document-type Command --content "file://$DOC" --document-format JSON >/dev/null
  echo "Created $NAME"
fi
if (( POLICY_OK )); then
  echo "Deployer policy already allows $NAME; IAM unchanged."
else
  awsr iam put-role-policy --role-name "$ROLE" --policy-name "$INLINE" --policy-document "file://$POLICY_FILE"
  echo "Deployer policy updated from reviewed $POLICY_FILE"
fi
echo "Done: $ROLE may run $NAME (read-only gates A-J)."
