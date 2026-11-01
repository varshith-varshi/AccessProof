"""Read-only approved site permission inspection with the existing Graph app token."""
from __future__ import annotations
import json
from pathlib import Path
import httpx

SITE="neuralmatrix093.sharepoint.com,9b00ec42-620a-4efc-acb3-f4d662c8ceb6,20231c9b-3196-4a5e-9ed0-0404090d5930"
CLIENT_APP="b8424d54-5428-4d35-ae2c-639de7e512a9"

def main() -> None:
    folder=Path.home()/".config/accessproof"
    registration=json.loads((folder/"entra-app-registration.json").read_text())
    secret=json.loads((folder/"entra-client-secret.json").read_text())
    with httpx.Client(timeout=12,trust_env=False,follow_redirects=False) as http:
        auth=http.post(
            "https://login.microsoftonline.com/"+registration["home_tenant"]+"/oauth2/v2.0/token",
            data=dict(client_id=registration["client_id"],client_secret=secret["client_secret"],
                      scope="https://graph.microsoft.com/.default",grant_type="client_credentials"),
        )
        print("GRAPH_OAUTH_HTTP",auth.status_code)
        if auth.status_code != 200:
            return
        headers={"Authorization":"Bearer "+auth.json()["access_token"]}
        endpoint="https://graph.microsoft.com/v1.0/sites/"+SITE
        for suffix in ("", "/permissions"):
            response=http.get(endpoint+suffix,headers=headers)
            print("SITE_ENDPOINT",suffix or "/","HTTP",response.status_code)
            if suffix == "/permissions" and response.status_code == 200:
                for row in response.json().get("value",[]):
                    grants=row.get("grantedToIdentitiesV2",[]) or row.get("grantedToIdentities",[])
                    app_ids=[(g.get("application") or {}).get("id") for g in grants]
                    if CLIENT_APP in app_ids:
                        print("CURRENT_APPROVED_APPLICATION_SITE_ROLE",row.get("roles",[]))
                print("TOTAL_SITE_PERMISSION_RECORDS",len(response.json().get("value",[])))

if __name__=="__main__":
    main()
