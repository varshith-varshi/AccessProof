"use client";

import {Suspense,useEffect} from "react";
import {useRouter, useSearchParams} from "next/navigation";
import {saveSession} from "@/lib/api";

function OidcCompleteContent(){
  const router=useRouter();
  const params=useSearchParams();
  useEffect(()=>{
    const organizationId=params.get("organization_id");
    if(!organizationId){router.replace("/login?error=oidc");return;}
    saveSession({organizationId});
    router.replace("/overview");
  },[params,router]);
  return <div style={{maxWidth:520,margin:"12vh auto",padding:24}}><h1>Completing sign-in…</h1><p>Your identity has been verified. The platform is opening your organization.</p></div>;
}

export default function OidcComplete(){return <Suspense fallback={<p>Completing sign-in…</p>}><OidcCompleteContent/></Suspense>;}
