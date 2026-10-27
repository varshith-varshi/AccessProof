"use client";
import {useEffect,useState} from "react";
import {DEFAULT_PRODUCT_NAME} from "@/lib/brand-config";

type Branding={product_name:string};
export default function Brand(){const [name,setName]=useState(DEFAULT_PRODUCT_NAME);useEffect(()=>{fetch("/api/v1/branding",{cache:"no-store"}).then(r=>r.ok?r.json():null).then((b:Branding|null)=>{if(b?.product_name)setName(b.product_name)}).catch(()=>undefined)},[]);return <div className="brand">{name}</div>}
