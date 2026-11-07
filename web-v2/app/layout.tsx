import "./globals.css";
export const metadata={metadataBase:new URL(process.env.NEXT_PUBLIC_SITE_URL??"https://app.accessproof.in"),title:"AccessProof · Authorization enforcement for AI",description:"Source-aware permission enforcement for supported enterprise AI and RAG routes.",robots:{index:true,follow:true},openGraph:{title:"AccessProof",description:"Source-aware permission enforcement for supported enterprise AI and RAG routes.",type:"website"}};
export default function Layout({children}:{children:React.ReactNode}){return <html lang="en"><body>{children}</body></html>}
