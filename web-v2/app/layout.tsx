import "./globals.css";
export const metadata={metadataBase:new URL(process.env.NEXT_PUBLIC_SITE_URL??"http://localhost:3001"),title:"AccessProof · Authorization enforcement for AI",description:"Real-time authorization enforcement for enterprise AI and RAG.",robots:{index:true,follow:true},openGraph:{title:"AccessProof",description:"Real-time authorization enforcement for enterprise AI and RAG.",type:"website"}};
export default function Layout({children}:{children:React.ReactNode}){return <html lang="en"><body>{children}</body></html>}
