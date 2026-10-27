import "./globals.css";
import Shell from "@/components/Shell";
import {DEFAULT_PRODUCT_NAME} from "@/lib/brand-config";
export const metadata = { title: DEFAULT_PRODUCT_NAME, description: "Permission lifecycle regression testing for enterprise AI" };
export default function RootLayout({children}:{children:React.ReactNode}) { return <html lang="en"><body><Shell>{children}</Shell></body></html>; }
