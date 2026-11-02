import Link from "next/link";
import { Fingerprint } from "lucide-react";

export function MarketingNav() {
  return <nav className="marketing-nav" aria-label="Main">
    <Link className="brand dark" href="/"><span className="brand-mark"><Fingerprint size={16}/></span>AccessProof</Link>
    <div className="marketing-links">
      <Link href="/#product">Product</Link><Link href="/#how">How it works</Link>
      <Link href="/security">Security</Link><Link href="/#pricing">Pricing</Link><Link href="/#faq">FAQ</Link>
    </div>
    <div className="nav-actions">
      <Link className="text-link" href="/login">Sign in</Link>
      <a className="button compact secondary hide-small" href="mailto:admin@accessproof.in?subject=AccessProof%20pilot">Request a pilot</a>
      <Link className="button compact" href="/register">Start free</Link>
    </div>
  </nav>;
}

export function MarketingFooter() {
  return <footer className="marketing-footer">
    <div><Link className="brand dark" href="/"><span className="brand-mark"><Fingerprint size={15}/></span>AccessProof</Link>
      <p>Permission-safe enterprise AI.</p></div>
    <div><b>Product</b><Link href="/#product">Features</Link><Link href="/#how">How it works</Link><Link href="/#pricing">Pricing</Link></div>
    <div><b>Trust</b><Link href="/security">Security</Link><Link href="/#faq">FAQ</Link></div>
    <div><b>Company</b><a href="mailto:admin@accessproof.in">Contact</a><Link href="/login">Sign in</Link></div>
    <small>© {new Date().getFullYear()} NeuralMatrix · AccessProof</small>
  </footer>;
}
