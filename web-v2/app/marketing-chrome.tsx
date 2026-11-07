import Link from "next/link";
import { Fingerprint, Menu } from "lucide-react";

export function MarketingNav() {
  return <nav className="marketing-nav" aria-label="Main">
    <Link className="brand dark" href="/"><span className="brand-mark"><Fingerprint size={16}/></span>AccessProof</Link>
    <div className="marketing-links">
      <Link href="/#product">Product</Link><Link href="/#how">How it works</Link>
      <Link href="/security">Security</Link><Link href="/#integrations">Integrations</Link><Link href="/#pilot">Pilot</Link>
    </div>
    <details className="marketing-menu">
      <summary role="button" aria-label="Open website navigation"><Menu size={18}/>Menu</summary>
      <div>
        <Link href="/#product">Product</Link><Link href="/#how">How it works</Link>
        <Link href="/security">Security</Link><Link href="/#integrations">Integrations</Link><Link href="/#pilot">Pilot</Link>
        <a href="mailto:admin@accessproof.in?subject=AccessProof%20guided%20pilot">Request a pilot</a><Link href="/login">Sign in</Link><Link href="/register">Create workspace</Link>
      </div>
    </details>
    <div className="nav-actions">
      <Link className="text-link" href="/login">Sign in</Link>
      <Link className="button compact secondary hide-small" href="/register">Create workspace</Link>
      <a className="button compact" href="mailto:admin@accessproof.in?subject=AccessProof%20guided%20pilot">Request a pilot</a>
    </div>
  </nav>;
}

export function MarketingFooter() {
  return <footer className="marketing-footer">
    <div><Link className="brand dark" href="/"><span className="brand-mark"><Fingerprint size={15}/></span>AccessProof</Link>
      <p>Permission-safe enterprise AI.</p></div>
    <div><b>Product</b><Link href="/#product">Features</Link><Link href="/#how">How it works</Link><Link href="/#integrations">Integrations</Link></div>
    <div><b>Trust</b><Link href="/security">Security</Link><Link href="/#faq">FAQ</Link></div>
    <div><b>Company</b><a href="mailto:admin@accessproof.in">Contact</a><Link href="/login">Sign in</Link></div>
    <small>© {new Date().getFullYear()} NeuralMatrix · AccessProof</small>
  </footer>;
}
