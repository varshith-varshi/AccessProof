// Loads rendered answer pages in real Chromium and records every network
// request the page makes without user interaction (zero-click exfiltration).
// Usage: node renderer_probe.cjs <pages.json>  ->  prints JSON results.
const fs = require("fs");
const path = require("path");
const pw = require(path.join(process.env.ACCESSPROOF_NODE_MODULES, "playwright"));

(async () => {
  const pages = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const browser = await pw.chromium.launch({ executablePath: process.env.ACCESSPROOF_CHROMIUM || undefined });
  const results = [];
  for (const item of pages) {
    const context = await browser.newContext();
    const page = await context.newPage();
    const requests = [];
    const dialogs = [];
    page.on("dialog", d => { dialogs.push(d.message()); d.dismiss(); });
    // Every request leaving the document (images, CSS, prefetch, iframes...).
    await context.route("**/*", route => {
      const url = route.request().url();
      if (!url.startsWith("about:") && !url.startsWith("data:")) requests.push(url);
      route.abort();
    });
    let links = [];
    let error = null;
    try {
      await page.setContent(item.html, { waitUntil: "load", timeout: 5000 }).catch(() => {});
      // Hover everything: catches onmouseover-style handlers that need no click.
      const elements = await page.$$("body *").catch(() => []);
      for (const el of elements) { await el.hover({ timeout: 200 }).catch(() => {}); }
      await page.waitForTimeout(150);
      links = await page.$$eval("a[href]", as => as.map(a => a.href)).catch(() => []);
    } catch (cause) {
      // A payload that navigates the page away is itself a finding; keep the
      // requests already recorded instead of aborting the whole probe.
      error = String(cause).slice(0, 200);
    }
    results.push({ name: item.name, mode: item.mode, requests, dialogs, links, error });
    await context.close();
  }
  await browser.close();
  process.stdout.write(JSON.stringify(results));
})().catch(error => { console.error(error); process.exit(2); });
