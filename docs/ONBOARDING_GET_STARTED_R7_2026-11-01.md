# AccessProof Get Started sidebar restoration — production r7

Date: November 1, 2026.

## Root cause

The source-built `web-v2` r6 production release restored the three-step `/onboarding` route but omitted the `Get Started` item from the shared sidebar navigation in `web-v2/app/app-shell.tsx`. The page remained available by direct URL but customers couldn't reach it from the sidebar. This was a frontend navigation regression, not a SharePoint/backend issue.

## Fix and release

- Added `Get Started` with the Rocket icon, linking to `/onboarding`, as the first sidebar item.
- Added a Playwright assertion for the sidebar link in the existing onboarding E2E coverage.
- Rebuilt from an exact copy of the r6 production source, changing only `app/app-shell.tsx`; this avoids incidental changes from the dirty working tree.
- Immutable release image: `accessproof/web-v2:onboarding-nav-r7-20261101`.
- Source location on EC2: `/home/ubuntu/accessproof-releases/onboarding-nav-r7-20261101/`.
- Persistent deployment selection: `/home/ubuntu/accessproof/.env` (`ACCESSPROOF_WEB_IMAGE`).
- Previous web image `accessproof/web-v2:onboarding-source-r6-20261101` preserved for rollback.

## Evidence

- TypeScript check and ESLint passed.
- Four desktop/mobile Playwright onboarding tests passed.
- EC2 Next.js production compilation passed and still includes `/onboarding`.
- Built image contains the compiled `Get Started` navigation assets.
- Public API ready: PostgreSQL and Redis OK.
- Public login returns 200; onboarding appropriately redirects unauthenticated visitors to login.
- Live web container r7 and the other production containers report healthy.

SharePoint certification/Protect status was not modified. This release addresses navigation only.

## Rollback

Restore `/home/ubuntu/accessproof-releases/onboarding-nav-r7-20261101/.env.before-r7` to the production environment (without printing secrets), validate Compose, then recreate only the web service using the previous image.
