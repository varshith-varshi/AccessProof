"""Reproducible, synthetic-data-only customer onboarding PDF (pilot review).

Requires reportlab and the screenshot fixtures from the current web-v2 browser tests.
Never includes production credentials or employee documents.
"""
from __future__ import annotations

from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image,
    PageBreak, KeepTogether, HRFlowable,
)
from PIL import Image as PILImage

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs/assets/customer-onboarding"
TARGET = ROOT / "docs/AccessProof_Customer_Onboarding_Guide.pdf"
INK = colors.HexColor("#172A3C")
NAVY = colors.HexColor("#102A44")
BLUE = colors.HexColor("#146DA8")
MUTED = colors.HexColor("#526576")
LIGHT = colors.HexColor("#F0F6FC")
AMBER = colors.HexColor("#FFF1D5")
GREEN = colors.HexColor("#E7F6ED")
WHITE = colors.white
PAGE_W, PAGE_H = A4

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="TitleAP", fontName="Helvetica-Bold", fontSize=31, leading=35, textColor=NAVY, spaceAfter=18))
styles.add(ParagraphStyle(name="SubtitleAP", fontName="Helvetica", fontSize=13, leading=20, textColor=MUTED, spaceAfter=16))
styles.add(ParagraphStyle(name="H1AP", fontName="Helvetica-Bold", fontSize=22, leading=28, textColor=NAVY, spaceBefore=5, spaceAfter=15))
styles.add(ParagraphStyle(name="H2AP", fontName="Helvetica-Bold", fontSize=14, leading=19, textColor=BLUE, spaceBefore=14, spaceAfter=7))
styles.add(ParagraphStyle(name="BodyAP", fontName="Helvetica", fontSize=10.5, leading=16.1, textColor=INK, spaceAfter=8))
styles.add(ParagraphStyle(name="SmallAP", fontName="Helvetica", fontSize=9, leading=13.8, textColor=MUTED, spaceAfter=6))
styles.add(ParagraphStyle(name="LabelAP", fontName="Helvetica-Bold", fontSize=8.5, leading=12, textColor=BLUE, spaceAfter=5))
styles.add(ParagraphStyle(name="BoxAP", fontName="Helvetica", fontSize=10, leading=15.5, textColor=INK))
styles.add(ParagraphStyle(name="TableHeadAP", fontName="Helvetica-Bold", fontSize=9, leading=13, textColor=WHITE))
styles.add(ParagraphStyle(name="TableCellAP", fontName="Helvetica", fontSize=9, leading=13, textColor=INK))

doc = SimpleDocTemplate(str(TARGET), pagesize=A4, rightMargin=44, leftMargin=44,
                        topMargin=64, bottomMargin=54, title="AccessProof Customer Onboarding Guide — 2026-11-05",
                        author="NeuralMatrix", subject="Enterprise RAG onboarding — pilot review")
S: list = []

def p(text: str, style="BodyAP"):
    S.append(Paragraph(text, styles[style]))

def h(text: str):
    p(text, "H1AP")

def h2(text: str):
    p(text, "H2AP")

def bullet(text: str):
    p("<font color='#146DA8'><b>•</b></font> &nbsp; " + text)

def note(text: str, background=LIGHT):
    t=Table([[Paragraph(text, styles["BoxAP"])]], colWidths=[PAGE_W-88], hAlign="LEFT")
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),background),
                           ("BOX",(0,0),(-1,-1),.6,colors.HexColor("#C7DCEB")),
                           ("LEFTPADDING",(0,0),(-1,-1),14), ("RIGHTPADDING",(0,0),(-1,-1),14),
                           ("TOPPADDING",(0,0),(-1,-1),12), ("BOTTOMPADDING",(0,0),(-1,-1),12)]))
    S.append(t)
    S.append(Spacer(1,12))

def pic(name: str, *, max_width=500, max_height=280):
    path=ASSETS / name
    assert path.is_file(), f"Missing synthetic screenshot {path}"
    with PILImage.open(path) as i:
        width,height = i.size
    scale=min(max_width/width,max_height/height)
    S.append(Image(str(path), width=width*scale, height=height*scale, hAlign="CENTER"))
    S.append(Spacer(1,9))

def tab(rows, widths):
    arr=[]
    for idx, row in enumerate(rows):
        arr.append([Paragraph(str(item), styles["TableHeadAP"] if idx==0 else styles["TableCellAP"]) for item in row])
    table=Table(arr, colWidths=widths, hAlign="LEFT", repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),NAVY),
                              ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, LIGHT]),
                              ("VALIGN",(0,0),(-1,-1),"TOP"),
                              ("LINEBELOW",(0,-1),(-1,-1),.6,colors.HexColor("#CBDBE5")),
                              ("LEFTPADDING",(0,0),(-1,-1),10), ("RIGHTPADDING",(0,0),(-1,-1),9),
                              ("TOPPADDING",(0,0),(-1,-1),10), ("BOTTOMPADDING",(0,0),(-1,-1),10)]))
    S.append(table)
    S.append(Spacer(1,15))

def nextpage():
    S.append(PageBreak())

def on_page(canvas, document):
    canvas.saveState()
    canvas.setFillColor(NAVY); canvas.rect(0,PAGE_H-25,PAGE_W,25,fill=1,stroke=0)
    canvas.setFillColor(WHITE); canvas.setFont("Helvetica-Bold",8)
    canvas.drawString(44,PAGE_H-17,"ACCESSPROOF  /  NEURALMATRIX")
    canvas.drawRightString(PAGE_W-44,PAGE_H-17,"PILOT REVIEW  •  05 NOV 2026")
    canvas.setStrokeColor(colors.HexColor("#D8E3E9"))
    canvas.line(44,37,PAGE_W-44,37)
    canvas.setFillColor(MUTED); canvas.setFont("Helvetica",8)
    canvas.drawString(44,25,"Customer onboarding • source, Guard, Gateway, route and approval")
    canvas.drawRightString(PAGE_W-44,25,f"{document.page}")
    canvas.restoreState()

# 1. Cover
S.append(Spacer(1,53))
p("NEURALMATRIX  /  ACCESSPROOF", "LabelAP")
p("Customer<br/>Onboarding Guide", "TitleAP")
p("Microsoft 365 + SharePoint  •  Customer-side Guard &amp; Gateway  •  Verified RAG protection", "SubtitleAP")
note("<b>Edition:</b> 05 November 2026. Updated to the current UI, backend permission model, and validated installation contracts. Screenshots use <b>synthetic test data</b>. This guide is issued for <b>pilot review</b>: do not present it as a completed independent customer certification.", GREEN)
S.append(Spacer(1,16))
p("THE EIGHT PHASES", "LabelAP")
tab([
    ["1–2   Authorize", "3–5   Connect", "6–8   Verify"],
    ["Register workspace; consent to the chosen SharePoint site.",
     "Enroll Guard; register RAG; install Gateway on a private host.",
     "Certify the real route; Owner approves; test live employees."],
], [167,167,173])
p("<b>Security principle:</b> No installer receipt, source sync, dashboard label, or chat answer can replace independent permissions evidence and signed route certification. Protect is fail-closed.")
p("<b>What we do not require:</b> a public RAG URL, a Microsoft password pasted into the website, or any NeuralMatrix AWS credentials on a customer host.")
nextpage()

# 2. Preparation
h("Before you begin")
p("Arrange the people and access below before opening the onboarding form. The customer chooses and approves the data boundary.")
tab([
    ["Role", "Responsibility"],
    ["Workspace Owner", "Signs in, registers the AI application, reviews the route certificate, gives final human approval."],
    ["Microsoft 365 / SharePoint admin", "Consents to the tenant application and separately approves an explicit grant to the chosen site."],
    ["RAG / IT owner", "Operates the private host, Docker stack, Guard, Gateway and agreed test route."],
    ["Two test employees", "Use different Microsoft accounts with approved and denied access to a synthetic test document."],
], [142,365])
h2("Preflight checklist")
for item in [
    "Microsoft 365 tenant with provisioned SharePoint Online site and document library.",
    "Verified tenant, site, library, drive and approved root DriveItem IDs. No site picker is available yet.",
    "Private customer-owned Linux RAG host with Docker and a reviewed integration path.",
    "Employee SSO issuer and audience known; no ID-token-for-access-token substitution.",
    "Customer security team has reviewed the potential selected-site elevated permission grant.",
    "A plan for signed, in-flight and post-revocation testing without exposing real documents.",
]: bullet(item)
note("<b>Bounded scope:</b> For early pilots, use one SharePoint site and one selected chatbot. Never silently scan hosts, enable unrelated chatbots, or broaden a Microsoft tenant grant.")
nextpage()

# 3. Phases 1 and 2
h("1  Create your workspace")
for x in ["Open <b>app.accessproof.in/register</b> and create the organization Owner account.",
          "Verify the email address and sign in. Enable MFA before using production data.",
          "Confirm the selected organization and the <b>Owner</b> role in the workspace menu."]:
    bullet(x)
h("2  Connect SharePoint")
p("On <b>Permission sources</b>, choose <b>Microsoft 365 + SharePoint</b>. Enter the customer's verified IDs and approved folder boundary. Consent is initiated from the browser; AccessProof never asks for a Graph bearer token in the form.")
p("<b>Current form (synthetic data, after layout fix)</b>","LabelAP")
pic("sharepoint-form-fixed.png",max_width=498,max_height=220)
note("<b>You're done when:</b> the source reports a valid connection and both directory and ACL synchronization are fresh. Fresh source state is necessary but not sufficient for production Protect.")
nextpage()

# 4. Site consent
h("2  Two independent Microsoft grants")
p("<b>First: tenant admin consent.</b> The administrator approves the configured Entra application permissions. With <b>Sites.Selected</b>, consent alone gives the AccessProof service principal access to <b>zero sites</b>.")
p("<b>Second: selected-site grant.</b> A separately authorized administrator grants the approved AccessProof application access to the named SharePoint site. The grant is not made by AccessProof itself.")
for item in [
    "If the callback says <b>Site grant required</b>, that is a safe, expected intermediate state. Valid consent is retained.",
    "Have the tenant admin issue the reviewed grant to the <b>approved site only</b>.",
    "Return to the same source and click <b>Validate</b>; re-consent is not necessary solely because a site grant was added.",
    "Wait for new employee/group and ACL synchronization. Verify scope, identity and effective permissions before Protect.",
]: bullet(item)
note("<b>Important security review:</b> Our November 2026 production-equivalent certification used the <b>site-scoped fullcontrol</b> role for effective-permission operations. This is elevated access even though it is confined to the selected site. <b>Never imply read-only is already certified, or grant fullcontrol without explicit customer security approval.</b> The app must not silently request tenant-wide Sites.FullControl.All.", AMBER)
p("<b>Operational reminder:</b> A successful consent callback is not a permission certificate. Source health and every application protection gate remain independently enforced.")
nextpage()

# 5. Guard and app
h("3  Enroll the customer Guard")
for item in [
    "Create a Guard and download its official installer from the dashboard.",
    "Run the installer on the customer-controlled host. Enter the one-time enrollment token in its local setup page.",
    "Set the trusted Microsoft OIDC issuer/audience used by the RAG. Verify the Guard can fetch a current signed policy.",
    "Confirm both <b>connected</b> and <b>security ready</b>; heartbeat alone does not prove source permissions or route enforcement.",
]: bullet(item)
h("4  Register exactly one AI application")
for item in [
    "Open AI Applications; register a stable application ID, display name and the supported AccessProof Gateway contract.",
    "Bind the enrolled Guard and the explicitly approved SharePoint source.",
    "Keep the source, tenant and route configuration fixed for certification; later changes invalidate relevant approvals.",
]: bullet(item)
note("<b>You're done when:</b> your customer host Guard has a current policy, the application is bound correctly, and the dashboard does not report missing source/Guard prerequisites.", GREEN)
nextpage()

# 6. Gateway
h("5  Connect the real RAG")
h2("Path A: Supported Docker Compose RAG")
for item in [
    "From Get Started, download the reviewed Gateway connector ZIP and the one-time pairing file.",
    "On the <b>private</b> customer Docker host, run <b>python3 ~/Downloads/accessproof-gateway-connector.zip</b>.",
    "The installer discovers local eligible RAGs without requesting an exposed RAG URL.",
    "Choose <b>one</b> chatbot in the dashboard. Unsupported applications require a separate reviewed integration.",
    "Confirm Gateway pairing, signed routing and local connectivity. Installation does <b>not</b> turn on Protect.",
]: bullet(item)
h2("What the customer selects")
pic("chatbot-picker-fixed.png",max_width=160,max_height=395)
p("Synthetic chatbot picker after the responsive layout correction.","SmallAP")
nextpage()

# 7. SDK
h("5  Alternative RAG framework path")
p("For an existing Python, LangChain or LlamaIndex RAG, a reviewed SDK and Gateway TLS integration can be used. This path is <b>not</b> an automatic conversion and currently requires agreed engineering assistance and route certification.")
for item in [
    "The Python client is kept in <b>integrations/rag-clients/python</b> and was <b>not published on PyPI</b> at this review.",
    "From your signed-in AccessProof workspace, download the reviewed v0.1.0 wheel from /downloads/accessproof_rag-0.1.0-py3-none-any.whl after this release is deployed, and verify its SHA-256 before installing.",
    "Configure Gateway TLS trust, delegated employee access tokens, signed retrieval and trusted document provenance.",
    "Keep private keys, Microsoft tokens, API secrets and customer RAG content out of source code and installer archives; configure them securely on the customer host.",
]: bullet(item)
note("<b>Correct installation command:</b> <font name='Courier'>python3 -m pip install ./accessproof_rag-0.1.0-py3-none-any.whl</font> after authenticated download and checksum verification. <b>SHA-256:</b> <font name='Courier'>ce72587503532202add008990e59fbf2a9c1c23e3740e1a4be3fac4b37235072</font>. Do <b>not</b> use the previous guide's unverified PyPI install command.", AMBER)
h2("Installer distribution checkpoint")
p("Before providing this step to customers, the deployment owner must confirm the <b>/downloads/accessproof-gateway-connector.zip</b> route requires a <b>server-validated AccessProof login session</b>, serves an actual ZIP, and that its SHA-256 matches the reviewed, published release. Merely seeing a redirect to /login without a cookie does not prove that arbitrary invalid cookies are rejected.")
nextpage()

# 8. Verification
h("6  Certify the actual RAG route")
p("Agree on a short, authorized test window. The RAG owner or a temporary approved AccessProof engineer runs the signed challenges on the <b>customer-controlled host</b>.")
for item in [
    "Run nonce-bound Gateway challenges against the real employee-facing route, with independent Guard audit correspondence.",
    "Verify valid source certification, allowed/denied employee access, and that unauthorized chunks never reach the model.",
    "Verify rejection of forged content and routes, fail-closed Guard outages and cache/revocation reuse protections.",
    "Keep test identities ephemeral; restore any synthetic permission changes and revoke temporary host access when finished.",
    "Review the server-authoritative route certificate and all Protect gates. A green installer cannot substitute for these checks.",
]: bullet(item)
note("<b>Not self-service yet:</b> The safe route-certification path still requires agreed access to the actual RAG host and real signed evidence. Do not bypass this requirement or claim automatic certification of arbitrary RAGs.", AMBER)
nextpage()

# 9. Owner approval
h("7  Owner approval and activation")
p("Once every other security gate passes and the current customer-facing route is certified, the signed-in organization <b>Owner</b> opens <b>AI Applications → Check &amp; Enable Protection</b>.")
for item in [
    "Read the active route and source certificate state. Confirm the intended customer deployment.",
    "Type exactly <b>APPROVE PROTECT &lt;application_id&gt;</b> in the Owner approval field.",
    "Click <b>Approve Protect as Owner</b>. This is audited and rejected for Admins, API keys and stale routes.",
    "Click <b>Enable Protection</b>. Wait for Guard acknowledgment and independent <b>PROTECTED_VERIFIED</b> state.",
    "A recertified/changed route requires new human approval. Never force-enable failed gates.",
]: bullet(item)
p("<b>Current Owner approval screen (synthetic data)</b>","LabelAP")
pic("owner-approval-fixed.png",max_width=498,max_height=219)
note("<b>Approval is not activation:</b> Successful approval creates an audited authorization decision, but the customer is not protected until the Guard acknowledges enforcement and all live security checks pass.", GREEN)
nextpage()

# 10. Live tests
h("8  Test in the customer's chatbot")
for item in [
    "Confirm backend state <b>PROTECTED_VERIFIED</b> for the right app, source, Guard and route.",
    "Have employee A sign in through their ordinary Microsoft SSO and ask a question about their approved test document.",
    "Have employee B sign in with a different account and ask about the same restricted document. It must not reach the model or appear in a released answer.",
    "Test a shared document that both can access and review Layer 1/Layer 2 authorization telemetry.",
    "When approved, revoke a test permission and verify denial after revocation, including cache and in-flight requests.",
    "Monitor signed evidence freshness and periodically re-certify when route or permissions change.",
]: bullet(item)
h2("Go-live checklist")
tab([
    ["Must be true", "Evidence"],
    ["Selected-site permission approved", "Admin sign-off; bounded tenant/site scope; grant reviewed"],
    ["Source current", "Connected + fresh directory / ACL snapshot"],
    ["Guard & Gateway live", "Authenticated heartbeat plus signed policy and route binding"],
    ["Security gates passed", "Signed current route + source certificates, no stale/forged evidence"],
    ["Owner approval recorded", "Interactive Owner audit after route certification"],
    ["Protect verified active", "Guard acknowledgment + successful live Alice/Bob tests"],
], [195,312])
nextpage()

# 11. Troubleshooting
h("Troubleshooting &amp; final review")
tab([
    ["What you see", "What to do"],
    ["Site grant required after consent", "Have tenant admin issue reviewed selected-site grant; click Validate on existing source. Consent is retained."],
    ["Source not configured / stale", "Confirm SharePoint provisioning, source IDs, directory/ACL sync, and effective-permission scope."],
    ["Guard connected, not ready", "Check signed policy, source freshness and Guard verification; never convert heartbeat into readiness."],
    ["Gateway paired, route uncertified", "Run approved signed customer RAG route challenge and real cutover evidence."],
    ["Owner approval unavailable", "Only signed-in Owner can approve, and all other gates and route certification must already pass."],
    ["Package not found on PyPI", "Obtain the reviewed wheel from AccessProof technical contact, with SHA-256 verification."],
], [190,317])
h2("Definitions")
for term, definition in [
    ("Source", "The customer's approved SharePoint site, drive and folder boundary."),
    ("Guard", "Customer-side enforcement node applying current policy and independent authorization."),
    ("Gateway", "Signed, customer-side AI traffic boundary used for protected requests."),
    ("Route certification", "Time-scoped security evidence bound to the actual customer RAG route and deployment."),
    ("Owner approval", "Audited human authorization separate from machine verification and Guard activation."),
]:
    p(f"<b>{term}:</b> {definition}","SmallAP")
note("<b>Before distribution:</b> confirm deployment of these UI changes, the production Entra client ID, customer download checksum and that the support mailbox <b>admin@accessproof.in</b> receives external email. All screenshots in this guide use synthetic data; a fresh independent customer tenant walkthrough is still required.", AMBER)

doc.build(S, onFirstPage=on_page, onLaterPages=on_page)
print(f"Updated guide: {TARGET} ({TARGET.stat().st_size:,} bytes)")
