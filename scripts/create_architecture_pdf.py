from __future__ import annotations

from pathlib import Path
from textwrap import wrap

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output" / "pdf" / "accessproof-complete-technical-architecture.pdf"
OUT.parent.mkdir(parents=True, exist_ok=True)

PAGE_W, PAGE_H = landscape(A4)

NAVY = colors.HexColor("#0B2533")
INK = colors.HexColor("#102B3A")
BLUE = colors.HexColor("#0D6FA4")
TEAL = colors.HexColor("#00A889")
CYAN = colors.HexColor("#5CC8D7")
AMBER = colors.HexColor("#E8A63A")
RED = colors.HexColor("#D55C55")
GREEN = colors.HexColor("#2F9D78")
PURPLE = colors.HexColor("#735DA8")
MUTED = colors.HexColor("#607985")
LINE = colors.HexColor("#C9D7DD")
PALE = colors.HexColor("#F3F7F8")
PALE_BLUE = colors.HexColor("#EAF4F8")
PALE_TEAL = colors.HexColor("#E9F7F3")
PALE_AMBER = colors.HexColor("#FFF4DF")
PALE_RED = colors.HexColor("#FCECEB")
WHITE = colors.white


def pstyle(size=8.2, leading=None, color=INK, align=TA_LEFT, bold=False):
    return ParagraphStyle(
        name=f"s-{size}-{leading}-{color}-{align}-{bold}",
        fontName="Helvetica-Bold" if bold else "Helvetica",
        fontSize=size,
        leading=leading or size * 1.25,
        textColor=color,
        alignment=align,
        spaceAfter=0,
        spaceBefore=0,
    )


def para(c, text, x, y, w, h, *, size=8.2, leading=None, color=INK, align=TA_LEFT, bold=False):
    obj = Paragraph(text, pstyle(size, leading, color, align, bold))
    _, used = obj.wrap(w, h)
    obj.drawOn(c, x, y + h - used)
    return used


def title(c, section, heading, subtitle=None):
    c.setFillColor(NAVY)
    c.rect(0, PAGE_H - 45, PAGE_W, 45, fill=1, stroke=0)
    c.setFillColor(CYAN)
    c.setFont("Helvetica-Bold", 7.5)
    c.drawString(30, PAGE_H - 18, section.upper())
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 17)
    c.drawString(30, PAGE_H - 36, heading)
    if subtitle:
        c.setFillColor(MUTED)
        c.setFont("Helvetica", 8)
        c.drawRightString(PAGE_W - 30, PAGE_H - 33, subtitle)


def footer(c, page_num):
    c.setStrokeColor(LINE)
    c.line(30, 27, PAGE_W - 30, 27)
    c.setFillColor(MUTED)
    c.setFont("Helvetica", 6.8)
    c.drawString(30, 16, "AccessProof technical architecture | Source snapshot 2026-10-26 | f15 @ b3e35a626eee + reviewed working tree")
    c.drawRightString(PAGE_W - 30, 16, str(page_num))


def start_page(c, section, heading, page_num, subtitle=None):
    if page_num > 1:
        c.showPage()
    title(c, section, heading, subtitle)
    footer(c, page_num)


def rounded(c, x, y, w, h, fill=WHITE, stroke=LINE, radius=8, sw=0.8):
    c.setFillColor(fill)
    c.setStrokeColor(stroke)
    c.setLineWidth(sw)
    c.roundRect(x, y, w, h, radius, fill=1, stroke=1)


def box(c, x, y, w, h, heading, body="", *, fill=WHITE, stroke=LINE, accent=BLUE,
        heading_size=9, body_size=7.2, label=None, center=False):
    rounded(c, x, y, w, h, fill, stroke)
    c.setFillColor(accent)
    c.roundRect(x, y + h - 5, w, 5, 4, fill=1, stroke=0)
    if label:
        badge(c, x + 10, y + h - 25, label, accent)
        top = y + h - 31
    else:
        top = y + h - 13
    para(c, heading, x + 9, top - 14, w - 18, 14, size=heading_size, bold=True,
         align=TA_CENTER if center else TA_LEFT)
    if body:
        para(c, body, x + 9, y + 8, w - 18, max(10, top - y - 25), size=body_size,
             color=MUTED, align=TA_CENTER if center else TA_LEFT)


def badge(c, x, y, text, color=BLUE):
    width = stringWidth(text.upper(), "Helvetica-Bold", 6.2) + 13
    c.setFillColor(color)
    c.roundRect(x, y, width, 13, 6, fill=1, stroke=0)
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 6.2)
    c.drawCentredString(x + width / 2, y + 4, text.upper())
    return width


def lane(c, x, y, w, h, heading, *, fill=PALE, edge=LINE):
    rounded(c, x, y, w, h, fill, edge, radius=10)
    c.setFillColor(edge)
    c.roundRect(x, y + h - 24, w, 24, 9, fill=1, stroke=0)
    c.setFillColor(INK)
    c.setFont("Helvetica-Bold", 8)
    c.drawString(x + 10, y + h - 16, heading.upper())


def arrow(c, points, *, color=BLUE, width=1.4, label=None, label_dx=0, label_dy=5, dashed=False):
    c.setStrokeColor(color)
    c.setFillColor(color)
    c.setLineWidth(width)
    if dashed:
        c.setDash(4, 3)
    else:
        c.setDash()
    path = c.beginPath()
    path.moveTo(*points[0])
    for point in points[1:]:
        path.lineTo(*point)
    c.drawPath(path, stroke=1, fill=0)
    c.setDash()
    x1, y1 = points[-2]
    x2, y2 = points[-1]
    if abs(x2 - x1) >= abs(y2 - y1):
        sign = 1 if x2 > x1 else -1
        head = [(x2, y2), (x2 - sign * 7, y2 + 3.5), (x2 - sign * 7, y2 - 3.5)]
    else:
        sign = 1 if y2 > y1 else -1
        head = [(x2, y2), (x2 + 3.5, y2 - sign * 7), (x2 - 3.5, y2 - sign * 7)]
    p = c.beginPath()
    p.moveTo(*head[0]); p.lineTo(*head[1]); p.lineTo(*head[2]); p.close()
    c.drawPath(p, fill=1, stroke=0)
    if label:
        mid = points[len(points) // 2]
        tw = stringWidth(label, "Helvetica-Bold", 6.3) + 8
        c.setFillColor(WHITE)
        c.roundRect(mid[0] - tw / 2 + label_dx, mid[1] + label_dy - 5, tw, 12, 4, fill=1, stroke=0)
        c.setFillColor(color)
        c.setFont("Helvetica-Bold", 6.3)
        c.drawCentredString(mid[0] + label_dx, mid[1] + label_dy - 1, label)


def note(c, x, y, w, h, heading, text, *, color=AMBER):
    rounded(c, x, y, w, h, colors.Color(color.red, color.green, color.blue, alpha=0.09), color, radius=6)
    c.setFillColor(color)
    c.setFont("Helvetica-Bold", 7.5)
    if h <= 34:
        c.drawString(x + 9, y + h / 2 - 2.5, heading)
        heading_width = stringWidth(heading, "Helvetica-Bold", 7.5) + 18
        para(c, text, x + heading_width, y + 3, w - heading_width - 8, h - 6,
             size=6.7, leading=8, color=INK)
    else:
        c.drawString(x + 9, y + h - 14, heading)
        para(c, text, x + 9, y + 7, w - 18, h - 24, size=7, color=INK)


def draw_table(c, data, x, y, w, h, widths=None, font=6.7, header_fill=NAVY):
    rows = []
    for ri, row in enumerate(data):
        rows.append([
            Paragraph(str(cell), pstyle(font, font * 1.22, WHITE if ri == 0 else INK,
                                        bold=ri == 0))
            for cell in row
        ])
    table = Table(rows, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_fill),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.45, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PALE]),
    ]))
    _, used = table.wrap(w, h)
    table.drawOn(c, x, y + h - used)
    return used


def bullets(c, items, x, y, w, h, *, size=7.5, color=INK, dot=TEAL):
    cursor = y + h
    for item in items:
        p = Paragraph(item, pstyle(size, size * 1.3, color))
        _, used = p.wrap(w - 16, cursor - y)
        cursor -= used + 4
        c.setFillColor(dot)
        c.circle(x + 4, cursor + used - size * 0.45, 2.1, fill=1, stroke=0)
        p.drawOn(c, x + 12, cursor)
    return cursor


def cover(c):
    c.setFillColor(NAVY)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    c.setFillColor(TEAL)
    c.circle(PAGE_W - 86, PAGE_H - 83, 110, fill=1, stroke=0)
    c.setFillColor(colors.HexColor("#0F4251"))
    c.circle(PAGE_W - 30, PAGE_H - 40, 72, fill=1, stroke=0)
    c.setFillColor(CYAN)
    c.setFont("Helvetica-Bold", 9)
    c.drawString(55, PAGE_H - 72, "ACCESSPROOF")
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 34)
    c.drawString(55, PAGE_H - 132, "Complete Technical Architecture")
    c.setFillColor(colors.HexColor("#BFD2DA"))
    c.setFont("Helvetica", 14)
    c.drawString(55, PAGE_H - 158, "Real-time authorization enforcement for enterprise AI and RAG")
    c.setStrokeColor(CYAN)
    c.setLineWidth(2)
    c.line(55, PAGE_H - 184, 335, PAGE_H - 184)
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(55, PAGE_H - 222, "Core runtime invariant")
    para(c,
         "Enterprise permissions are synchronized, resolved into effective access, installed as versioned policy at the customer boundary, enforced before generation, and verified again before any answer is released.",
         55, PAGE_H - 322, 540, 82, size=13, leading=18, color=WHITE)
    stages = ["SYNC", "RESOLVE", "ENFORCE", "VERIFY", "AUDIT"]
    x = 55
    for i, stage in enumerate(stages):
        c.setFillColor(TEAL if i in {0, 2, 4} else BLUE)
        c.roundRect(x, 105, 112, 34, 8, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 9)
        c.drawCentredString(x + 56, 117, stage)
        if i < len(stages) - 1:
            arrow(c, [(x + 112, 122), (x + 134, 122)], color=CYAN, width=2)
        x += 134
    c.setFillColor(colors.HexColor("#A9C0C9"))
    c.setFont("Helvetica", 8)
    c.drawString(55, 54, "Source-derived architecture | 2026-10-26 | Repository: /home/white-devil/Downloads/accessproof/f15")
    c.drawRightString(PAGE_W - 55, 54, "Architecture and security pipeline")


def page_legend(c, page):
    start_page(c, "Guide", "How to read this architecture", page, "Audience: engineering, security, product, and customer teams")
    box(c, 34, 365, 240, 140, "Three planes, three responsibilities",
        "<b>Control plane</b>: configuration, identity, permission synchronization, policy generation, evidence, and reporting.<br/><br/><b>Customer enforcement plane</b>: Guard, Gateway/SDK, local policy cache, and answer release control.<br/><br/><b>Provider/model plane</b>: enterprise sources, retrievers, caches, tools, and LLM endpoints.",
        fill=PALE_BLUE, accent=BLUE, body_size=7.5)
    box(c, 292, 365, 240, 140, "Decision vocabulary",
        "<b>ALLOW</b>: at least one current effective grant and no stronger denial.<br/><br/><b>DENY</b>: explicit denial or known absence of access.<br/><br/><b>UNKNOWN</b>: incomplete identity, source, group, policy, revision, or provider evidence. Protect mode blocks UNKNOWN by default.",
        fill=PALE_TEAL, accent=TEAL, body_size=7.5)
    box(c, 550, 365, 258, 140, "Evidence vocabulary",
        "<b>Observed</b>: recorded by AccessProof in a real route or provider flow.<br/><br/><b>Simulated</b>: deterministic local or contract environment.<br/><br/><b>Certified route</b>: exact application + Guard + source + adapter + policy fingerprint passed a bounded challenge. It is never a universal claim.",
        fill=PALE_AMBER, accent=AMBER, body_size=7.5)
    lane(c, 34, 78, 774, 255, "Visual notation", fill=PALE)
    samples = [
        (58, "Hosted service", PALE_BLUE, BLUE, "Runs in AccessProof cloud/control plane"),
        (246, "Customer-side service", PALE_TEAL, TEAL, "Runs at the customer's trust boundary"),
        (434, "External dependency", PALE_AMBER, AMBER, "Identity, source, model, or delivery provider"),
        (622, "Evidence / durable state", PALE_RED, RED, "Persistence, audit, signed report, or local cache"),
    ]
    for x, heading, fill, accent, text in samples:
        box(c, x, 200, 160, 92, heading, text, fill=fill, accent=accent, center=True)
    arrow(c, [(118, 145), (280, 145)], color=BLUE, label="HTTPS / API")
    arrow(c, [(350, 145), (512, 145)], color=TEAL, label="machine-authenticated")
    arrow(c, [(582, 145), (744, 145)], color=AMBER, label="provider/model call", dashed=True)
    c.setFillColor(MUTED); c.setFont("Helvetica", 7)
    c.drawString(58, 105, "Solid arrows: data/control flow   |   Dashed arrows: external or asynchronous dependency   |   Red callouts: fail-closed or evidence boundary")


def page_context(c, page):
    start_page(c, "01 - System context", "Complete product context and trust boundaries", page)
    lane(c, 32, 82, 150, 420, "People and clients", fill=PALE)
    box(c, 48, 382, 118, 78, "Workspace admin", "Configures sources, identities, applications, Guards, protection, and reports.", fill=WHITE, accent=BLUE, center=True)
    box(c, 48, 260, 118, 78, "Employee", "Authenticates to the customer's AI; identity is validated by Guard.", fill=WHITE, accent=PURPLE, center=True)
    box(c, 48, 138, 118, 78, "Security / audit", "Reviews events, blocked requests, route evidence, and signed reports.", fill=WHITE, accent=AMBER, center=True)

    lane(c, 200, 82, 278, 420, "AccessProof hosted control plane", fill=PALE_BLUE, edge=colors.HexColor("#B7D6E5"))
    box(c, 220, 390, 108, 74, "web-v2", "Next.js 16 user interface and server-side API proxy.", fill=WHITE, accent=BLUE, center=True)
    box(c, 350, 390, 108, 74, "FastAPI API", "157 routes for configuration, auth, sync, protection, evidence, and tests.", fill=WHITE, accent=BLUE, center=True)
    box(c, 220, 270, 108, 74, "Worker", "Sync, notifications, email, webhooks, cleanup, retention, and policy events.", fill=WHITE, accent=BLUE, center=True)
    box(c, 350, 270, 108, 74, "Postgres + Redis", "Tenant state, policies, evidence, queues, cursors, and cache/coordination.", fill=WHITE, accent=RED, center=True)
    box(c, 220, 146, 238, 80, "Authorization control plane", "Normalizes provider state, resolves direct/group/org grant paths, produces policies and signed authorization revisions, and verifies Guard evidence.", fill=WHITE, accent=TEAL, center=True)

    lane(c, 496, 82, 312, 420, "Customer and provider boundary", fill=PALE_TEAL, edge=colors.HexColor("#B7E2D7"))
    box(c, 516, 390, 122, 74, "Enterprise sources", "Google Drive; Microsoft 365/SharePoint; connector contracts for other providers.", fill=WHITE, accent=AMBER, center=True)
    box(c, 666, 390, 122, 74, "Enterprise IdP", "OIDC/JWT issuer, JWKS, tenant and stable subject identity.", fill=WHITE, accent=PURPLE, center=True)
    box(c, 516, 270, 122, 74, "AccessProof Guard", "Durable local policy, identity verification, Layer 1 and Layer 2 decisions.", fill=WHITE, accent=TEAL, center=True)
    box(c, 666, 270, 122, 74, "Gateway / RAG SDK", "Integrates retrieval, provenance, buffering, cache reauthorization, and model calls.", fill=WHITE, accent=TEAL, center=True)
    box(c, 516, 146, 122, 74, "Customer RAG", "Retriever, vector store, orchestration, cache, tools, and application route.", fill=WHITE, accent=PURPLE, center=True)
    box(c, 666, 146, 122, 74, "LLM endpoint", "OpenAI-compatible, Azure/OpenAI adapter, or trusted custom adapter.", fill=WHITE, accent=AMBER, center=True)

    arrow(c, [(166, 421), (220, 421)], label="browser")
    arrow(c, [(328, 427), (350, 427)], label="BFF")
    arrow(c, [(404, 390), (404, 344)], label="state")
    arrow(c, [(458, 307), (516, 307)], color=TEAL, label="policy / audit")
    arrow(c, [(576, 390), (576, 344)], color=AMBER, label="ACL + changes", dashed=True)
    arrow(c, [(727, 390), (727, 344)], color=PURPLE, label="JWT/JWKS", dashed=True)
    arrow(c, [(666, 307), (638, 307)], color=TEAL, label="Layer 1/2")
    arrow(c, [(727, 270), (727, 220), (638, 183)], color=TEAL, label="authorized context")
    arrow(c, [(638, 183), (666, 183)], color=AMBER, label="buffered call", dashed=True)
    note(c, 200, 40, 608, 30, "Primary boundary",
         "The hosted control plane never needs direct access to private RAG/model endpoints. Guard and Gateway remain customer-side; only machine-authenticated policy and evidence traffic crosses the boundary.", color=RED)


def page_deployment(c, page):
    start_page(c, "02 - Deployment", "Production deployment topology", page, "Current EC2/Docker Compose shape")
    lane(c, 34, 94, 124, 390, "Public internet", fill=PALE)
    box(c, 50, 352, 92, 76, "Browser", "app.accessproof.in\nHTTPS", fill=WHITE, accent=BLUE, center=True)
    box(c, 50, 230, 92, 76, "API client", "api.accessproof.in\nHTTPS", fill=WHITE, accent=PURPLE, center=True)
    box(c, 50, 108, 92, 76, "Providers", "OAuth callbacks, Google watch, SMTP", fill=WHITE, accent=AMBER, center=True)

    lane(c, 176, 94, 632, 390, "Private Docker network 172.30.0.0/24", fill=PALE_BLUE, edge=colors.HexColor("#B7D6E5"))
    box(c, 196, 354, 106, 76, "nginx", "TLS 1.2/1.3, HSTS, security headers, host routing; only ports 80/443 public.", fill=WHITE, accent=BLUE, center=True)
    box(c, 336, 354, 106, 76, "web-v2", "Pinned release image, read-only filesystem, no-new-privileges, cap-drop ALL.", fill=WHITE, accent=BLUE, center=True)
    box(c, 476, 354, 106, 76, "FastAPI API", "Schema preflight, trusted hosts, CORS, sessions/CSRF, RBAC, tenant context.", fill=WHITE, accent=BLUE, center=True)
    box(c, 616, 354, 106, 76, "Worker", "Cross-tenant system jobs with server-only RLS bypass; never exposed publicly.", fill=WHITE, accent=BLUE, center=True)

    box(c, 240, 220, 112, 76, "PostgreSQL 17", "Durable product state, forced tenant RLS, migrations through k5d3e7a9b214.", fill=WHITE, accent=RED, center=True)
    box(c, 402, 220, 112, 76, "Redis 7", "Append-only persistence; coordination and transient state.", fill=WHITE, accent=RED, center=True)
    box(c, 564, 220, 112, 76, "Migration job", "One-shot Alembic upgrade. API replicas perform schema check only.", fill=WHITE, accent=GREEN, center=True)

    box(c, 240, 112, 112, 70, "SMTP provider", "Verification, reset, invitations, and operational email outbox delivery.", fill=WHITE, accent=AMBER, center=True)
    box(c, 402, 112, 112, 70, "Telemetry", "Prometheus metrics and optional OpenTelemetry exporter.", fill=WHITE, accent=PURPLE, center=True)
    box(c, 564, 112, 112, 70, "Encrypted secrets", "Local AES-GCM or AWS KMS backend; secrets stay outside images and browser responses.", fill=WHITE, accent=PURPLE, center=True)

    arrow(c, [(142, 390), (196, 390)], label="443")
    arrow(c, [(142, 268), (180, 268), (180, 380), (196, 380)], label="443")
    arrow(c, [(302, 392), (336, 392)], label="proxy")
    arrow(c, [(442, 382), (476, 382)], label="/api")
    # API and worker share a clearly routed persistence bus. Downward branches
    # terminate at the exact database boxes rather than crossing through them.
    c.setStrokeColor(RED); c.setLineWidth(1.35)
    c.line(512, 354, 512, 318); c.line(646, 354, 646, 318); c.line(296, 318, 646, 318)
    arrow(c, [(296, 318), (296, 296)], color=RED, label="SQL", label_dx=0, label_dy=4)
    arrow(c, [(458, 318), (458, 296)], color=RED, label="Redis", label_dx=0, label_dy=4)
    # The one-shot migration job reaches PostgreSQL below the data-service row.
    arrow(c, [(620, 220), (620, 204), (296, 204), (296, 220)], color=GREEN, label="migrate")
    # Dashed operational dependencies route through box gaps and around the
    # service row so every endpoint remains visible.
    arrow(c, [(582, 390), (540, 330), (540, 198), (458, 182)], color=PURPLE, label="metrics", dashed=True)
    arrow(c, [(722, 410), (760, 410), (760, 196), (620, 182)], color=PURPLE, label="decrypt", dashed=True)
    arrow(c, [(722, 370), (780, 370), (780, 190), (296, 190), (296, 182)], color=AMBER, label="SMTP", dashed=True)
    note(c, 34, 45, 774, 34, "Deployment invariant",
         "Database migrations are executed once before application restart. API startup refuses a schema mismatch; PostgreSQL/Redis volumes and customer data are preserved across image cutovers.", color=GREEN)


def page_control_plane(c, page):
    start_page(c, "03 - Control plane", "Hosted control-plane component map", page)
    lane(c, 34, 86, 150, 408, "web-v2 surfaces", fill=PALE_BLUE)
    bullets(c, [
        "Dashboard and protection overview",
        "Employees and identity mappings",
        "Permission sources and events",
        "AI applications and integrations",
        "Guards and enrollment",
        "Blocked requests and audit",
        "Reports, diagnostics, settings",
        "Authentication and recovery",
    ], 48, 118, 122, 330, size=7.1)

    lane(c, 202, 86, 380, 408, "FastAPI domain services", fill=PALE)
    cards = [
        (220, 394, "Auth + tenant", "Sessions, CSRF, MFA, OIDC, API keys, invitations, SCIM, RBAC, org membership."),
        (402, 394, "Source control", "OAuth/admin consent, credential rotation, capability discovery, directory/ACL sync."),
        (220, 280, "Authorization", "Normalized events, effective grants, group expansion, policies, signed revisions."),
        (402, 280, "Protection", "AI applications, Guard bindings, readiness, route challenge, Shadow/Protect state."),
        (220, 166, "Evidence", "Guard audit, blocked requests, revocation timeline, signed control-plane reports."),
        (402, 166, "Testing", "Targets, test identities, suites, runs, runners, evidence, releases, comparisons."),
    ]
    for x, y, h, b in cards:
        box(c, x, y, 162, 82, h, b, fill=WHITE, accent=TEAL)

    lane(c, 600, 86, 208, 408, "Worker + persistence", fill=PALE_TEAL)
    box(c, 620, 394, 168, 82, "Background worker", "Provider events, directory/ACL reconciliation, Google watch renewal, Guard event resolution, cleanup, email, webhooks, retention, alerts.", fill=WHITE, accent=BLUE)
    box(c, 620, 280, 168, 82, "PostgreSQL", "65 domain/operational tables grouped across identity, sources, testing, Guard, authorization, evidence, and delivery.", fill=WHITE, accent=RED)
    box(c, 620, 166, 168, 82, "Redis + outboxes", "Transient coordination plus durable database outboxes for email and webhooks; bounded retry state.", fill=WHITE, accent=RED)
    note(c, 620, 106, 168, 42, "Scale boundary", "Current worker is a polling loop; multi-worker coordination should be validated before horizontal expansion.", color=AMBER)

    arrow(c, [(184, 298), (202, 298)], label="same-origin BFF")
    arrow(c, [(582, 321), (620, 435)], color=BLUE, label="jobs")
    arrow(c, [(582, 242), (620, 321)], color=RED, label="SQL")
    arrow(c, [(582, 196), (620, 207)], color=RED)
    c.setFillColor(MUTED); c.setFont("Helvetica", 7)
    c.drawString(220, 118, "API inventory: 157 HTTP routes. Browser APIs are tenant-scoped; Guard/runner machine APIs use dedicated credentials.")


def page_identity(c, page):
    start_page(c, "04 - Identity and tenancy", "Authentication, identity mapping, and tenant isolation", page)
    lane(c, 34, 96, 180, 390, "Human control-plane identity", fill=PALE_BLUE)
    box(c, 52, 370, 144, 78, "Password session", "PBKDF2-SHA256, email verification, reset, secure HttpOnly session cookie, CSRF token.", fill=WHITE, accent=BLUE)
    box(c, 52, 258, 144, 78, "Enterprise OIDC", "Discovery/JWKS, issuer, audience, state/nonce/PKCE, stable identity binding.", fill=WHITE, accent=PURPLE)
    box(c, 52, 146, 144, 78, "Admin automation", "Scoped API keys, SCIM bearer auth, organization roles and permissions.", fill=WHITE, accent=TEAL)

    lane(c, 234, 96, 260, 390, "Tenant enforcement", fill=PALE)
    box(c, 252, 376, 224, 72, "Membership and RBAC", "Every browser/session request resolves a server-side organization membership and required permission.", fill=WHITE, accent=TEAL)
    box(c, 252, 264, 224, 72, "Transaction tenant context", "API sets accessproof.organization_id after membership validation; browser X-Organization-ID alone has no authority.", fill=WHITE, accent=RED)
    box(c, 252, 152, 224, 72, "PostgreSQL forced RLS", "Tenant-scoped tables reject cross-organization rows. Worker-only bypass is restricted to the background process.", fill=WHITE, accent=RED)
    arrow(c, [(364, 376), (364, 336)], color=TEAL, label="authorize")
    arrow(c, [(364, 264), (364, 224)], color=RED, label="SET LOCAL")

    lane(c, 514, 96, 294, 390, "Employee data-plane identity", fill=PALE_TEAL)
    box(c, 532, 376, 258, 72, "Customer IdP token", "Guard validates signature, algorithm, issuer, audience, expiry/not-before, tenant, subject, and JWKS key rotation.", fill=WHITE, accent=PURPLE)
    box(c, 532, 264, 258, 72, "Stable subject mapping", "OIDC issuer + subject + tenant map to the source subject identifier used by provider ACL policy.", fill=WHITE, accent=TEAL)
    box(c, 532, 152, 258, 72, "Application/source binding", "The validated employee can only request the source bound to the AI application and Guard policy.", fill=WHITE, accent=TEAL)
    arrow(c, [(661, 376), (661, 336)], color=PURPLE, label="verify")
    arrow(c, [(661, 264), (661, 224)], color=TEAL, label="bind")
    note(c, 34, 44, 774, 38, "Identity invariant",
         "An email or user_id supplied in JSON is never identity proof. Human control-plane sessions and employee RAG identity are separate trust chains.", color=RED)


def page_source_sync(c, page):
    start_page(c, "05 - Source synchronization", "Provider connection, ingestion, and change processing", page)
    columns = [48, 204, 360, 516, 672]
    heads = [
        ("1. Connect", "Admin OAuth/consent or approved credentials; boundary/root selection; encrypted token storage."),
        ("2. Discover", "Validate tenant/root, capabilities, stable provider IDs, directory, groups, and source boundary."),
        ("3. Snapshot", "Authoritative directory and ACL pages; pagination, Shared Drive context, inherited/direct details."),
        ("4. Normalize", "Subjects, resources, groups, memberships, grants, revisions, and health into provider-neutral records."),
        ("5. Reconcile", "Full and incremental rechecks; stale paths revoked; source health and sync cursors committed."),
    ]
    for i, (h, b) in enumerate(heads):
        box(c, columns[i], 335, 122, 130, h, b, fill=WHITE, accent=[BLUE, PURPLE, AMBER, TEAL, GREEN][i], center=True)
        if i < 4:
            arrow(c, [(columns[i] + 122, 400), (columns[i + 1], 400)], color=BLUE)

    lane(c, 48, 108, 746, 180, "Provider-specific paths and safety controls", fill=PALE)
    box(c, 64, 138, 216, 116, "Google Drive",
        "Drive ACL snapshots, changes.list cursor, changes.watch hints, channel secret/resource/message checks, 3-day renewal, Shared Drive revalidation, directory/group reconciliation, limited-access metadata rejection, shortcut exclusion.", fill=PALE_AMBER, accent=AMBER)
    box(c, 292, 138, 216, 116, "Microsoft 365 / SharePoint",
        "Tenant-bound Graph token endpoint, site/drive/root profile, item permissions, effective-access probe, admin consent state, direct user grant/revoke test path. Protect eligibility remains evidence-gated.", fill=PALE_BLUE, accent=BLUE)
    box(c, 520, 138, 258, 116, "Connector contracts",
        "Confluence, Salesforce, Slack, demo and mock adapters implement validation, capability discovery, controlled synthetic-resource mutation, and cleanup ownership. Availability does not equal live-provider certification.", fill=PALE_TEAL, accent=TEAL)
    note(c, 48, 48, 746, 43, "Change-notification rule",
         "Webhook/watch notifications are bounded hints, not authorization truth. The worker reads authoritative provider state before changing effective access. Incomplete provider evidence becomes UNKNOWN and Protect fails closed.", color=RED)


def page_effective_access(c, page):
    start_page(c, "06 - Authorization", "Effective-access resolution and monotonic state", page)
    lane(c, 34, 88, 174, 404, "Normalized inputs", fill=PALE_BLUE)
    for y, h, b, a in [
        (398, "Subject", "Stable provider identity and active/disabled status", PURPLE),
        (304, "Resource", "Stable source/resource IDs and read scope", AMBER),
        (210, "Group graph", "Direct and nested membership paths", BLUE),
        (116, "Grant paths", "Subject, group, organization; allow/deny; revision", TEAL),
    ]:
        box(c, 52, y, 138, 62, h, b, fill=WHITE, accent=a, center=True)

    lane(c, 226, 88, 360, 404, "Resolver transaction", fill=PALE)
    box(c, 246, 398, 150, 64, "Event gate", "Reject malformed, incomplete, wrong-tenant, stale, replayed, or equal-revision grant resurrection.", fill=WHITE, accent=RED)
    box(c, 416, 398, 150, 64, "Mutation journal", "Apply grant/membership upsert or revoke; persist tombstones for revoke-before-grant.", fill=WHITE, accent=RED)
    box(c, 246, 282, 320, 78, "Compute all effective paths", "Expand current active group memberships; select active grants for subject/group/organization and exact source + resource + scope. Removing one path does not deny while another valid path remains.", fill=WHITE, accent=TEAL, center=True)
    box(c, 246, 164, 92, 70, "ALLOW", "At least one valid allow; no explicit deny.", fill=PALE_TEAL, accent=GREEN, center=True)
    box(c, 360, 164, 92, 70, "DENY", "Explicit deny or complete evidence shows no current access.", fill=PALE_RED, accent=RED, center=True)
    box(c, 474, 164, 92, 70, "UNKNOWN", "Required identity, group, ACL, provider, or snapshot evidence is incomplete.", fill=PALE_AMBER, accent=AMBER, center=True)
    arrow(c, [(396, 430), (416, 430)], color=RED)
    arrow(c, [(406, 398), (406, 360)], color=TEAL)
    arrow(c, [(406, 282), (292, 234)], color=GREEN)
    arrow(c, [(406, 282), (406, 234)], color=RED)
    arrow(c, [(406, 282), (520, 234)], color=AMBER)

    lane(c, 604, 88, 204, 404, "Outputs", fill=PALE_TEAL)
    box(c, 624, 398, 164, 64, "Effective snapshot", "Per subject/source/resource/scope decision plus reason and provider revision.", fill=WHITE, accent=TEAL)
    box(c, 624, 294, 164, 64, "Guard policy", "Monotonic policy version and distribution record for assigned Guards.", fill=WHITE, accent=BLUE)
    box(c, 624, 190, 164, 64, "Authorization revision", "Signed, tenant/application-scoped, hash-chained revision of relevant state.", fill=WHITE, accent=PURPLE)
    box(c, 624, 108, 164, 54, "Audit trail", "Event status, policy link, errors, and timestamps.", fill=WHITE, accent=AMBER)
    arrow(c, [(566, 319), (624, 430)], color=TEAL, label="commit")
    arrow(c, [(706, 398), (706, 358)], color=BLUE)
    arrow(c, [(706, 294), (706, 254)], color=PURPLE)
    arrow(c, [(706, 190), (706, 162)], color=AMBER)
    note(c, 226, 45, 582, 30, "Fail-safe ordering", "Newer revisions win; at equal revision DENY/UNKNOWN dominates ALLOW. A delayed event cannot resurrect revoked access.", color=RED)


def page_policy_distribution(c, page):
    start_page(c, "07 - Policy delivery", "Guard enrollment, policy distribution, and revision acknowledgement", page)
    lane(c, 34, 86, 254, 408, "Control plane", fill=PALE_BLUE)
    box(c, 54, 400, 214, 62, "One-time enrollment", "Admin creates Guard + short-lived enrollment record; credential is returned once and only its hash is retained.", fill=WHITE, accent=BLUE)
    box(c, 54, 306, 214, 62, "Policy + bindings", "Guard-specific effective decisions, application/source/mode bindings, source health, policy version.", fill=WHITE, accent=TEAL)
    box(c, 54, 212, 214, 62, "Signed authorization revisions", "Tenant/application revision number, hash chain, timestamp, current configuration binding.", fill=WHITE, accent=PURPLE)
    box(c, 54, 118, 214, 62, "Evidence ingestion", "Heartbeat, active revisions, Layer 1/2 audit batches, policy acknowledgement, challenge results.", fill=WHITE, accent=AMBER)

    lane(c, 316, 86, 210, 408, "Authenticated channel", fill=PALE)
    box(c, 342, 388, 158, 74, "Exchange", "Enrollment code -> Guard ID + machine credential", fill=WHITE, accent=BLUE, center=True)
    box(c, 342, 278, 158, 74, "Poll / long-poll", "Policy notifications and signed snapshots", fill=WHITE, accent=TEAL, center=True)
    box(c, 342, 168, 158, 74, "Upload", "Heartbeat, revision acknowledgement, audit buffer", fill=WHITE, accent=AMBER, center=True)
    arrow(c, [(421, 388), (421, 352)], color=BLUE)
    arrow(c, [(421, 278), (421, 242)], color=TEAL)

    lane(c, 554, 86, 254, 408, "Customer Guard", fill=PALE_TEAL)
    box(c, 574, 400, 214, 62, "Enrollment UI / CLI", "Local setup page supports token entry and status; state directory stores machine credentials with restricted permissions.", fill=WHITE, accent=BLUE)
    box(c, 574, 306, 214, 62, "Atomic SQLite policy cache", "WAL mode; serialized installs; full snapshot replacement; stale/fork rejection; durable last valid policy.", fill=WHITE, accent=RED)
    box(c, 574, 212, 214, 62, "Application/revision readiness", "Protect requires assigned application, current source health, installed policy, and current revision.", fill=WHITE, accent=PURPLE)
    box(c, 574, 118, 214, 62, "Durable audit buffer", "Decision metadata only; no raw prompts/documents/answers; Protect can fail closed when evidence cannot be retained.", fill=WHITE, accent=AMBER)
    arrow(c, [(268, 431), (342, 425)], label="create")
    arrow(c, [(500, 425), (574, 431)], color=BLUE, label="credential")
    arrow(c, [(268, 337), (342, 315)], color=TEAL, label="policy")
    arrow(c, [(500, 315), (574, 337)], color=TEAL, label="install")
    arrow(c, [(574, 149), (500, 205)], color=AMBER, label="batch")
    arrow(c, [(342, 205), (268, 149)], color=AMBER, label="evidence")
    note(c, 34, 44, 774, 30, "Outage behavior", "Temporary control-plane outage preserves the last valid policy; it does not reset to allow-all. Restart invalidates source-health readiness until a fresh authenticated sync.", color=RED)


def page_guard(c, page):
    start_page(c, "08 - Guard", "Customer-side enforcement data plane", page)
    lane(c, 34, 98, 774, 388, "One protected request", fill=PALE_TEAL, edge=colors.HexColor("#B7E2D7"))
    steps = [
        (48, "1", "Authenticate", "Validate employee JWT or configured trusted identity mode."),
        (166, "2", "Bind", "Resolve stable source subject and exact application/source/mode."),
        (284, "3", "Read policy", "Require fresh source health, active policy, and authorization revision."),
        (402, "4", "Layer 1", "Return only ALLOW resources; classify DENY and UNKNOWN separately."),
        (520, "5", "Context", "Store one-time decision context bound to app, subject, request, source, resources, revision."),
        (638, "6", "Layer 2", "Verify exact trace, current access/revision, and consume context before release."),
    ]
    for x, n, h, b in steps:
        box(c, x, 316, 102, 126, h, b, fill=WHITE, accent=TEAL, label=n, center=True, body_size=6.65)
        if x < 638:
            arrow(c, [(x + 102, 379), (x + 118, 379)], color=TEAL)

    box(c, 48, 172, 170, 94, "Shadow mode", "Returns original retrieved context while recording WOULD_ALLOW / WOULD_BLOCK. It measures impact and does not enforce.", fill=PALE_BLUE, accent=BLUE)
    box(c, 238, 172, 170, 94, "Protect mode", "Removes denied/unknown resources before generation and blocks unsafe output before any byte is released.", fill=PALE_TEAL, accent=GREEN)
    box(c, 428, 172, 170, 94, "Single-use contexts", "Five-minute TTL, request/application/subject/source binding, revision hash, atomic consumption, replay rejection.", fill=PALE_AMBER, accent=AMBER)
    box(c, 618, 172, 170, 94, "Audit metadata", "Layer, result, reason, policy version, resource IDs, revision, timestamps. Raw content is excluded.", fill=PALE_RED, accent=RED)
    note(c, 48, 116, 740, 38, "Guard readiness",
         "Ready only when enrolled, policy is installed, applications are bound, Protect sources are healthy, required revisions exist, and the control-plane sync is fresh.", color=AMBER)
    note(c, 48, 54, 740, 46, "Default failure behavior",
         "Invalid identity, application mismatch, missing mapping, stale source, absent policy/revision, decision-context failure, provenance escape, revoked resource, and audit-buffer exhaustion all prevent a Protect release.", color=RED)


def page_rag_sequence(c, page):
    start_page(c, "09 - Protected RAG", "End-to-end protected answer sequence", page, "Layer 1 before generation; Layer 2 before release")
    lanes = [
        ("Employee / RAG route", 430, PALE_BLUE),
        ("Retriever + trusted ingestion", 342, PALE_AMBER),
        ("AccessProof Guard", 254, PALE_TEAL),
        ("Gateway / SDK", 166, PALE),
        ("Model endpoint", 78, PALE_RED),
    ]
    for name, y, fill in lanes:
        c.setFillColor(fill); c.rect(34, y, 774, 74, fill=1, stroke=0)
        c.setFillColor(INK); c.setFont("Helvetica-Bold", 7.5); c.drawString(42, y + 58, name.upper())
        c.setStrokeColor(LINE); c.line(34, y, 808, y)
    xs = [160, 262, 364, 466, 568, 670, 772]
    events = [
        (xs[0], 467, "1", "Question + employee JWT"),
        (xs[1], 379, "2", "Retrieve candidate chunks"),
        (xs[2], 379, "3", "Verify content attestations"),
        (xs[3], 291, "4", "Layer 1 filter"),
        (xs[4], 203, "5", "Build context from ALLOW only"),
        (xs[5], 115, "6", "Generate and fully buffer"),
        (xs[6], 291, "7", "Layer 2 check, then release"),
    ]
    for x, y, n, txt in events:
        c.setFillColor(NAVY); c.circle(x, y, 12, fill=1, stroke=0)
        c.setFillColor(WHITE); c.setFont("Helvetica-Bold", 7); c.drawCentredString(x, y - 2.5, n)
        para(c, txt, x - 43, y - 42, 86, 36, size=6.4, align=TA_CENTER, bold=True)
    arrow(c, [(xs[0], 455), (xs[0], 416), (xs[1], 391)], color=BLUE)
    arrow(c, [(xs[1] + 12, 379), (xs[2] - 12, 379)], color=AMBER)
    arrow(c, [(xs[2], 367), (xs[2], 326), (xs[3], 303)], color=TEAL)
    arrow(c, [(xs[3], 279), (xs[3], 235), (xs[4], 215)], color=TEAL)
    arrow(c, [(xs[4], 191), (xs[4], 150), (xs[5], 127)], color=AMBER)
    arrow(c, [(xs[5] + 12, 115), (xs[6], 115), (xs[6], 279)], color=RED)
    arrow(c, [(xs[6], 303), (xs[6], 418), (xs[0] + 15, 455)], color=GREEN, label="ALLOW response")
    c.setStrokeColor(RED); c.setLineWidth(1.4); c.setDash(4,3)
    c.line(364, 330, 364, 90); c.line(466, 280, 466, 90); c.line(772, 278, 772, 90)
    c.setDash()
    badge(c, 323, 55, "block before model", RED)
    badge(c, 425, 55, "deny/unknown", RED)
    badge(c, 722, 55, "block before release", RED)
    c.setFillColor(MUTED); c.setFont("Helvetica", 6.8)
    c.drawRightString(808, 35, "Streaming is intentionally rejected on the certified route because released bytes cannot be retracted.")


def page_integrations(c, page):
    start_page(c, "10 - RAG integrations", "Supported integration patterns and trust contracts", page)
    box(c, 34, 334, 236, 150, "A. Framework-neutral Python SDK",
        "ProtectedRAG + GuardClient coordinate attestation verification, Layer 1 filtering, bounded generation, exact source trace, Layer 2 release, signed-cache verification, and reasoned blocked responses.", fill=PALE_TEAL, accent=TEAL)
    box(c, 302, 334, 236, 150, "B. TypeScript SDK",
        "Mirrors the Python contract with WebCrypto Ed25519 verification, ProtectedRAG lifecycle, provenance level, and certification eligibility. Customer code owns the retrieval hook and response release boundary.", fill=PALE_BLUE, accent=BLUE)
    box(c, 570, 334, 238, 150, "C. RAG Security Gateway",
        "Customer-side HTTP service for the documented attested retrieval-manifest route. It calls Guard, constructs model context from authorized bytes, buffers the model response, and verifies output before return.", fill=PALE_AMBER, accent=AMBER)

    lane(c, 34, 92, 774, 206, "Adapters and supporting paths", fill=PALE)
    items = [
        (52, "LangChain", "Normalizes trusted document metadata and passes only authorized originals."),
        (198, "LlamaIndex", "Maps node/document metadata to the stable contract; enforces protected generation."),
        (344, "Haystack", "Uses the same retrieved-resource contract and buffered release lifecycle."),
        (490, "Authorization-first retrieval", "Guard returns explicit scope; pgvector backend applies subject/source/resource predicate before ANN."),
        (636, "Signed caches", "Answer dependency manifest + source attestations + optional revision binding are reauthorized on every hit."),
    ]
    for x, h, b in items:
        box(c, x, 132, 128, 126, h, b, fill=WHITE, accent=PURPLE, center=True, body_size=6.7)
    note(c, 34, 45, 774, 32, "Integration boundary",
         "Opaque RAGs, hidden tools/retrieval, unsigned metadata, uninstrumented cache reads, native streaming, and undisclosed response paths are outside Protect coverage until separately integrated and verified.", color=RED)


def page_gateway(c, page):
    start_page(c, "11 - Gateway", "RAG Security Gateway internals", page)
    lane(c, 34, 82, 774, 410, "Certified reference route: POST /v1/chat/completions", fill=PALE_AMBER, edge=colors.HexColor("#F1D8A7"))
    stages = [
        (54, 382, "Request boundary", "Body-size cap; extra fields forbidden; application binding; employee conversation is user-only; stream=false."),
        (206, 382, "Attestation boundary", "Pinned public keys verify tenant, app, source, resource, chunk, revision, digest, issue/expiry."),
        (358, 382, "Guard Layer 1", "Employee token forwarded only to local Guard; denied/unknown bytes never enter model context."),
        (510, 382, "Model adapter", "OpenAI-compatible/native adapter or explicit trusted custom adapter; redirects off; trust_env off."),
        (662, 382, "Guard Layer 2", "Buffered output; exact generated source trace; revision/access recheck; one-time context consume."),
    ]
    for i, (x, y, h, b) in enumerate(stages):
        box(c, x, y, 126, 82, h, b, fill=WHITE, accent=[BLUE, PURPLE, TEAL, AMBER, GREEN][i], center=True, body_size=6.15)
        if i < len(stages)-1:
            arrow(c, [(x+126, y+41), (stages[i+1][0], y+41)], color=TEAL)

    box(c, 54, 232, 224, 104, "Model-context construction",
        "System instruction establishes the security contract. Attested enterprise content and employee conversation are inserted as untrusted user data, preventing document text from elevating itself to a privileged instruction.", fill=WHITE, accent=PURPLE)
    box(c, 308, 232, 224, 104, "Response resource safety",
        "Upstream response is consumed incrementally into a bounded buffer; oversized or malformed provider responses fail. The response is not streamed to the employee while authorization is pending.", fill=WHITE, accent=RED)
    box(c, 562, 232, 226, 104, "Protected cache route",
        "POST /v1/cache/authorize verifies signed answer manifest, every dependency attestation, tenant/application, optional authorization revision, Guard access, and cache producer identity before return.", fill=WHITE, accent=TEAL)

    box(c, 54, 116, 224, 76, "Health routes", "/health/live and /health/ready expose process and dependency readiness without customer content.", fill=PALE_BLUE, accent=BLUE)
    box(c, 308, 116, 224, 76, "Supported providers", "OpenAI-compatible and configured model adapters. Custom protocol code must be installed locally and explicitly trusted.", fill=PALE_AMBER, accent=AMBER)
    box(c, 562, 116, 226, 76, "Hard failure", "Guard, attestation, model, payload, provenance, cache binding, revision, or output-check failure returns no model answer.", fill=PALE_RED, accent=RED)
    note(c, 54, 54, 734, 42, "What this gateway does not claim", "It cannot discover arbitrary hidden retrievers, tools, caches, agents, background jobs, or model calls. Only the configured and challenged route is covered.", color=RED)


def page_runner(c, page):
    start_page(c, "12 - Verification engine", "Synthetic test runner and permission-regression lifecycle", page)
    lane(c, 34, 92, 152, 392, "Control plane", fill=PALE_BLUE)
    box(c, 52, 382, 116, 70, "Queue run", "Project, suite, source, target, allowed identity, denied control, SLO.", fill=WHITE, accent=BLUE, center=True)
    box(c, 52, 270, 116, 70, "Job lease", "Runner capability/version matching and authenticated lease.", fill=WHITE, accent=BLUE, center=True)
    box(c, 52, 158, 116, 70, "Persist evidence", "Transitions, checkpoints, probes, outcomes, reports.", fill=WHITE, accent=RED, center=True)

    lane(c, 204, 92, 352, 392, "Private runner execution", fill=PALE_TEAL)
    flow = [
        (224, 394, "Validate connections", "Build source/target adapters; validate identity and capabilities."),
        (382, 394, "Provision canary", "Create a uniquely marked synthetic resource inside the approved test boundary."),
        (224, 278, "Positive/negative controls", "Allowed user must retrieve; denied control must not retrieve."),
        (382, 278, "Revoke and poll", "Mutate source authorization, observe source truth, probe AI repeatedly."),
        (224, 162, "Stable denial", "Require configured consecutive clean observations and calculate latency/window."),
        (382, 162, "Cleanup", "Delete only runner-tracked synthetic resources; journal failures for retry."),
    ]
    for x,y,h,b in flow:
        box(c, x, y, 150, 72, h, b, fill=WHITE, accent=TEAL, body_size=6.6)
    arrow(c, [(374, 430), (382, 430)], color=TEAL)
    arrow(c, [(457, 394), (457, 350), (299, 350)], color=TEAL)
    arrow(c, [(374, 314), (382, 314)], color=TEAL)
    arrow(c, [(457, 278), (457, 238), (299, 238)], color=TEAL)
    arrow(c, [(374, 198), (382, 198)], color=TEAL)

    lane(c, 574, 92, 234, 392, "External test systems", fill=PALE_AMBER)
    box(c, 594, 382, 194, 70, "Permission source", "Controlled provider root/sandbox; create/grant/revoke/ground-truth/delete.", fill=WHITE, accent=AMBER)
    box(c, 594, 270, 194, 70, "Customer AI target", "Cloud HTTPS or runner-private target; real identity token templates and response mappings.", fill=WHITE, accent=PURPLE)
    box(c, 594, 158, 194, 70, "Outcome engine", "PASS, FAIL, INCONCLUSIVE, PRECONDITION_FAILURE, ERROR, CANCELED with explicit reason.", fill=WHITE, accent=GREEN)
    arrow(c, [(168, 305), (224, 430)], color=BLUE, label="lease")
    arrow(c, [(556, 430), (594, 417)], color=AMBER, label="mutate")
    arrow(c, [(556, 314), (594, 305)], color=PURPLE, label="probe")
    arrow(c, [(556, 198), (594, 193)], color=GREEN, label="result")
    arrow(c, [(594, 193), (540, 120), (168, 193)], color=RED, label="complete")
    note(c, 34, 47, 774, 31, "Separation", "The Guard enforces production RAG requests. The runner is a separate verification engine used to measure real revocation behavior and generate evidence.", color=BLUE)


def page_evidence(c, page):
    start_page(c, "13 - Evidence", "Audit, reports, route certification, and telemetry", page)
    lane(c, 34, 88, 240, 404, "Evidence producers", fill=PALE_BLUE)
    box(c, 54, 392, 200, 64, "Provider and sync", "Permission mutation/observation, ACL commit, directory/ACL freshness, event lag.", fill=WHITE, accent=AMBER)
    box(c, 54, 296, 200, 64, "Guard", "Layer 1/2 decision metadata, reason, policy version, application, revision and resource IDs.", fill=WHITE, accent=TEAL)
    box(c, 54, 200, 200, 64, "Runner", "State transitions, probes, canary hashes, stable denial, exposure window, outcome.", fill=WHITE, accent=PURPLE)
    box(c, 54, 112, 200, 56, "Control plane", "Configuration, mode changes, route challenge, retention and deletion receipts.", fill=WHITE, accent=BLUE)

    lane(c, 294, 88, 250, 404, "Evidence processing", fill=PALE)
    box(c, 314, 388, 210, 72, "Six-timestamp revocation timeline", "Provider mutation -> observation -> ACL commit -> revision -> Guard apply -> first verified denial. Missing values remain NOT_OBSERVED.", fill=WHITE, accent=RED)
    box(c, 314, 278, 210, 72, "Reference-route certificate", "Exact org + app + Guard + source + adapter + contract + policy fingerprint; nonce challenge; 24-hour expiry.", fill=WHITE, accent=TEAL)
    box(c, 314, 168, 210, 72, "Signed reports", "Ed25519-signed canonical envelope with key ID, SHA-256, evidence levels, expiration, scope and limitations.", fill=WHITE, accent=PURPLE)
    box(c, 314, 104, 210, 42, "Retention", "Policy-driven purge and deletion receipts.", fill=WHITE, accent=AMBER)

    lane(c, 564, 88, 244, 404, "Consumers", fill=PALE_TEAL)
    box(c, 584, 392, 204, 64, "web-v2", "Protection overview, blocked requests, activity, audit, reports, diagnostics.", fill=WHITE, accent=BLUE)
    box(c, 584, 296, 204, 64, "Prometheus", "Bounded-label source freshness, event lag, certificate age, coverage, revision lag, decisions, blocks, cache reauth, revocation latency.", fill=WHITE, accent=GREEN)
    box(c, 584, 200, 204, 64, "CI / exports", "SARIF, JSON, HTML, PDF, JUnit, release comparison, signed report download and verification.", fill=WHITE, accent=PURPLE)
    box(c, 584, 112, 204, 56, "Security team", "Evidence-backed claim with explicit limits; independent certification remains false unless separately obtained.", fill=WHITE, accent=RED)
    arrow(c, [(254, 300), (314, 424)], color=RED, label="events")
    arrow(c, [(524, 314), (584, 328)], color=TEAL, label="status")
    arrow(c, [(524, 204), (584, 232)], color=PURPLE, label="report")
    note(c, 34, 44, 774, 30, "Evidence minimization", "Raw customer prompts, source documents, and model answers are not stored in Guard audit records; evidence favors identifiers, hashes, reasons, revisions, and timestamps.", color=GREEN)


def page_data(c, page):
    start_page(c, "14 - Data architecture", "Persistent data model by bounded context", page, "65 SQLAlchemy models; PostgreSQL in production")
    groups = [
        ("Identity and tenant", BLUE, ["users", "organizations", "memberships", "invitations", "sessions", "one_time_tokens", "mfa_methods", "api_keys", "oidc_configurations", "oidc_login_states", "oidc_identities", "scim_configurations", "scim_identities", "scim_groups", "scim_group_members"]),
        ("Sources and synchronization", AMBER, ["source_connections", "source_effective_certifications", "provider_sync_cursors", "provider_event_subscriptions", "provider_event_journal", "google_source_oauth_states", "microsoft_consent_states"]),
        ("Testing and evidence", PURPLE, ["projects", "ai_targets", "test_identities", "test_suites", "releases", "test_runs", "run_state_transitions", "evidence_items", "synthetic_resources", "reports", "runners", "runner_registrations", "runner_checkpoints", "mutation_journal", "cleanup_tasks"]),
        ("Guard and effective access", TEAL, ["guard_subjects", "guard_identity_mappings", "guard_resources", "guard_permission_events", "guard_groups", "guard_group_memberships", "guard_permission_grants", "guard_permission_snapshots", "guard_effective_access", "guard_policies", "guard_policy_sequences", "guard_policy_distributions"]),
        ("Protection and revisions", GREEN, ["guard_registrations", "guard_enrollments", "ai_applications", "protection_activation_runs", "rag_route_challenges", "guard_protection_decisions", "guard_audit_events", "authorization_revision_sequences", "authorization_revisions", "control_plane_reports"]),
        ("Operations and delivery", RED, ["audit_events", "alert_records", "retention_policies", "deletion_receipts", "email_outbox", "webhook_endpoints", "webhook_deliveries", "entitlements", "usage_records"]),
    ]
    x_positions = [34, 294, 554]
    y_positions = [294, 74]
    for i, (heading, accent, names) in enumerate(groups):
        x = x_positions[i % 3]; y = y_positions[i // 3]
        box(c, x, y, 240, 190, heading, "", fill=PALE, accent=accent)
        text = "<font name='Courier'>" + "<br/>".join(names) + "</font>"
        para(c, text, x + 10, y + 10, 220, 150, size=6.3, leading=8, color=INK)
    note(c, 34, 37, 760, 30, "RLS boundary", "Tenant RLS protects project/run/evidence/report and signed authorization evidence tables; application checks still enforce membership and RBAC.", color=RED)


def page_security(c, page):
    start_page(c, "15 - Security", "Security controls mapped to threat boundaries", page)
    data = [
        ["Threat", "Primary control", "Failure / evidence behavior"],
        ["Forged employee identity", "Guard validates OIDC/JWT signature, algorithm, issuer, audience, time, tenant, and stable subject mapping.", "401/403; no policy lookup under caller-supplied email."],
        ["Cross-tenant access", "Server-side membership/RBAC + transaction tenant context + forced PostgreSQL RLS.", "Request denied; no cross-tenant metadata returned."],
        ["Stale or reordered permission events", "Monotonic provider revisions, revoke tombstones, deny/unknown tie precedence, signed revision hash chain.", "Stale/fork rejected; prior access is not resurrected."],
        ["Prompt/document instruction injection", "Gateway treats employee and document text as untrusted user data; trusted system instruction is operator-controlled.", "Instruction text cannot grant authorization or elevate message role."],
        ["Resource-ID/content swap", "Independent Ed25519 content attestation binds tenant/app/source/resource/chunk/revision/exact digest.", "Blocks before model generation."],
        ["Layer 1 bypass / untrusted provenance", "One-time decision context binds request, app, subject, source, resources, and revision; exact trace checked at Layer 2.", "No answer is released."],
        ["Stale cache answer", "Signed dependency manifest, every source attestation, Guard reauthorization, optional authorization revision binding.", "Cache hit blocks or regenerates."],
        ["Secret leakage", "Encrypted provider credentials; token hashes; machine secrets absent from URLs; browser responses omit raw credentials.", "Rotation and audit paths; secrets excluded from normal logs."],
        ["SSRF / arbitrary upstream", "HTTPS/private-target separation; trusted endpoints; no redirects; gateway trust_env=false; tenant-bound OAuth token endpoints.", "Connection rejected before token/content forwarding."],
        ["Evidence loss", "Durable Guard audit buffer and database outboxes; bounded retries and operational alerts.", "Protect may fail closed when required evidence cannot be retained."],
    ]
    draw_table(c, data, 34, 52, 774, 438, widths=[142, 392, 240], font=6.5)


def page_failures(c, page):
    start_page(c, "16 - Failure semantics", "Decision and release behavior under degraded conditions", page)
    data = [
        ["Condition", "Shadow", "Protect", "Why"],
        ["Known ALLOW, current policy/revision", "WOULD_ALLOW", "ALLOW", "All required evidence exists."],
        ["Known DENY", "WOULD_BLOCK; context preserved for observation", "BLOCK; denied context removed", "Authorization is explicit."],
        ["UNKNOWN / incomplete provider state", "WOULD_BLOCK/UNKNOWN telemetry", "BLOCK", "Unknown cannot silently become allow."],
        ["Guard unavailable", "Integration reports error", "BLOCK / 503", "No trusted decision boundary."],
        ["Control plane temporarily unavailable", "Guard uses last valid policy", "Guard uses last valid policy if still locally ready", "Policy cache is durable; no empty allow-all recovery."],
        ["Source ACL health stale after restart", "Observed as not ready", "BLOCK", "Fresh authenticated sync is required."],
        ["Authorization revision missing or changed", "Would-block evidence", "BLOCK", "Request context no longer matches current authority."],
        ["Attestation missing, expired, wrong key, or content changed", "Not certification-eligible", "BLOCK before model", "Resource metadata alone does not prove bytes."],
        ["Model timeout/error/oversize/malformed output", "ERROR", "No response released", "Gateway response remains buffered and bounded."],
        ["Provenance missing/escape or access revoked during generation", "WOULD_BLOCK", "BLOCK before release", "Layer 2 rechecks exact generated trace."],
        ["Audit buffer full", "Telemetry degradation", "BLOCK when evidence is required", "Protected decisions must remain auditable."],
    ]
    draw_table(c, data, 34, 76, 774, 410, widths=[205, 150, 150, 269], font=6.6)
    note(c, 34, 44, 774, 32, "Configured exception", "Fail-open behavior, where supported, must be an explicit application policy choice; the production security posture is fail-closed.", color=RED)


def page_api(c, page):
    start_page(c, "17 - Interfaces", "HTTP, machine, SDK, and operator interface catalog", page)
    groups = [
        ("Browser/control-plane APIs", "157 FastAPI routes", "Auth/session/MFA/OIDC/SCIM; organization/RBAC; sources/employees; applications/protection; Guards; events; reports; testing; webhooks; audit; entitlements."),
        ("web-v2 BFF", "/api/v1/*", "Same-origin Next.js proxy; forbids path traversal/non-v1 routes, strips hop-by-hop headers, preserves Set-Cookie, injects organization cookie, and forwards CSRF-protected mutations."),
        ("Guard setup", "GET /setup, /setup/status; POST /setup/enroll", "Local browser enrollment for customer operators plus CLI packaging."),
        ("Guard runtime", "GET /health; POST authorization-scope, filter-resources, check-output", "Customer-local identity verification, authorization-first scope, Layer 1 resource filtering, Layer 2 output verification."),
        ("Gateway runtime", "GET /health/live, /health/ready; POST /v1/chat/completions, /v1/cache/authorize", "Attested protected route, bounded non-streaming model completion, and protected cache-hit release."),
        ("Runner machine API", "exchange, heartbeat, lease, checkpoint, cancel-status, complete", "Dedicated bearer credential; persists deterministic lifecycle and evidence without placing runner secrets in URLs."),
        ("Python SDK", "packages.rag_sdk", "ProtectedRAG, GuardClient, framework adapters, content attestation, ingestion, authorization-first retrieval, pgvector backend, signed cache manifests/connectors."),
        ("TypeScript SDK", "packages/rag-sdk-typescript", "ProtectedRAG and Ed25519 attestation contract for Node/browser-server integrations; employee tokens stay at the customer boundary."),
    ]
    for i, (h, label, body) in enumerate(groups):
        col = i % 2; row = i // 2
        x = 34 + col * 390; y = 386 - row * 106
        box(c, x, y, 374, 88, h, f"<b>{label}</b><br/>{body}", fill=WHITE,
            accent=[BLUE, BLUE, TEAL, TEAL, AMBER, PURPLE, GREEN, GREEN][i])
    c.setFillColor(MUTED); c.setFont("Helvetica", 6.8)
    c.drawString(34, 42, "Machine endpoints use dedicated credentials and do not inherit browser trust. All production interfaces remain versioned or explicitly bounded by contract.")


def page_routes(c, page):
    start_page(c, "18 - API domains", "Control-plane route inventory and authorization surfaces", page)
    data = [
        ["Domain", "Routes", "Representative responsibilities"],
        ["Current product surfaces", "33", "Dashboard, applications, protection readiness/status/challenge, adapters, sources, employees, reports, capabilities, revisions, timeline."],
        ["Authentication", "23", "Signup/login/logout, verification, recovery, sessions, MFA, OIDC configuration/begin/callback, invitation acceptance."],
        ["Guards", "14", "Create/list/download/revoke, enrollment/exchange/heartbeat, policies/notifications/ack, challenge evidence."],
        ["Runners", "14", "Registration, exchange, heartbeat, list/admin, lease, checkpoint, cancel status, completion."],
        ["Organization", "10", "Members/roles, invitations, mutation gate, retention, purge, organization deletion."],
        ["Sources", "7 + current flows", "Create/list/validate/capabilities/rotate/reauthorize/disconnect plus Google OAuth and Microsoft admin consent."],
        ["SCIM Users + Groups", "10", "RFC-style discovery, user and group CRUD/patch with tenant-scoped SCIM configuration."],
        ["Test identities, suites, targets, runs, releases", "20", "Synthetic identity/credential lifecycle, suites, target registration, run history/detail/cancel, release comparison."],
        ["Reports", "6 + current signed", "SARIF, JSON, HTML, PDF, JUnit, integrity, signed control-plane report create/list/get/verify/download."],
        ["Projects, API keys, webhooks, audit, entitlements", "13", "Project lifecycle, scoped automation credentials, signed webhook endpoints, audit read, plan usage."],
        ["Health, branding, metrics, provider events", "7", "Liveness/readiness, public branding, Prometheus scrape, normalized permission/provider notification intake."],
    ]
    draw_table(c, data, 34, 62, 774, 424, widths=[180, 70, 524], font=6.7)
    note(c, 34, 42, 774, 30, "Count basis", "AST-derived from the active FastAPI source on 2026-10-26; route aliases/current product surfaces are grouped for readability.", color=BLUE)


def page_customer(c, page):
    start_page(c, "19 - Customer lifecycle", "From connection to verified Protect cutover", page)
    stages = [
        (52, 374, "1. Create workspace", "Verify administrator email, configure organization roles, optional OIDC/SCIM."),
        (204, 374, "2. Connect source", "OAuth/admin consent, approved boundary, sync directory and ACLs, inspect health."),
        (356, 374, "3. Enroll Guard", "Download/package, launch local setup UI, exchange one-time token, confirm heartbeat."),
        (508, 374, "4. Register AI app", "Bind source, Guard, application ID, adapter contract, start in Shadow."),
        (660, 374, "5. Integrate RAG", "SDK or Gateway, trusted ingestion keys, identity mapping, buffering and provenance."),
        (128, 198, "6. Observe Shadow", "Review would-block reasons, unknowns, source freshness, route coverage, and audit."),
        (318, 198, "7. Run challenge", "Authorized allow, denied/revoked Layer 1 block, provenance/tamper Layer 2 block."),
        (508, 198, "8. Request Protect", "Readiness gate verifies Guard/source/identity/policy/revision/route evidence."),
        (698, 198, "9. Operate", "Monitor revisions, revocation timeline, blocked requests, reports, metrics, rotation, and retention."),
    ]
    for i, (x,y,h,b) in enumerate(stages):
        w = 132 if i < 5 else 150
        box(c, x, y, w, 106, h, b, fill=WHITE, accent=TEAL, center=True, body_size=6.4)
    for i in range(4):
        x = stages[i][0] + 132; nx = stages[i+1][0]
        arrow(c, [(x, 427), (nx, 427)], color=TEAL)
    arrow(c, [(726, 374), (726, 330), (128, 330), (128, 304)], color=TEAL)
    for i in range(5,8):
        x = stages[i][0] + 150; nx = stages[i+1][0]
        arrow(c, [(x, 251), (nx, 251)], color=TEAL)
    note(c, 52, 104, 736, 60, "Operator responsibilities",
         "Keep Guard/Gateway private and patched; own IdP and provider consent; protect ingestion private keys; instrument every retrieval/cache/tool path in scope; avoid streaming on protected routes; review stale/unknown state; rerun challenge after configuration or policy changes.", color=AMBER)
    note(c, 52, 48, 736, 40, "Claim boundary", "Protect status applies only to the verified application route and binding. It does not automatically cover every AI endpoint in the customer's estate.", color=RED)


def page_repository(c, page):
    start_page(c, "20 - Code map", "Repository-to-runtime component map", page)
    data = [
        ["Path", "Runtime / responsibility"],
        ["web-v2/", "Official Next.js frontend, same-origin API proxy, 21 product/auth screens, Playwright flows."],
        ["apps/api/accessproof_api/", "FastAPI control plane, domain orchestration, auth, tenant/RBAC, sources, Guard, protection, testing, reporting, SCIM."],
        ["apps/worker/accessproof_worker/", "Background polling/event processing, provider reconciliation/watch renewal, outboxes, cleanup, retention, alerts."],
        ["apps/guard/accessproof_guard/", "Customer-side HTTP service, enrollment UI/CLI, OIDC identity validation, local sync/cache, Layer 1/2 endpoints."],
        ["apps/gateway/accessproof_gateway/", "Customer-side protected RAG HTTP boundary, model adapters, install/cutover/challenge agents."],
        ["apps/runner/accessproof_runner/", "Private synthetic test runner, enrollment UI, leases, checkpoints, source mutation, target probes, completion."],
        ["packages/guard/", "Provider-neutral policy and permission resolution primitives."],
        ["packages/rag_sdk/", "Python protected RAG lifecycle, adapters, attestations, ingestion, authorization-first retrieval, pgvector, cache verification."],
        ["packages/rag-sdk-typescript/", "TypeScript protected RAG and source-attestation contract."],
        ["packages/auth, crypto, identity, domain, reporting, test_engine", "Shared session/OIDC/security primitives, signing/encryption, models, report output, and test orchestration."],
        ["connectors/", "Google Drive, Microsoft 365, Confluence, Salesforce, Slack, demo, and mock source adapters."],
        ["integrations/", "Email, GitHub, GitLab, durable signed webhooks."],
        ["migrations/versions/", "43 Alembic revisions through tenant-RLS evidence hardening."],
        ["deploy/ + packaging/", "nginx/TLS/systemd material; Guard/Gateway customer packages and release artifacts."],
        ["tests/ + web-v2/e2e/", "181 test modules/specs covering unit, integration, security, contract, load, customer simulation, and UI paths."],
    ]
    draw_table(c, data, 34, 50, 774, 438, widths=[220, 554], font=6.5)


def page_operations(c, page):
    start_page(c, "21 - Operations", "Runtime jobs, observability, delivery, and lifecycle controls", page)
    lane(c, 34, 92, 240, 392, "Worker loop", fill=PALE_BLUE)
    bullets(c, [
        "Refresh expiring provider OAuth credentials against pinned token endpoints",
        "Process Google provider-event hints via authoritative changes.list",
        "Schedule directory and ACL synchronization and known-resource reconciliation",
        "Maintain Google watch channels and renew before expiry",
        "Resolve normalized Guard permission events into policies",
        "Deliver email and signed webhooks from durable outboxes",
        "Retry owned synthetic-resource cleanup",
        "Apply retention and create operational alerts",
    ], 50, 122, 208, 326, size=7.1)

    lane(c, 294, 92, 250, 392, "Health and telemetry", fill=PALE_TEAL)
    box(c, 314, 386, 210, 68, "Service health", "API live/ready; web and container health checks; Guard and Gateway live/ready; runner/Guard heartbeat age.", fill=WHITE, accent=GREEN)
    box(c, 314, 286, 210, 68, "Metrics", "Prometheus counters/gauges for auth decisions, source freshness, event lag, route coverage, revision lag, cache reauth, and revocation latency.", fill=WHITE, accent=GREEN)
    box(c, 314, 186, 210, 68, "Tracing", "Optional OpenTelemetry SDK/OTLP exporter; identifiers and labels are bounded to prevent content/tenant leakage.", fill=WHITE, accent=PURPLE)
    box(c, 314, 116, 210, 42, "Diagnostics", "web-v2 diagnostics and API readiness expose actionable state without secrets.", fill=WHITE, accent=BLUE)

    lane(c, 564, 92, 244, 392, "Lifecycle safety", fill=PALE_AMBER)
    box(c, 584, 386, 204, 68, "Credential rotation", "Source, runner, Guard, API-key, session and report-signing lifecycles are distinct.", fill=WHITE, accent=PURPLE)
    box(c, 584, 286, 204, 68, "Retention/deletion", "Tenant retention policy, purge workflow, organization/project deletion checks, and deletion receipts.", fill=WHITE, accent=RED)
    box(c, 584, 186, 204, 68, "Release safety", "Versioned web image, one-shot migration service, schema preflight, backups, service health before cutover.", fill=WHITE, accent=BLUE)
    box(c, 584, 116, 204, 42, "Recovery", "Durable DB/Redis volumes and Guard policy cache; bounded outbox retries and alerts.", fill=WHITE, accent=AMBER)
    arrow(c, [(274, 300), (314, 320)], color=BLUE, label="measure")
    arrow(c, [(544, 220), (584, 220)], color=AMBER, label="operate")
    note(c, 34, 46, 774, 30, "Scaling note", "Horizontal worker/API scaling, provider rate-limit behavior, and production load characteristics require environment-specific validation.", color=AMBER)


def page_limits(c, page):
    start_page(c, "22 - Evidence boundary", "Implemented architecture versus remaining validation", page)
    box(c, 34, 294, 374, 188, "Implemented and locally/contract verified",
        "<b>Control plane</b>: auth, tenant/RBAC/RLS, sources, effective access, Guard policies, signed revisions, evidence, reports, worker pipelines.<br/><br/><b>Enforcement</b>: Guard Layer 1/2, durable policy, OIDC identity, one-time contexts, signed content attestation, buffered response release.<br/><br/><b>Integration</b>: Python/TypeScript SDKs, LangChain/LlamaIndex/Haystack adapters, Gateway route, authorization-first pgvector reference, signed cache manifests.<br/><br/><b>Verification</b>: private runner lifecycle, route challenge, revocation timeline, metrics, signed control-plane reports.",
        fill=PALE_TEAL, accent=GREEN, body_size=7.4)
    box(c, 434, 294, 374, 188, "Evidence still required for unrestricted production claims",
        "<b>Live providers</b>: Google Workspace inherited/nested-group/Shared Drive/limited-access revocations at realistic scale; Microsoft/SharePoint effective authorization and consent/token lifecycle.<br/><br/><b>Customer routes</b>: independently integrated external RAG with every retrieval, cache, tool, memory, agent and background path covered.<br/><br/><b>Operations</b>: real OIDC tenants, key rotation, multi-worker PostgreSQL/pgvector behavior, load/resilience/failover, rate limits, streaming alternatives, WebSocket/SSE scope.<br/><br/><b>Certification</b>: independent customer or third-party evidence is not created by local tests.",
        fill=PALE_AMBER, accent=AMBER, body_size=7.4)
    lane(c, 34, 92, 774, 170, "Claim vocabulary", fill=PALE)
    cards = [
        (52, "LAB", "Unit/local integration evidence; valid for engineering and controlled demonstration."),
        (238, "CONSTRAINED PILOT", "Only after provider, identity, route, and operational evidence exists for the named scope."),
        (424, "CERTIFIED PROFILE", "Exact binding and route, current challenge/certificate, explicit limitations, independent evidence where claimed."),
        (610, "NO-GO", "Missing identity, source truth, policy, Guard readiness, revision, provenance, or route coverage."),
    ]
    for i,(x,h,b) in enumerate(cards):
        box(c, x, 126, 168, 102, h, b, fill=WHITE, accent=[BLUE, AMBER, GREEN, RED][i], center=True)
    note(c, 34, 44, 774, 30, "Interpretation", "Architecture shows what the code is designed to do. It does not convert simulated evidence into live-provider or independent certification.", color=RED)


def build():
    c = canvas.Canvas(str(OUT), pagesize=landscape(A4), pageCompression=1)
    c.setTitle("AccessProof Complete Technical Architecture")
    c.setAuthor("AccessProof engineering architecture generated from source")
    cover(c)
    page_legend(c, 2)
    page_context(c, 3)
    page_deployment(c, 4)
    page_control_plane(c, 5)
    page_identity(c, 6)
    page_source_sync(c, 7)
    page_effective_access(c, 8)
    page_policy_distribution(c, 9)
    page_guard(c, 10)
    page_rag_sequence(c, 11)
    page_integrations(c, 12)
    page_gateway(c, 13)
    page_runner(c, 14)
    page_evidence(c, 15)
    page_data(c, 16)
    page_security(c, 17)
    page_failures(c, 18)
    page_api(c, 19)
    page_routes(c, 20)
    page_customer(c, 21)
    page_repository(c, 22)
    page_operations(c, 23)
    page_limits(c, 24)
    c.save()
    print(OUT)


if __name__ == "__main__":
    build()
