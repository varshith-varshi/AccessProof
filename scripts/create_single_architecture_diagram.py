"""Generate the one-page AccessProof end-to-end architecture diagram."""
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A3, landscape
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas


OUT = Path("output/pdf/accessproof-end-to-end-architecture-workflow.pdf")
W, H = landscape(A3)

NAVY = colors.HexColor("#082A38")
INK = colors.HexColor("#112B3C")
MUTED = colors.HexColor("#5B7180")
LINE = colors.HexColor("#BDCBD2")
PANEL = colors.HexColor("#F5F8FA")
TEAL = colors.HexColor("#00A98F")
BLUE = colors.HexColor("#1976C9")
PURPLE = colors.HexColor("#7257B7")
AMBER = colors.HexColor("#F29D38")
RED = colors.HexColor("#D94B55")
GREEN = colors.HexColor("#238C63")


def fit(c, text, x, y, max_width, font="Helvetica", size=8.2, color=INK):
    current = size
    while stringWidth(text, font, current) > max_width and current > 5.6:
        current -= 0.2
    c.setFont(font, current)
    c.setFillColor(color)
    c.drawString(x, y, text)


def wrapped(c, text, x, y, width, font="Helvetica", size=7, leading=8.5, color=MUTED, max_lines=4):
    words = text.split()
    lines, line = [], ""
    for word in words:
        trial = (line + " " + word).strip()
        if stringWidth(trial, font, size) <= width:
            line = trial
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    lines = lines[:max_lines]
    c.setFillColor(color)
    c.setFont(font, size)
    for index, value in enumerate(lines):
        c.drawString(x, y - index * leading, value)


def box(c, x, y, w, h, title, subtitle, accent=TEAL, step=None):
    c.setFillColor(colors.white)
    c.setStrokeColor(LINE)
    c.setLineWidth(0.7)
    c.roundRect(x, y, w, h, 7, stroke=1, fill=1)
    c.setFillColor(accent)
    c.roundRect(x, y + h - 5, w, 5, 7, stroke=0, fill=1)
    if step is not None:
        c.setFillColor(accent)
        c.circle(x + 14, y + h - 18, 9, stroke=0, fill=1)
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 7)
        c.drawCentredString(x + 14, y + h - 20.5, str(step))
        tx = x + 29
        tw = w - 36
    else:
        tx = x + 10
        tw = w - 20
    fit(c, title, tx, y + h - 22, tw, "Helvetica-Bold", 8.2, INK)
    wrapped(c, subtitle, x + 10, y + h - 36, w - 20, max_lines=4)


def zone(c, x, y, w, h, label, sublabel, color):
    c.setFillColor(PANEL)
    c.setStrokeColor(colors.HexColor("#D9E2E7"))
    c.roundRect(x, y, w, h, 9, stroke=1, fill=1)
    c.setFillColor(color)
    c.roundRect(x, y + h - 27, w, 27, 9, stroke=0, fill=1)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 9)
    c.drawString(x + 10, y + h - 17, label)
    c.setFont("Helvetica", 6.5)
    c.drawRightString(x + w - 10, y + h - 17, sublabel)


def arrow(c, points, color=BLUE, dashed=False, label=None, lx=None, ly=None):
    c.saveState()
    c.setStrokeColor(color)
    c.setLineWidth(1.45)
    if dashed:
        c.setDash(3, 2)
    path = c.beginPath()
    path.moveTo(*points[0])
    for point in points[1:]:
        path.lineTo(*point)
    c.drawPath(path, stroke=1, fill=0)
    x1, y1 = points[-2]
    x2, y2 = points[-1]
    import math
    angle = math.atan2(y2-y1, x2-x1)
    head = 6
    c.setFillColor(color)
    p = c.beginPath()
    p.moveTo(x2, y2)
    p.lineTo(x2 - head * math.cos(angle - 0.48), y2 - head * math.sin(angle - 0.48))
    p.lineTo(x2 - head * math.cos(angle + 0.48), y2 - head * math.sin(angle + 0.48))
    p.close()
    c.drawPath(p, stroke=0, fill=1)
    c.restoreState()
    if label and lx is not None:
        c.setFillColor(colors.white)
        c.setStrokeColor(colors.HexColor("#D8E1E6"))
        tw = stringWidth(label, "Helvetica", 6.5) + 8
        c.roundRect(lx - 3, ly - 2, tw, 10, 3, stroke=1, fill=1)
        c.setFillColor(color)
        c.setFont("Helvetica", 6.5)
        c.drawString(lx + 1, ly, label)


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(OUT), pagesize=landscape(A3))
    c.setTitle("AccessProof End-to-End Architecture and Workflow")
    c.setAuthor("AccessProof engineering architecture generated from source")
    c.setFillColor(colors.white)
    c.rect(0, 0, W, H, stroke=0, fill=1)
    c.setFillColor(NAVY)
    c.rect(0, H - 62, W, 62, stroke=0, fill=1)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 20)
    c.drawString(34, H - 34, "AccessProof - complete end-to-end architecture")
    c.setFont("Helvetica", 8.5)
    c.drawString(34, H - 49, "One workflow: synchronize authoritative access -> enforce before generation -> verify provenance -> retain defensible evidence")
    c.setFillColor(colors.HexColor("#B8CED7"))
    c.setFont("Helvetica", 7)
    c.drawRightString(W - 34, H - 43, "Source-derived architecture | v1 control plane + v2 Guard/Gateway")

    # Major boundaries
    left, gap = 28, 12
    y, zh = 238, 487
    widths = [190, 286, 370, 260]
    xs = []
    cursor = left
    for width in widths:
        xs.append(cursor)
        cursor += width + gap
    zone(c, xs[0], y, widths[0], zh, "CUSTOMER IDENTITY + SOURCES", "authoritative systems", PURPLE)
    zone(c, xs[1], y, widths[1], zh, "ACCESSPROOF CONTROL PLANE", "hosted or customer-managed", BLUE)
    zone(c, xs[2], y, widths[2], zh, "CUSTOMER RUNTIME", "inside the customer trust boundary", TEAL)
    zone(c, xs[3], y, widths[3], zh, "AI + RETRIEVAL", "customer-selected stack", AMBER)

    # First column: authoritative side
    box(c, xs[0] + 13, 640, 164, 61, "Enterprise IdP / Directory", "OIDC issuer, workforce identities, group membership and session claims.", PURPLE, 1)
    box(c, xs[0] + 13, 552, 164, 65, "Permission Sources", "Google Drive, SharePoint/M365, Confluence, Slack, Salesforce and source connectors.", PURPLE, 2)
    box(c, xs[0] + 13, 460, 164, 68, "Authoritative Change", "A document, inherited permission or group membership is added, changed or revoked.", RED, 3)
    box(c, xs[0] + 13, 358, 164, 76, "Customer RAG Application", "Uses the Guard/Gateway or the Python/TypeScript SDK before it retrieves or answers.", TEAL, 8)
    box(c, xs[0] + 13, 262, 164, 70, "Application / End User", "Authenticated user request. User identity and tenant context enter the protected path.", TEAL, 7)

    # Control plane
    box(c, xs[1] + 14, 640, 124, 61, "Web-v2 UI", "Workspace setup, source and AI application configuration, incidents and reports.", BLUE)
    box(c, xs[1] + 148, 640, 124, 61, "FastAPI API", "Tenant/RBAC boundary; registration, policy and evidence APIs.", BLUE)
    box(c, xs[1] + 14, 550, 124, 65, "Source Sync + Workers", "Connector polling/webhooks normalize source permissions into change events.", BLUE, 4)
    box(c, xs[1] + 148, 550, 124, 65, "Effective Access Resolver", "Expands direct grants, nested groups and inheritance into per-resource access state.", BLUE, 5)
    box(c, xs[1] + 14, 448, 124, 74, "Policy + Revision Engine", "Maps source state into signed, tenant-scoped authorization revisions and policy bundles.", BLUE, 6)
    box(c, xs[1] + 148, 448, 124, 74, "Evidence + Reporting", "Audit trail, decision events, incidents, signed reports, retention and export controls.", BLUE, 13)
    box(c, xs[1] + 14, 318, 258, 100, "State and Control Services", "PostgreSQL: tenants, users, integrations, grants, events, policies, revisions, decisions and evidence. Redis: jobs, caching and worker coordination. Secret backend: encrypted source credentials and signing material.", BLUE)
    box(c, xs[1] + 14, 262, 258, 34, "Outbound integrations", "Webhooks, email/SMTP, GitHub/GitLab, OTLP and operational notifications.", BLUE)

    # Runtime
    box(c, xs[2] + 14, 640, 163, 61, "AccessProof Guard", "Customer-installed local policy decision point. Receives only signed revisions and stores encrypted SQLite state.", TEAL)
    box(c, xs[2] + 193, 640, 163, 61, "RAG Gateway", "Optional HTTP boundary for frameworks that cannot directly embed the SDK.", TEAL)
    box(c, xs[2] + 14, 550, 163, 64, "Layer 1 - Pre-retrieval", "Checks tenant, subject, resource scope, policy revision, freshness and source authorization before retrieval.", GREEN, 9)
    box(c, xs[2] + 193, 550, 163, 64, "Layer 2 - Pre-release", "Verifies cited resource provenance, authorization version and newly revoked resources before release.", GREEN, 11)
    box(c, xs[2] + 14, 448, 163, 73, "Adapter / SDK", "Python and TypeScript middleware extracts identity, builds check requests and reports decisions.", TEAL)
    box(c, xs[2] + 193, 448, 163, 73, "Signed policy delivery", "Enrollment identity, mTLS or bearer transport, signature validation, revision acknowledgement and heartbeat.", TEAL)
    box(c, xs[2] + 14, 345, 342, 73, "Customer-local decision boundary", "Guard evaluates locally and fails closed when a required policy, signature, tenant binding or source freshness requirement is invalid. Raw source credentials and identity tokens do not return to the hosted control plane.", RED)
    box(c, xs[2] + 14, 262, 342, 58, "Decision telemetry", "Allow/block reason, policy/revision IDs, provenance summary and health flow to the control plane without application payload secrets.", TEAL, 12)

    # AI + retrieval
    box(c, xs[3] + 14, 640, 232, 61, "Retriever / Vector Store / Connector", "Searches customer indexes or live source APIs and returns resource IDs plus provenance metadata.", AMBER)
    box(c, xs[3] + 14, 550, 232, 64, "LLM / AI Provider", "Generates a candidate response. It is buffered until Layer 2 provenance and revocation checks approve release.", AMBER, 10)
    box(c, xs[3] + 14, 448, 232, 73, "Provenance Contract", "Each retrieved item must carry a stable resource identifier, source context and authorization-relevant metadata.", AMBER)
    box(c, xs[3] + 14, 345, 232, 73, "Safe response / block", "Only approved, attributable content reaches the user. Blocks are explainable and recorded for operators.", GREEN, 14)
    box(c, xs[3] + 14, 262, 232, 58, "Provider controls", "Time-outs, retries, response-size limits, schema validation, streaming buffer/hold and error classification.", AMBER)

    # arrows - source synchronization top/middle
    arrow(c, [(xs[0] + 95, 552), (xs[0] + 95, 535), (xs[1] + 76, 535), (xs[1] + 76, 550)], BLUE, label="sync / webhook", lx=190, ly=537)
    arrow(c, [(xs[1] + 138, 582), (xs[1] + 148, 582)], BLUE, label="normalized events", lx=352, ly=586)
    arrow(c, [(xs[1] + 210, 550), (xs[1] + 210, 530), (xs[1] + 76, 530), (xs[1] + 76, 522)], BLUE, label="effective grants", lx=325, ly=531)
    arrow(c, [(xs[1] + 138, 485), (xs[1] + 148, 485)], BLUE, label="audit / evidence", lx=349, ly=489)
    arrow(c, [(xs[1] + 138, 485), (xs[1] + 210, 485), (xs[1] + 210, 522)], BLUE, label="policy revision", lx=347, ly=511)
    arrow(c, [(xs[1] + 272, 485), (xs[2] + 193, 485), (xs[2] + 193, 522)], TEAL, label="signed bundle", lx=584, ly=490)
    arrow(c, [(xs[2] + 274, 550), (xs[2] + 274, 530), (xs[2] + 95, 530), (xs[2] + 95, 522)], TEAL, label="ack / heartbeat", lx=730, ly=532)

    # request workflow
    arrow(c, [(xs[0] + 95, 332), (xs[0] + 95, 346), (xs[0] + 95, 346), (xs[0] + 95, 358)], TEAL, label="request", lx=113, ly=340)
    arrow(c, [(xs[0] + 177, 397), (xs[2] + 14, 397), (xs[2] + 14, 480)], TEAL, label="identity + resource context", lx=405, ly=401)
    arrow(c, [(xs[2] + 177, 480), (xs[2] + 193, 480)], TEAL, label="check", lx=754, ly=484)
    arrow(c, [(xs[2] + 95, 448), (xs[2] + 95, 430), (xs[3] + 14, 430), (xs[3] + 14, 670)], GREEN, label="allow to retrieve", lx=767, ly=434)
    arrow(c, [(xs[3] + 130, 640), (xs[3] + 130, 614)], AMBER, label="grounded context", lx=1062, ly=620)
    arrow(c, [(xs[3] + 130, 550), (xs[3] + 130, 522), (xs[2] + 274, 522)], AMBER, label="candidate answer + citations", lx=939, ly=527)
    arrow(c, [(xs[2] + 274, 550), (xs[2] + 274, 530), (xs[3] + 130, 530), (xs[3] + 130, 418)], GREEN, label="release / block", lx=960, ly=534)

    # telemetry and state lines
    arrow(c, [(xs[2] + 185, 262), (xs[2] + 185, 245), (xs[1] + 210, 245), (xs[1] + 210, 296)], TEAL, dashed=True, label="decision telemetry", lx=560, ly=248)
    arrow(c, [(xs[1] + 76, 448), (xs[1] + 76, 418)], BLUE, dashed=True, label="persist", lx=428, ly=425)
    arrow(c, [(xs[1] + 272, 470), (xs[1] + 300, 470), (xs[1] + 300, 279), (xs[1] + 272, 279)], BLUE, dashed=True, label="notify", lx=528, ly=365)

    # bottom workflow band
    c.setFillColor(NAVY)
    c.roundRect(28, 154, W - 56, 78, 8, stroke=0, fill=1)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(42, 210, "End-to-end workflow")
    workflow = [
        ("1", "Connect identity and sources"), ("2", "Ingest permission change"),
        ("3", "Resolve effective access"), ("4", "Publish signed revision"),
        ("5", "Guard acknowledges policy"), ("6", "User asks RAG"),
        ("7", "Layer 1 authorizes retrieval"), ("8", "Retriever + model produce candidate"),
        ("9", "Layer 2 verifies provenance + revocation"), ("10", "Release/block and retain evidence"),
    ]
    start_x, cell_w = 42, 112
    for idx, (num, text) in enumerate(workflow):
        x = start_x + idx * cell_w
        c.setFillColor(TEAL if idx not in (2, 8) else AMBER)
        c.circle(x + 8, 185, 8, stroke=0, fill=1)
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 6.5)
        c.drawCentredString(x + 8, 182.8, num)
        wrapped(c, text, x + 20, 190, cell_w - 23, "Helvetica", 6.5, 7.3, colors.white, 2)
        if idx < len(workflow) - 1:
            c.setStrokeColor(colors.HexColor("#6D94A2"))
            c.setLineWidth(1)
            c.line(x + cell_w - 9, 185, x + cell_w - 2, 185)

    # legend + note
    c.setFillColor(INK)
    c.setFont("Helvetica-Bold", 7.6)
    c.drawString(30, 128, "Diagram key")
    legend = [(PURPLE, "identity/source authority"), (BLUE, "control-plane processing"), (TEAL, "customer runtime and data path"), (AMBER, "retrieval/model processing"), (RED, "fail-closed trust boundary"), (GREEN, "enforced allow/block gate")]
    lx = 30
    for color, text in legend:
        c.setFillColor(color)
        c.roundRect(lx, 110, 9, 9, 2, stroke=0, fill=1)
        c.setFillColor(MUTED)
        c.setFont("Helvetica", 6.8)
        c.drawString(lx + 13, 111, text)
        lx += 178
    c.setFillColor(colors.HexColor("#FFF5E6"))
    c.setStrokeColor(colors.HexColor("#F2C88A"))
    c.roundRect(28, 50, W - 56, 47, 7, stroke=1, fill=1)
    c.setFillColor(INK)
    c.setFont("Helvetica-Bold", 7.6)
    c.drawString(40, 81, "Security invariant")
    wrapped(c, "AccessProof is an authorization control and evidence plane, not a replacement identity provider or document store. Correct protection depends on a trustworthy source connector, canonical resource IDs, secure Guard enrollment, signed policy delivery, and the RAG supplying complete retrieval provenance.", 40, 68, W - 80, "Helvetica", 7.3, 9, INK, 2)
    c.setFillColor(MUTED)
    c.setFont("Helvetica", 6.4)
    c.drawRightString(W - 30, 23, "Generated from the AccessProof f15 repository | architecture summary")
    c.save()


if __name__ == "__main__":
    main()
