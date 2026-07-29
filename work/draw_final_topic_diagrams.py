from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


OUT = Path("report_assets/diagrams")
WIDTH, HEIGHT = 1800, 1180

FONT_REGULAR = r"C:\Windows\Fonts\arial.ttf"
FONT_BOLD = r"C:\Windows\Fonts\arialbd.ttf"

NAVY = "#123653"
INK = "#17324A"
MUTED = "#526C80"
BLUE = "#2375B8"
CYAN = "#2D9AB7"
GREEN = "#278B68"
AMBER = "#D48616"
RED = "#C24656"
SLATE = "#667A8C"
WHITE = "#FFFFFF"
CANVAS = "#F4F7FA"
PANEL = "#FFFFFF"
BORDER = "#B9CAD6"
LIGHT_BLUE = "#EAF4FB"
LIGHT_GREEN = "#E9F6F0"
LIGHT_AMBER = "#FFF4E2"
LIGHT_RED = "#FDECEF"
LIGHT_SLATE = "#EFF3F6"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONT_BOLD if bold else FONT_REGULAR, size)


def wrap(draw: ImageDraw.ImageDraw, text: str, fnt: ImageFont.FreeTypeFont, width: int) -> list[str]:
    output: list[str] = []
    for raw in text.split("\n"):
        if not raw:
            output.append("")
            continue
        current = ""
        for word in raw.split():
            candidate = word if not current else f"{current} {word}"
            if draw.textbbox((0, 0), candidate, font=fnt)[2] <= width:
                current = candidate
            else:
                if current:
                    output.append(current)
                current = word
        if current:
            output.append(current)
    return output


def text(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    value: str,
    size: int,
    fill: str = INK,
    bold: bool = False,
    width: int | None = None,
    spacing: int = 5,
) -> None:
    fnt = font(size, bold)
    x, y = xy
    if width is None:
        draw.text((x, y), value, font=fnt, fill=fill)
        return
    line_height = draw.textbbox((0, 0), "Ag", font=fnt)[3] + spacing
    for line in wrap(draw, value, fnt, width):
        draw.text((x, y), line, font=fnt, fill=fill)
        y += line_height


def box(
    draw: ImageDraw.ImageDraw,
    rect: tuple[int, int, int, int],
    title: str,
    body: str,
    accent: str,
    fill: str = PANEL,
    title_size: int = 25,
    body_size: int = 20,
) -> None:
    x1, y1, x2, y2 = rect
    draw.rounded_rectangle(rect, radius=18, fill=fill, outline=BORDER, width=3)
    draw.rounded_rectangle((x1, y1, x1 + 12, y2), radius=8, fill=accent)
    text(draw, (x1 + 28, y1 + 18), title, title_size, INK, True)
    text(draw, (x1 + 28, y1 + 58), body, body_size, MUTED, False, x2 - x1 - 52)


def title_bar(draw: ImageDraw.ImageDraw, title: str, subtitle: str) -> None:
    draw.rectangle((0, 0, WIDTH, 120), fill=NAVY)
    text(draw, (48, 24), title, 39, WHITE, True)
    text(draw, (50, 76), subtitle, 23, "#D7E8F5")


def arrow(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    color: str = BLUE,
    width: int = 6,
    label: str | None = None,
) -> None:
    draw.line((*start, *end), fill=color, width=width)
    angle = math.atan2(end[1] - start[1], end[0] - start[0])
    head, wing = 18, 10
    p2 = (
        end[0] - head * math.cos(angle) + wing * math.sin(angle),
        end[1] - head * math.sin(angle) - wing * math.cos(angle),
    )
    p3 = (
        end[0] - head * math.cos(angle) - wing * math.sin(angle),
        end[1] - head * math.sin(angle) + wing * math.cos(angle),
    )
    draw.polygon((end, p2, p3), fill=color)
    if label:
        fnt = font(17, True)
        bbox = draw.textbbox((0, 0), label, font=fnt)
        cx = (start[0] + end[0]) // 2
        cy = (start[1] + end[1]) // 2 - 28
        pad_x, pad_y = 12, 7
        draw.rounded_rectangle(
            (cx - (bbox[2] - bbox[0]) // 2 - pad_x, cy - pad_y,
             cx + (bbox[2] - bbox[0]) // 2 + pad_x, cy + (bbox[3] - bbox[1]) + pad_y),
            radius=8,
            fill=WHITE,
            outline=BORDER,
            width=2,
        )
        draw.text((cx - (bbox[2] - bbox[0]) // 2, cy), label, font=fnt, fill=color)


def dashed_arrow(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    color: str = SLATE,
    width: int = 4,
) -> None:
    x1, y1 = start
    x2, y2 = end
    dist = math.hypot(x2 - x1, y2 - y1)
    if not dist:
        return
    ux, uy = (x2 - x1) / dist, (y2 - y1) / dist
    pos = 0.0
    while pos < dist - 18:
        seg = min(pos + 18, dist - 18)
        draw.line((x1 + ux * pos, y1 + uy * pos, x1 + ux * seg, y1 + uy * seg), fill=color, width=width)
        pos += 30
    arrow(draw, start=(int(x2 - ux * 22), int(y2 - uy * 22)), end=end, color=color, width=width)


def elbow_arrow(
    draw: ImageDraw.ImageDraw,
    points: list[tuple[int, int]],
    color: str = BLUE,
    width: int = 5,
    label: str | None = None,
) -> None:
    if len(points) < 2:
        return
    for start, end in zip(points, points[1:-1]):
        draw.line((*start, *end), fill=color, width=width)
    arrow(draw, points[-2], points[-1], color=color, width=width)
    if label and len(points) >= 3:
        mid = points[len(points) // 2]
        fnt = font(17, True)
        bbox = draw.textbbox((0, 0), label, font=fnt)
        draw.rounded_rectangle(
            (mid[0] - 12, mid[1] - 27, mid[0] + (bbox[2] - bbox[0]) + 14, mid[1] + 2),
            radius=8,
            fill=WHITE,
            outline=BORDER,
            width=2,
        )
        draw.text((mid[0], mid[1] - 23), label, font=fnt, fill=color)


def canvas(title: str, subtitle: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (WIDTH, HEIGHT), CANVAS)
    draw = ImageDraw.Draw(image)
    title_bar(draw, title, subtitle)
    return image, draw


def save(image: Image.Image, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    image.save(OUT / name, optimize=True)
    print((OUT / name).resolve())


def architecture() -> None:
    image, draw = canvas(
        "KIẾN TRÚC TỔNG THỂ A11 AGENTIC SOC LOCAL-FIRST",
        "Ubuntu SOC là lõi xử lý; RAG và n8n nằm trong stack local; Splunk chỉ quan sát bản sao log",
    )
    y = 175
    cols = [
        (60, "TELEMETRY", RED, LIGHT_RED, "Kali attack\nOPNsense syslog\nApache access.log\nSuricata EVE\nWindows Security Event"),
        (390, "COLLECTOR", CYAN, LIGHT_BLUE, "REST API /api/v1/ingest\nHEC-compatible :8000\nSyslog UDP/5514\nAuth token + API key"),
        (720, "SOCPIPELINE", BLUE, LIGHT_BLUE, "Parse → normalize\nFingerprint + dedup\nCorrelation window 300s\nPersist raw evidence"),
        (1050, "AGENTIC AI", GREEN, LIGHT_GREEN, "Triage deterministic\nEnrichment IOC/asset\nRAG local playbook\nOllama optional"),
        (1380, "OPERATIONS", AMBER, LIGHT_AMBER, "Alert + Incident\nReport Markdown\nApproval gate\nn8n/OPNsense/audit"),
    ]
    rects = []
    for x, title, accent, fill, body in cols:
        rect = (x, y, x + 290, y + 450)
        rects.append(rect)
        box(draw, rect, title, body, accent, fill, 24, 20)
    for left, right in zip(rects, rects[1:]):
        arrow(draw, (left[2] + 8, y + 225), (right[0] - 10, y + 225), BLUE)
    box(
        draw,
        (110, 765, 560, 975),
        "POSTGRESQL + DATA",
        "alerts • security_events • incidents • response_actions • audit_events\nassets.json + iocs.json",
        SLATE,
        LIGHT_SLATE,
    )
    box(
        draw,
        (680, 765, 1180, 975),
        "KNOWLEDGE + AUTOMATION",
        "knowledge/*.md: 8 playbook RAG\nn8n/workflows/a11_soc_local_automation.json\nWebhook audit callback",
        GREEN,
        LIGHT_GREEN,
    )
    box(
        draw,
        (1300, 765, 1730, 975),
        "SPLUNK OPTIONAL",
        "Nhận mirror raw log để tìm kiếm/đối chiếu.\nKhông cấp dữ liệu bắt buộc cho A11 SOC.",
        SLATE,
        LIGHT_SLATE,
        22,
        19,
    )
    dashed_arrow(draw, (520, 640), (340, 755), SLATE)
    dashed_arrow(draw, (1200, 640), (930, 755), SLATE)
    dashed_arrow(draw, (340, 370), (1300, 840), SLATE)
    save(image, "so_do_2_1_kien_truc_tong_the.png")


def network() -> None:
    image, draw = canvas(
        "MÔ HÌNH MẠNG LAB VÀ TUYẾN TELEMETRY LOCAL-FIRST",
        "IP, subnet, giao thức và vai trò từng máy trong kịch bản tấn công đến SOC",
    )
    box(draw, (70, 250, 390, 460), "KALI ATTACKER", "192.168.228.128/24\nWAN lab 192.168.228.0/24\nNmap TCP SYN\nDIRB HTTP GET", RED, LIGHT_RED)
    box(draw, (520, 230, 880, 485), "OPNSENSE", "WAN: 192.168.228.142/24\nLAN: 192.168.1.1/24\nNAT WAN:80 → 192.168.1.100:80\nSuricata + firewall filterlog", AMBER, LIGHT_AMBER)
    box(draw, (1010, 170, 1340, 370), "WEB/SURICATA TARGET", "Ubuntu target 192.168.1.100/24\nApache TCP/80\naccess.log + eve.json", BLUE, LIGHT_BLUE)
    box(draw, (1410, 170, 1725, 370), "WINDOWS ENDPOINT", "192.168.1.101/24\nSecurity Event JSON\n4625 • 4688 • 1102", CYAN, LIGHT_BLUE)
    box(draw, (710, 760, 1110, 1010), "A11 SOC UBUNTU SERVER", "192.168.1.10/24\nDocker Compose: api + postgres + n8n\nREST/HEC TCP/8000\nSyslog UDP/5514", GREEN, LIGHT_GREEN)
    box(draw, (1310, 760, 1720, 985), "SPLUNK CLOUD/ENTERPRISE", "Bản sao telemetry để quan sát\nDashboard/search tùy chọn\nKhông thuộc critical path", SLATE, LIGHT_SLATE, 23, 19)
    arrow(draw, (395, 355), (510, 355), RED, label="TCP/80, ICMP, scan")
    arrow(draw, (885, 330), (1000, 275), AMBER, label="DNAT HTTP")
    elbow_arrow(draw, [(1175, 380), (1175, 670), (1030, 750)], BLUE, 5, "REST/HEC :8000")
    elbow_arrow(draw, [(1565, 380), (1565, 700), (1115, 835)], CYAN, 5, "REST/HEC :8000")
    elbow_arrow(draw, [(700, 500), (700, 650), (840, 750)], AMBER, 5, "Syslog UDP/5514")
    dashed_arrow(draw, (1335, 285), (1510, 750), SLATE)
    dashed_arrow(draw, (1570, 380), (1530, 750), SLATE)
    text(draw, (70, 1035), "Ghi chú: WAN trong đồ án là vùng WAN mô phỏng trong VMware, không phải Internet thật. A11 SOC chạy độc lập trên Ubuntu 192.168.1.10.", 22, MUTED, True, 1580)
    save(image, "so_do_2_2_mo_hinh_mang_lab.png")


def agent_coordination() -> None:
    image, draw = canvas(
        "MÔ HÌNH PHỐI HỢP AGENT, RAG VÀ N8N",
        "SOCPipeline là orchestrator; agent không tự vượt approval gate",
    )
    box(draw, (590, 170, 1210, 330), "SOCPipeline ORCHESTRATOR", "process(event) điều phối agent theo thứ tự xác định\nDB transaction + EventBus SSE; không gọi cloud bắt buộc", NAVY, WHITE, 26, 20)
    agents = [
        ((65, 450, 335, 650), "Parser / Normalizer", "Apache • EVE\nWindows • Syslog\nCommon schema", BLUE, LIGHT_BLUE),
        ((405, 450, 675, 650), "Enrichment", "assets.json\niocs.json\nIP context", GREEN, LIGHT_GREEN),
        ((745, 450, 1015, 650), "Triage", "severity\nconfidence\nMITRE", RED, LIGHT_RED),
        ((1085, 450, 1355, 650), "RAG Agent", "8 playbook\nknowledge/search\nlocal only", CYAN, LIGHT_BLUE),
        ((1425, 450, 1695, 650), "Local LLM", "Ollama optional\nJSON assessment\nfallback", SLATE, LIGHT_SLATE),
    ]
    for rect, title, body, accent, fill in agents:
        box(draw, rect, title, body, accent, fill, 23, 19)
    for left, right in zip(agents, agents[1:]):
        arrow(draw, (left[0][2] + 8, 550), (right[0][0] - 10, 550), BLUE, 5)
    elbow_arrow(draw, [(900, 335), (900, 405), (200, 440)], NAVY, 5, "context")
    box(draw, (320, 820, 650, 1035), "Report/Response", "Incident + report\nnotify/block/isolate proposal\napproval_required=true", AMBER, LIGHT_AMBER, 23, 19)
    box(draw, (735, 820, 1065, 1035), "Approval Gate", "Analyst approve/reject\nsafety validation\nkhông tự động chặn", RED, LIGHT_RED, 23, 19)
    box(draw, (1150, 820, 1485, 1035), "n8n + Audit", "alert webhook\nresponse webhook\n/api/v1/automation/audit", GREEN, LIGHT_GREEN, 23, 19)
    arrow(draw, (1560, 655), (485, 810), AMBER, 5, "analysis")
    arrow(draw, (655, 930), (725, 930), RED, 5)
    arrow(draw, (1070, 930), (1140, 930), GREEN, 5)
    save(image, "so_do_2_4_phoi_hop_agent.png")


def docker_compose() -> None:
    image, draw = canvas(
        "TRIỂN KHAI DOCKER COMPOSE TRÊN UBUNTU SERVER",
        "Clone GitHub → .env → docker compose profile automation → A11 SOC + n8n local",
    )
    box(draw, (80, 210, 420, 420), "GITHUB REPO", "phuonglatoi/A11-Agentic-SOC\nsource code + report\nn8n workflow + docs", BLUE, LIGHT_BLUE)
    box(draw, (560, 190, 950, 450), "UBUNTU SERVER", "Docker Engine + Compose\n.env secrets\nSOC_HTTP_BIND\nSYSLOG_BIND", GREEN, LIGHT_GREEN)
    box(draw, (1100, 165, 1510, 355), "api", "FastAPI :8000\nHEC-compatible\nSyslog UDP/5514\nSOCPipeline + SSE", BLUE, LIGHT_BLUE)
    box(draw, (1100, 410, 1510, 590), "postgres", "soc DB\nalerts/events/incidents/actions/audit\npostgres_data volume", SLATE, LIGHT_SLATE)
    box(draw, (1100, 645, 1510, 825), "n8n profile automation", "127.0.0.1:5678\n/workflows mount\nalert/response webhook", GREEN, LIGHT_GREEN)
    box(draw, (1100, 880, 1510, 1060), "optional profiles", "ollama profile ai\nsplunk-poller profile splunk\nkhông bắt buộc luồng chính", AMBER, LIGHT_AMBER)
    arrow(draw, (425, 315), (550, 315), BLUE, label="git clone")
    arrow(draw, (955, 315), (1090, 260), GREEN, label="build api")
    arrow(draw, (955, 330), (1090, 500), SLATE, label="DB URL")
    arrow(draw, (955, 350), (1090, 735), GREEN, label="profile automation")
    dashed_arrow(draw, (1305, 645), (1305, 590), GREEN)
    text(draw, (90, 1000), "Lệnh demo: cp .env.example .env → sửa secret → docker compose --profile automation up -d --build → import n8n/workflows/a11_soc_local_automation.json", 24, MUTED, True, 900)
    save(image, "so_do_3_1_trien_khai_docker.png")


def sequence_response() -> None:
    image, draw = canvas(
        "SEQUENCE TỪ TẤN CÔNG ĐẾN PHẢN ỨNG VÀ AUDIT",
        "Luồng end-to-end theo đề tài mới: local ingest, RAG, n8n, approval và báo cáo",
    )
    actors = [
        ("Attacker", 120),
        ("OPNsense/Web/Windows", 390),
        ("A11 Collector", 660),
        ("SOCPipeline", 930),
        ("Agents/RAG", 1200),
        ("Analyst + n8n", 1500),
    ]
    for name, x in actors:
        box(draw, (x - 105, 180, x + 105, 260), name, "", BLUE if x < 1000 else GREEN, WHITE, 20, 1)
        draw.line((x, 270, x, 1030), fill="#C9D6DF", width=3)
    steps = [
        (120, 390, 330, "Nmap/DIRB/Brute force"),
        (390, 660, 410, "access.log / EVE / Windows JSON / syslog"),
        (660, 930, 490, "auth → parse → normalize"),
        (930, 930, 570, "dedup + correlate 300s + persist raw evidence"),
        (930, 1200, 650, "triage + enrichment + RAG playbook"),
        (1200, 930, 730, "severity, MITRE, recommendation"),
        (930, 1500, 810, "High/Critical: alert + incident + action"),
        (1500, 930, 970, "audit callback + report timeline"),
    ]
    for x1, x2, y, label in steps:
        if x1 == x2:
            draw.arc((x1 - 35, y - 18, x1 + 85, y + 52), 260, 95, fill=AMBER, width=5)
            text(draw, (x1 + 90, y - 8), label, 18, INK, True, 360)
        else:
            arrow(draw, (x1 + 5, y), (x2 - 5, y), GREEN if x2 >= x1 else AMBER, 5, label)
    box(
        draw,
        (1335, 865, 1715, 945),
        "APPROVAL + EXECUTION",
        "approve/reject; n8n webhook hoặc OPNsense alias",
        AMBER,
        LIGHT_AMBER,
        20,
        17,
    )
    arrow(draw, (1500, 820), (1500, 855), AMBER, 5)
    save(image, "so_do_3_2_sequence_phan_ung.png")


def alert_lifecycle() -> None:
    image, draw = canvas(
        "VÒNG ĐỜI ALERT, INCIDENT, RESPONSE ACTION VÀ AUDIT",
        "Trạng thái rõ ràng để chứng minh human-in-the-loop và khả năng giải thích",
    )
    states = [
        ((80, 220, 380, 400), "RAW EVENT", "SecurityEvent\nraw + normalized", BLUE, LIGHT_BLUE),
        ((510, 220, 810, 400), "ALERT", "open/investigating\nfingerprint + count", CYAN, LIGHT_BLUE),
        ((940, 220, 1240, 400), "INCIDENT", "High/Critical\ntimeline + report", RED, LIGHT_RED),
        ((1370, 220, 1670, 400), "RESPONSE ACTION", "pending\napproved/rejected", AMBER, LIGHT_AMBER),
        ((1370, 650, 1670, 830), "EXECUTION", "dry_run/webhook/opnsense\nn8n callback", GREEN, LIGHT_GREEN),
        ((940, 650, 1240, 830), "AUDIT EVENT", "decision + result\nactor + outcome", SLATE, LIGHT_SLATE),
        ((510, 650, 810, 830), "REPORT", "summary\nMITRE + evidence\nrecommendation", GREEN, LIGHT_GREEN),
        ((80, 650, 380, 830), "DASHBOARD SSE", "real-time queue\nmetrics\nstream ticket", BLUE, LIGHT_BLUE),
    ]
    for rect, title, body, accent, fill in states:
        box(draw, rect, title, body, accent, fill, 24, 20)
    pairs = [(380, 220, 510, 310), (810, 310, 940, 310), (1240, 310, 1370, 310), (1520, 400, 1520, 650), (1370, 740, 1240, 740), (940, 740, 810, 740), (510, 740, 380, 740)]
    arrow(draw, (380, 310), (510, 310), BLUE, 5, "persist")
    arrow(draw, (810, 310), (940, 310), RED, 5, "≥ High")
    arrow(draw, (1240, 310), (1370, 310), AMBER, 5, "proposal")
    arrow(draw, (1520, 400), (1520, 650), GREEN, 5, "approved")
    arrow(draw, (1370, 740), (1240, 740), SLATE, 5, "result")
    arrow(draw, (940, 740), (810, 740), GREEN, 5, "report")
    arrow(draw, (510, 740), (380, 740), BLUE, 5, "publish")
    text(draw, (120, 985), "Mọi hành động rủi ro cao đều có approval_required=true. n8n chỉ nhận action sau khi SOC tạo proposal và analyst phê duyệt.", 24, MUTED, True, 1500)
    save(image, "so_do_3_3_vong_doi_alert.png")


def main() -> None:
    architecture()
    network()
    agent_coordination()
    docker_compose()
    sequence_response()
    alert_lifecycle()


if __name__ == "__main__":
    main()
