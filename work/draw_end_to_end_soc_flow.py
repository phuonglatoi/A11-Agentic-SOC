from __future__ import annotations

import math
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


OUT = Path("report_assets/diagrams/so_do_2_3_luong_tong_quat_end_to_end.png")
WIDTH, HEIGHT = 1800, 2150

NAVY = "#123653"
INK = "#193047"
MUTED = "#557086"
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

FONT_REGULAR = r"C:\Windows\Fonts\arial.ttf"
FONT_BOLD = r"C:\Windows\Fonts\arialbd.ttf"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONT_BOLD if bold else FONT_REGULAR, size)


def wrap_text(draw: ImageDraw.ImageDraw, text: str, fnt, max_width: int) -> list[str]:
    lines: list[str] = []
    for raw_line in text.split("\n"):
        if not raw_line:
            lines.append("")
            continue
        words = raw_line.split()
        current = ""
        for word in words:
            candidate = word if not current else f"{current} {word}"
            if draw.textbbox((0, 0), candidate, font=fnt)[2] <= max_width:
                current = candidate
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
    return lines


def draw_wrapped(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    text: str,
    fnt,
    fill: str,
    max_width: int,
    spacing: int = 7,
    max_lines: int | None = None,
) -> int:
    lines = wrap_text(draw, text, fnt, max_width)
    if max_lines is not None and len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = lines[-1].rstrip(" .") + "..."
    x, y = xy
    line_h = draw.textbbox((0, 0), "Ag", font=fnt)[3] + spacing
    for line in lines:
        draw.text((x, y), line, font=fnt, fill=fill)
        y += line_h
    return y


def rounded_box(
    draw: ImageDraw.ImageDraw,
    rect: tuple[int, int, int, int],
    title: str,
    body: str,
    accent: str,
    fill: str = PANEL,
    title_size: int = 31,
    body_size: int = 28,
    max_lines: int | None = None,
) -> None:
    x1, y1, x2, y2 = rect
    draw.rounded_rectangle(rect, radius=18, fill=fill, outline=BORDER, width=3)
    draw.rounded_rectangle((x1, y1, x1 + 13, y2), radius=9, fill=accent)
    draw.text((x1 + 31, y1 + 20), title, font=font(title_size, True), fill=INK)
    draw_wrapped(
        draw,
        (x1 + 31, y1 + 65),
        body,
        font(body_size),
        MUTED,
        x2 - x1 - 56,
        spacing=6,
        max_lines=max_lines,
    )


def arrow(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    color: str = BLUE,
    width: int = 7,
    label: str | None = None,
    label_y_offset: int = -44,
) -> None:
    draw.line((start, end), fill=color, width=width)
    angle = math.atan2(end[1] - start[1], end[0] - start[0])
    head = 18
    wing = 10
    p1 = end
    p2 = (
        end[0] - head * math.cos(angle) + wing * math.sin(angle),
        end[1] - head * math.sin(angle) - wing * math.cos(angle),
    )
    p3 = (
        end[0] - head * math.cos(angle) - wing * math.sin(angle),
        end[1] - head * math.sin(angle) + wing * math.cos(angle),
    )
    draw.polygon((p1, p2, p3), fill=color)
    if label:
        fnt = font(20, True)
        bbox = draw.textbbox((0, 0), label, font=fnt)
        label_w = bbox[2] - bbox[0] + 24
        label_h = bbox[3] - bbox[1] + 14
        cx = (start[0] + end[0]) // 2
        cy = (start[1] + end[1]) // 2 + label_y_offset
        draw.rounded_rectangle(
            (cx - label_w // 2, cy - label_h // 2, cx + label_w // 2, cy + label_h // 2),
            radius=10,
            fill=WHITE,
            outline=BORDER,
            width=2,
        )
        draw.text(
            (cx - (bbox[2] - bbox[0]) // 2, cy - (bbox[3] - bbox[1]) // 2 - 2),
            label,
            font=fnt,
            fill=color,
        )


def poly_arrow(
    draw: ImageDraw.ImageDraw,
    points: list[tuple[int, int]],
    color: str,
    width: int = 7,
) -> None:
    draw.line(points, fill=color, width=width, joint="curve")
    start = points[-2]
    end = points[-1]
    angle = math.atan2(end[1] - start[1], end[0] - start[0])
    head = 18
    wing = 10
    p2 = (
        end[0] - head * math.cos(angle) + wing * math.sin(angle),
        end[1] - head * math.sin(angle) - wing * math.cos(angle),
    )
    p3 = (
        end[0] - head * math.cos(angle) - wing * math.sin(angle),
        end[1] - head * math.sin(angle) + wing * math.cos(angle),
    )
    draw.polygon((end, p2, p3), fill=color)


def section_panel(
    draw: ImageDraw.ImageDraw,
    y1: int,
    y2: int,
    number: str,
    title: str,
    accent: str,
) -> None:
    draw.rounded_rectangle((35, y1, WIDTH - 35, y2), radius=24, fill=PANEL, outline="#D6E1E8", width=3)
    draw.ellipse((58, y1 + 20, 112, y1 + 74), fill=accent)
    num_bbox = draw.textbbox((0, 0), number, font=font(27, True))
    draw.text(
        (
            85 - (num_bbox[2] - num_bbox[0]) // 2,
            y1 + 47 - (num_bbox[3] - num_bbox[1]) // 2 - 4,
        ),
        number,
        font=font(27, True),
        fill=WHITE,
    )
    draw.text((130, y1 + 24), title, font=font(31, True), fill=accent)
    draw.line((130, y1 + 72, WIDTH - 65, y1 + 72), fill="#DCE6EC", width=2)


def diamond(
    draw: ImageDraw.ImageDraw,
    center: tuple[int, int],
    size: tuple[int, int],
    title: str,
    subtitle: str,
) -> tuple[int, int, int, int]:
    cx, cy = center
    w, h = size
    points = [(cx, cy - h // 2), (cx + w // 2, cy), (cx, cy + h // 2), (cx - w // 2, cy)]
    draw.polygon(points, fill=LIGHT_AMBER, outline=AMBER)
    draw.line(points + [points[0]], fill=AMBER, width=4)
    tb = draw.textbbox((0, 0), title, font=font(29, True))
    draw.text((cx - (tb[2] - tb[0]) // 2, cy - 29), title, font=font(29, True), fill=INK)
    sb = draw.textbbox((0, 0), subtitle, font=font(24))
    draw.text((cx - (sb[2] - sb[0]) // 2, cy + 12), subtitle, font=font(24), fill=MUTED)
    return cx - w // 2, cy - h // 2, cx + w // 2, cy + h // 2


def main() -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), CANVAS)
    draw = ImageDraw.Draw(image)

    draw.rectangle((0, 0, WIDTH, 155), fill=NAVY)
    draw.text((55, 30), "SƠ ĐỒ LUỒNG TỔNG QUÁT END-TO-END CỦA A11 SOC", font=font(48, True), fill=WHITE)
    draw.text(
        (58, 92),
        "Từ máy tấn công, giao thức mạng và telemetry đến phân tích Agentic AI, phản ứng và báo cáo",
        font=font(27),
        fill="#D7E8F5",
    )

    # 01 - Attack and routing
    section_panel(draw, 180, 520, "01", "TẤN CÔNG VÀ ĐỊNH TUYẾN MẠNG", RED)
    rounded_box(
        draw,
        (65, 275, 500, 500),
        "KALI LINUX — ATTACKER",
        "192.168.228.128/24\nSubnet WAN lab 192.168.228.0/24\nRFC1918 • GW 192.168.228.142\nNmap -sS -Pn • DIRB",
        RED,
        fill=LIGHT_RED,
        body_size=25,
    )
    rounded_box(
        draw,
        (690, 275, 1120, 500),
        "OPNSENSE — PERIMETER",
        "WAN 192.168.228.142/24\nStateful firewall + filterlog\nSuricata IDS/IPS + EVE JSON\nLAN gateway 192.168.1.1/24",
        AMBER,
        fill=LIGHT_AMBER,
        body_size=25,
    )
    rounded_box(
        draw,
        (1305, 275, 1735, 500),
        "UBUNTU WEB / SOC",
        "LAN 192.168.1.100/24\nApache HTTP TCP/80\n/var/log/apache2/access.log\nNhận DNAT từ cổng WAN 80",
        BLUE,
        fill=LIGHT_BLUE,
        body_size=25,
    )
    arrow(draw, (505, 375), (680, 375), RED, label="TCP SYN | HTTP :80")
    arrow(draw, (1125, 375), (1295, 375), AMBER, label="DNAT TCP/80")

    # 02 - Telemetry
    section_panel(draw, 545, 905, "02", "THU THẬP VÀ VẬN CHUYỂN TELEMETRY", BLUE)
    source_boxes = [
        (
            (65, 635, 420, 780),
            "FIREWALL / IDS",
            "Filterlog + EVE JSON\nRemote syslog UDP/5514",
            AMBER,
        ),
        (
            (485, 635, 840, 780),
            "WEB / ENDPOINT",
            "Apache + Windows JSON\nREST/HEC • TCP/8000",
            CYAN,
        ),
        (
            (905, 635, 1260, 780),
            "SPLUNK CLOUD",
            "UF → TLS TCP/9997\nhoặc HEC HTTPS/8088",
            BLUE,
        ),
        (
            (1325, 635, 1735, 780),
            "SPLUNK POLLER",
            "Search REST v2 HTTPS/443\nPOST /api/v1/ingest",
            SLATE,
        ),
    ]
    for rect, title, body, accent in source_boxes:
        rounded_box(draw, rect, title, body, accent, title_size=28, body_size=24)
        cx = (rect[0] + rect[2]) // 2
        arrow(draw, (cx, rect[3] + 4), (cx, 814), accent, width=5)
    draw.rounded_rectangle((155, 815, 1645, 875), radius=16, fill=NAVY, outline=NAVY)
    draw.text(
        (220, 829),
        "A11 INGEST GATEWAY  •  Syslog 5514  •  HEC  •  REST  •  Gắn source + received_at",
        font=font(27, True),
        fill=WHITE,
    )

    # 03 - Real-time pipeline
    section_panel(draw, 930, 1245, "03", "PIPELINE XỬ LÝ REAL-TIME", CYAN)
    pipeline = [
        ("AUTH", "X-API-Key\nSplunk token", BLUE),
        ("PARSE", "Apache / EVE\nWindows / JSON", CYAN),
        ("NORMALIZE", "Common schema\nIP, port, protocol", CYAN),
        ("DEDUP", "Fingerprint\nloại bản ghi trùng", SLATE),
        ("CORRELATE", "Cửa sổ 300 s\ngom chuỗi hành vi", GREEN),
        ("PERSIST", "Event + raw log\nalert + audit", SLATE),
    ]
    x_positions = [60, 350, 640, 930, 1220, 1510]
    rects: list[tuple[int, int, int, int]] = []
    for index, (title, body, accent) in enumerate(pipeline):
        rect = (x_positions[index], 1020, x_positions[index] + 230, 1195)
        rects.append(rect)
        rounded_box(draw, rect, title, body, accent, title_size=24, body_size=22)
        if index:
            arrow(draw, (rects[index - 1][2] + 5, 1108), (rect[0] - 10, 1108), BLUE, width=5)

    # 04 - Agentic analysis
    section_panel(draw, 1270, 1585, "04", "AGENTIC AI, TRIAGE VÀ QUYẾT ĐỊNH", GREEN)
    agent_boxes = [
        ((65, 1365, 375, 1530), "ENRICHMENT", "assets.json + iocs.json\nIP context + criticality", GREEN),
        ((450, 1365, 760, 1530), "TRIAGE", "Severity + confidence\nreasons + MITRE ATT&CK", GREEN),
        ((835, 1365, 1145, 1530), "RAG", "Truy xuất playbook\nkhuyến nghị theo ngữ cảnh", BLUE),
        ((1220, 1365, 1510, 1530), "OLLAMA TÙY CHỌN", "Structured JSON\nqwen2.5:7b + fallback", SLATE),
    ]
    for index, (rect, title, body, accent) in enumerate(agent_boxes):
        rounded_box(draw, rect, title, body, accent, title_size=27, body_size=22)
        if index:
            previous = agent_boxes[index - 1][0]
            arrow(draw, (previous[2] + 5, 1440), (rect[0] - 10, 1440), GREEN, width=5)
    decision_rect = diamond(draw, (1640, 1440), (230, 165), "SEVERITY", "≥ HIGH?")
    arrow(draw, (1515, 1440), (decision_rect[0] - 8, 1440), AMBER, width=5)

    # 05 - Outcomes
    section_panel(draw, 1610, 2090, "05", "KẾT QUẢ, PHẢN ỨNG VÀ BÁO CÁO", NAVY)
    draw.rounded_rectangle((65, 1698, 1735, 1805), radius=18, fill=LIGHT_GREEN, outline="#AAD6C3", width=3)
    draw.text((90, 1715), "NHÁNH LOW / MEDIUM", font=font(27, True), fill=GREEN)
    draw.text(
        (415, 1715),
        "Lưu và giám sát  →  SSE real-time  →  Dashboard Events / Alerts / Metrics",
        font=font(27),
        fill=INK,
    )
    arrow(draw, (1650, 1528), (1650, 1685), GREEN, width=6, label="KHÔNG", label_y_offset=-18)

    response_rects = [
        ((65, 1850, 335, 1995), "ALERT + INCIDENT", "High/Critical\ntimeline + evidence", RED),
        ((395, 1850, 665, 1995), "REPORT AGENT", "Summary, IOC, MITRE\nimpact + actions", AMBER),
        ((725, 1850, 1015, 1995), "RESPONSE", "notify / block_ip\nisolate_host", RED),
        ((1075, 1850, 1375, 1995), "SAFETY + APPROVAL", "validate target\nanalyst approve/reject", AMBER),
        ((1435, 1850, 1735, 1995), "EXECUTE + AUDIT", "dry-run / webhook\nOPNsense alias", SLATE),
    ]
    for index, (rect, title, body, accent) in enumerate(response_rects):
        rounded_box(draw, rect, title, body, accent, title_size=25, body_size=22)
        if index:
            previous = response_rects[index - 1][0]
            arrow(draw, (previous[2] + 5, 1922), (rect[0] - 10, 1922), RED, width=5)
    poly_arrow(
        draw,
        [(1715, 1480), (1760, 1480), (1760, 1825), (200, 1825), (200, 1838)],
        RED,
        width=6,
    )
    draw.rounded_rectangle((1695, 1650, 1768, 1693), radius=9, fill=WHITE, outline=BORDER, width=2)
    draw.text((1710, 1657), "CÓ", font=font(24, True), fill=RED)

    draw.rounded_rectangle((230, 2020, 1570, 2072), radius=14, fill=NAVY)
    final_text = (
        "BÁO CÁO HOÀN CHỈNH • timeline • IP/port/protocol • evidence • "
        "MITRE • tác động • phản ứng • khuyến nghị"
    )
    bbox = draw.textbbox((0, 0), final_text, font=font(20, True))
    draw.text(((WIDTH - (bbox[2] - bbox[0])) // 2, 2035), final_text, font=font(20, True), fill=WHITE)

    draw.text(
        (55, 2110),
        "Ghi chú: WAN trong mô hình là vùng WAN lab; các địa chỉ 192.168.x.x đều thuộc dải riêng RFC1918.",
        font=font(22),
        fill=MUTED,
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUT, optimize=True)
    print(OUT.resolve())


if __name__ == "__main__":
    main()
